#!/usr/bin/env python3
"""
Bugcrowd Browser Authentication

Uses Playwright to open a real browser for Bugcrowd login (supports MFA).
After authentication, the session cookies are extracted and cached.

Flow:
1. Check for cached cookies in ~/.bugcrowd/session_cookies.json
2. If expired/missing → launch Playwright browser to Bugcrowd dashboard
3. User completes login + MFA in browser
4. Detect successful auth (dashboard page loads)
5. Extract session cookies (_bugcrowd_session, etc.)
6. Cache with TTL (default 55 min — Bugcrowd sessions last ~1h)
7. Close browser

Usage:
  python3 bugcrowd_auth.py                 # get cookies (from cache or browser)
  python3 bugcrowd_auth.py --clear         # clear cache
  python3 bugcrowd_auth.py --status        # check cache status
  python3 bugcrowd_auth.py --validate      # test if cookies still work

From other scripts:
  from bugcrowd_auth import get_session_cookies
  cookies = get_session_cookies()  # returns cookie dict
"""

import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional, Dict, List

try:
    from playwright.sync_api import sync_playwright, Page, Browser
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    print("Playwright not installed. Run: pip install playwright && playwright install chromium")

CACHE_DIR = Path.home() / ".bugcrowd"
COOKIE_CACHE_FILE = CACHE_DIR / "session_cookies.json"
COOKIE_META_FILE = CACHE_DIR / "session_meta.json"

BUGCROWD_LOGIN_URL = "https://bugcrowd.com/user/sign_in"
BUGCROWD_DASHBOARD_URL = "https://bugcrowd.com/dashboard"
BUGCROWD_PROGRAMS_URL = "https://bugcrowd.com/dashboard/programs"
BUGCROWD_API_TEST = "https://bugcrowd.com/dashboard/programs"

# Important Bugcrowd cookie names
BUGCROWD_SESSION_COOKIES = [
    "_bugcrowd_session",
    "remember_researcher_token",
    "csrf-token"
]

# Bugcrowd sessions last ~1-2 hours; refresh at 55 min
DEFAULT_TTL = 55 * 60


def _ensure_cache_dir():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def get_cached_cookies() -> Optional[Dict[str, str]]:
    """Return cached cookies if still valid."""
    if not COOKIE_CACHE_FILE.exists() or not COOKIE_META_FILE.exists():
        return None
    try:
        meta = json.loads(COOKIE_META_FILE.read_text())
        if meta.get("expires_at", 0) > time.time() + 60:
            cookies = json.loads(COOKIE_CACHE_FILE.read_text())
            if cookies and isinstance(cookies, dict):
                return cookies
    except (json.JSONDecodeError, KeyError):
        pass
    return None


def _save_cookies(cookies: Dict[str, str], ttl: int = DEFAULT_TTL) -> Dict[str, str]:
    """Cache the session cookies."""
    _ensure_cache_dir()
    COOKIE_CACHE_FILE.write_text(json.dumps(cookies, indent=2))
    COOKIE_CACHE_FILE.chmod(0o600)
    COOKIE_META_FILE.write_text(json.dumps({
        "expires_at": time.time() + ttl,
        "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }))
    COOKIE_META_FILE.chmod(0o600)
    return cookies


def validate_cookies(cookies: Dict[str, str]) -> bool:
    """Test if cookies are still valid against Bugcrowd dashboard."""
    if not cookies:
        return False

    # Convert cookies dict to header string
    cookie_header = "; ".join([f"{name}={value}" for name, value in cookies.items()])

    req = urllib.request.Request(BUGCROWD_API_TEST)
    req.add_header("Cookie", cookie_header)
    req.add_header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    req.add_header("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 BugcrowdAuth/1.0")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            # Look for authenticated dashboard content
            return any(indicator in content.lower() for indicator in [
                "dashboard", "programs", "submissions", "researcher", "logout"
            ])
    except urllib.error.HTTPError as e:
        if e.code == 302:  # Redirect might be okay
            return True
        return False
    except Exception:
        return False


def _wait_for_login_success(page: Page, timeout: int = 300) -> bool:
    """Wait for successful login detection."""
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            current_url = page.url

            # Check if we're on dashboard or programs page
            if any(indicator in current_url for indicator in ["/dashboard", "/programs"]):
                # Additional check - look for dashboard elements
                if page.query_selector("[data-cy='dashboard'], .dashboard, [href*='dashboard'], [href*='submissions']"):
                    return True

            # Check for dashboard content in the page
            if page.query_selector("text='Dashboard'") or page.query_selector("text='Programs'"):
                return True

            time.sleep(1)

        except Exception as e:
            print(f"Login detection error: {e}")
            time.sleep(1)

    return False


def _extract_cookies_from_page(page: Page) -> Dict[str, str]:
    """Extract important session cookies from browser context."""
    try:
        context_cookies = page.context.cookies()

        extracted = {}
        for cookie in context_cookies:
            if cookie['domain'] in ['.bugcrowd.com', 'bugcrowd.com']:
                name = cookie['name']
                if (name.startswith('_') or
                    'session' in name.lower() or
                    'auth' in name.lower() or
                    'token' in name.lower() or
                    'csrf' in name.lower() or
                    'remember' in name.lower()):
                    extracted[name] = cookie['value']

        # Ensure we have at least some important cookies
        if not extracted:
            # Fallback - get all cookies
            for cookie in context_cookies:
                if cookie['domain'] in ['.bugcrowd.com', 'bugcrowd.com']:
                    extracted[cookie['name']] = cookie['value']

        return extracted

    except Exception as e:
        print(f"Cookie extraction error: {e}")
        return {}


def browser_login() -> Dict[str, str]:
    """
    Launch Playwright browser for Bugcrowd login.
    User completes login manually, then cookies are extracted.
    """
    if not PLAYWRIGHT_AVAILABLE:
        raise ImportError("Playwright not available. Install with: pip install playwright && playwright install chromium")

    print("🌐 Opening browser for Bugcrowd login...")
    print("ℹ️  Complete login process in browser (including MFA if needed)")
    print("ℹ️  Browser will close automatically after successful login")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=False,  # Always show browser for login
            args=["--disable-blink-features=AutomationControlled"]
        )

        context = browser.new_context(
            viewport={"width": 1280, "height": 720},
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

        page = context.new_page()

        try:
            # Navigate to login page
            print(f"🔗 Navigating to: {BUGCROWD_LOGIN_URL}")
            page.goto(BUGCROWD_LOGIN_URL)
            page.wait_for_load_state("networkidle")

            print("👤 Please complete login in the browser window...")
            print("   1. Enter your Bugcrowd credentials")
            print("   2. Complete MFA if prompted")
            print("   3. Wait for dashboard to load")
            print("   ⏳ Waiting for login success...")

            # Wait for successful login
            login_success = _wait_for_login_success(page, timeout=300)  # 5 minutes

            if not login_success:
                print("❌ Login timeout or failed - dashboard not detected")
                return {}

            print("✅ Login success detected!")

            # Extract cookies
            cookies = _extract_cookies_from_page(page)

            if not cookies:
                print("⚠️  No cookies extracted - login may have failed")
                return {}

            print(f"🍪 Extracted {len(cookies)} session cookies")

            # Test cookies immediately
            if validate_cookies(cookies):
                print("✅ Cookie validation successful")
            else:
                print("⚠️  Cookie validation failed - cookies may not work")

            return cookies

        except Exception as e:
            print(f"❌ Browser login failed: {e}")
            return {}

        finally:
            browser.close()


def get_session_cookies(force_refresh: bool = False) -> Dict[str, str]:
    """
    Get valid Bugcrowd session cookies.
    Uses cache if available and valid, otherwise launches browser login.
    """
    if not force_refresh:
        cached = get_cached_cookies()
        if cached and validate_cookies(cached):
            print("✅ Using cached Bugcrowd session")
            return cached
        elif cached:
            print("⚠️  Cached cookies expired/invalid")

    print("🔄 Acquiring fresh Bugcrowd session...")
    cookies = browser_login()

    if cookies:
        _save_cookies(cookies)
        print(f"💾 Session cached for {DEFAULT_TTL//60} minutes")

    return cookies


def clear_cache():
    """Clear cached session data."""
    for file in [COOKIE_CACHE_FILE, COOKIE_META_FILE]:
        if file.exists():
            file.unlink()
    print("🗑️  Cache cleared")


def check_status():
    """Check cache status and validity."""
    cached = get_cached_cookies()

    if not cached:
        print("❌ No cached session found")
        return

    try:
        meta = json.loads(COOKIE_META_FILE.read_text())
        saved_at = meta.get("saved_at", "unknown")
        expires_at = meta.get("expires_at", 0)

        time_left = int(expires_at - time.time())

        print(f"📋 Session Status:")
        print(f"   Saved: {saved_at}")
        print(f"   Time left: {time_left//60}m {time_left%60}s")
        print(f"   Cookies: {len(cached)} items")

        if validate_cookies(cached):
            print("✅ Session is valid")
        else:
            print("❌ Session validation failed")

    except Exception as e:
        print(f"❌ Error checking status: {e}")


def main():
    """CLI interface for Bugcrowd authentication."""
    import argparse

    parser = argparse.ArgumentParser(description="Bugcrowd Browser Authentication")
    parser.add_argument("--clear", action="store_true", help="Clear cached session")
    parser.add_argument("--status", action="store_true", help="Check session status")
    parser.add_argument("--validate", action="store_true", help="Validate current session")
    parser.add_argument("--force", action="store_true", help="Force fresh login")

    args = parser.parse_args()

    if args.clear:
        clear_cache()
    elif args.status:
        check_status()
    elif args.validate:
        cached = get_cached_cookies()
        if cached and validate_cookies(cached):
            print("✅ Session is valid")
        else:
            print("❌ Session is invalid or expired")
    else:
        cookies = get_session_cookies(force_refresh=args.force)
        if cookies:
            print(f"✅ Session ready - {len(cookies)} cookies available")
        else:
            print("❌ Failed to get session")


if __name__ == "__main__":
    main()