#!/usr/bin/env python3
"""
Intigriti Browser Authentication

Uses Playwright to open a real browser for Intigriti login (supports MFA).
After authentication, the session cookie is extracted and cached.

Flow:
1. Check for cached cookie in ~/.intigriti/session_cookie.txt
2. If expired/missing → launch Playwright browser to Intigriti inbox
3. User completes login + MFA in browser
4. Detect successful auth (inbox page loads)
5. Extract __Host-Intigriti.Web.Researcher cookie
6. Cache with TTL (default 55 min — Intigriti sessions last ~1h)
7. Close browser

Usage:
  python3 intigriti_auth.py                 # get cookie (from cache or browser)
  python3 intigriti_auth.py --clear         # clear cache
  python3 intigriti_auth.py --status        # check cache status
  python3 intigriti_auth.py --validate      # test if cookie still works

From other scripts:
  from intigriti_auth import get_session_cookie
  cookie = get_session_cookie()  # returns cookie value string
"""

import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional

CACHE_DIR = Path.home() / ".intigriti"
COOKIE_CACHE_FILE = CACHE_DIR / "session_cookie.txt"
COOKIE_META_FILE = CACHE_DIR / "session_meta.json"

INTIGRITI_INBOX_URL = "https://app.intigriti.com/researcher/inbox"
INTIGRITI_API_TEST = "https://app.intigriti.com/api/core/researcher/submissions?offset=0&limit=1"
SESSION_COOKIE_NAME = "__Host-Intigriti.Web.Researcher"

# Intigriti sessions last ~1 hour; refresh at 55 min
DEFAULT_TTL = 55 * 60


def _ensure_cache_dir():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def get_cached_cookie() -> Optional[str]:
    """Return cached cookie value if still valid."""
    if not COOKIE_CACHE_FILE.exists() or not COOKIE_META_FILE.exists():
        return None
    try:
        meta = json.loads(COOKIE_META_FILE.read_text())
        if meta.get("expires_at", 0) > time.time() + 60:
            cookie = COOKIE_CACHE_FILE.read_text().strip()
            if cookie:
                return cookie
    except (json.JSONDecodeError, KeyError):
        pass
    return None


def _save_cookie(cookie_value: str, ttl: int = DEFAULT_TTL) -> str:
    """Cache the session cookie value."""
    _ensure_cache_dir()
    COOKIE_CACHE_FILE.write_text(cookie_value)
    COOKIE_CACHE_FILE.chmod(0o600)
    COOKIE_META_FILE.write_text(json.dumps({
        "expires_at": time.time() + ttl,
        "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }))
    COOKIE_META_FILE.chmod(0o600)
    return cookie_value


def validate_cookie(cookie: str) -> bool:
    """Test if cookie is still valid against Intigriti API."""
    req = urllib.request.Request(INTIGRITI_API_TEST)
    req.add_header("Cookie", f"{SESSION_COOKIE_NAME}={cookie}")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "Mozilla/5.0 IntiAuth/1.0")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            content_type = resp.headers.get("Content-Type", "")
            return "application/json" in content_type
    except urllib.error.HTTPError:
        return False
    except Exception:
        return False


def browser_login() -> str:
    """
    Launch Playwright browser for Intigriti login.
    User completes login + MFA manually.
    Cookie is extracted automatically after successful auth.
    Returns the session cookie value.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("[!] Playwright not installed. Run:", file=sys.stderr)
        print("    pip install playwright && playwright install chromium", file=sys.stderr)
        sys.exit(1)

    print("[*] Launching browser for Intigriti login...")
    print("[*] Complete login + MFA in the browser window.")
    print("[*] The browser will close automatically after successful auth.\n")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()

        page.goto(INTIGRITI_INBOX_URL, wait_until="domcontentloaded")

        # Wait for the user to complete login and land on the researcher area
        # The inbox URL or any /researcher/ page means auth is complete
        try:
            page.wait_for_url("**/researcher/**", timeout=180_000)
            # Wait for cookies to settle after redirect chain
            page.wait_for_timeout(3000)
            page.wait_for_load_state("networkidle", timeout=15_000)
        except Exception:
            pass

        # Extract the session cookie
        all_cookies = context.cookies()
        session_cookie = None
        for c in all_cookies:
            if c["name"] == SESSION_COOKIE_NAME:
                session_cookie = c["value"]
                break

        browser.close()

    if not session_cookie:
        print("[!] Session cookie not found after login.", file=sys.stderr)
        print("[!] Make sure you completed the full login flow.", file=sys.stderr)
        sys.exit(1)

    # Validate
    print(f"[+] Cookie extracted ({len(session_cookie)} chars)")
    if validate_cookie(session_cookie):
        print("[+] Cookie validated — API access confirmed")
    else:
        print("[!] Cookie validation failed — it may still work, proceeding anyway")

    _save_cookie(session_cookie)
    print(f"[+] Cached at {COOKIE_CACHE_FILE} (TTL: {DEFAULT_TTL // 60} min)")

    return session_cookie


def get_session_cookie() -> str:
    """
    Get Intigriti session cookie.
    1. Returns cached cookie if still valid
    2. Otherwise launches Playwright browser for login

    Returns cookie value string ready to use in API calls.
    """
    # 1. Try cached
    cached = get_cached_cookie()
    if cached:
        if validate_cookie(cached):
            return cached
        print("[*] Cached cookie expired, re-authenticating...")

    # 2. Browser login
    return browser_login()


def clear_cache():
    for f in [COOKIE_CACHE_FILE, COOKIE_META_FILE]:
        if f.exists():
            f.unlink()
    print("[+] Intigriti session cache cleared.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--clear":
        clear_cache()
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "--status":
        cached = get_cached_cookie()
        if cached:
            meta = json.loads(COOKIE_META_FILE.read_text())
            remaining = int(meta["expires_at"] - time.time())
            valid = validate_cookie(cached)
            print(f"Cached cookie: {len(cached)} chars")
            print(f"Expires in: {remaining // 60}m {remaining % 60}s")
            print(f"API validation: {'OK' if valid else 'FAILED'}")
        else:
            print("No valid cached cookie.")
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == "--validate":
        cached = get_cached_cookie()
        if cached and validate_cookie(cached):
            print("Cookie is valid.")
            sys.exit(0)
        else:
            print("Cookie is invalid or missing.")
            sys.exit(1)

    # Default: get cookie
    cookie = get_session_cookie()
    print(f"\nCookie value ({len(cookie)} chars):")
    print(cookie[:50] + "..." + cookie[-20:])
