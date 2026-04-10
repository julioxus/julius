#!/usr/bin/env python3
"""
Bugcrowd Session Management for Bounty Intel
Provides MCP-compatible functions for Bugcrowd authentication and session management.

Avoids importing Playwright directly (conflicts with MCP async loop).
Uses subprocess for browser login, reads cache files directly for status.
"""

import json
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

CACHE_DIR = Path.home() / ".bugcrowd"
COOKIE_CACHE_FILE = CACHE_DIR / "session_cookies.json"
COOKIE_META_FILE = CACHE_DIR / "session_meta.json"
AUTH_SCRIPT = Path(__file__).parent.parent / ".claude" / "skills" / "bugcrowd" / "tools" / "bugcrowd_auth.py"

BUGCROWD_DASHBOARD_URL = "https://bugcrowd.com/dashboard/programs"


def _read_cached_cookies() -> dict | None:
    """Read cached cookies directly from disk."""
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


def _validate_cookies(cookies: dict) -> bool:
    """Test if cookies are still valid against Bugcrowd dashboard."""
    if not cookies:
        return False
    cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
    req = urllib.request.Request(BUGCROWD_DASHBOARD_URL)
    req.add_header("Cookie", cookie_header)
    req.add_header("Accept", "text/html,application/xhtml+xml")
    req.add_header("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            return any(w in content.lower() for w in ["dashboard", "programs", "submissions", "logout"])
    except urllib.error.HTTPError as e:
        return e.code == 302
    except Exception:
        return False


def refresh_bugcrowd_session() -> dict:
    """Refresh Bugcrowd session cookie via Playwright browser login.

    Launches bugcrowd_auth.py as a subprocess to avoid async/sync conflict.
    """
    if not AUTH_SCRIPT.exists():
        return {"error": f"Auth script not found: {AUTH_SCRIPT}", "status": "missing_file"}

    try:
        result = subprocess.run(
            [sys.executable, str(AUTH_SCRIPT), "--force"],
            timeout=320,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            return {
                "error": result.stderr.strip() or "Login process failed",
                "stdout": result.stdout.strip(),
                "status": "failed",
            }

        # Read the cookies that were just cached
        cookies = _read_cached_cookies()
        if cookies:
            return {
                "status": "ok",
                "cookies_count": len(cookies),
                "message": f"Bugcrowd session refreshed ({len(cookies)} cookies)",
                "cached": True,
            }
        return {"error": "Login completed but no cookies cached", "status": "failed"}

    except subprocess.TimeoutExpired:
        return {"error": "Login timed out (5 min)", "status": "timeout"}
    except Exception as e:
        return {"error": str(e), "status": "error"}


def get_bugcrowd_session_status() -> dict:
    """Check Bugcrowd session status and validity."""
    cached = _read_cached_cookies()
    if not cached:
        # Check if there are expired cookies
        if COOKIE_CACHE_FILE.exists():
            try:
                meta = json.loads(COOKIE_META_FILE.read_text())
                return {
                    "status": "expired",
                    "authenticated": False,
                    "message": f"Session expired (saved {meta.get('saved_at', 'unknown')})",
                    "needs_refresh": True,
                }
            except Exception:
                pass
        return {
            "status": "no_session",
            "message": "No cached Bugcrowd session found",
            "authenticated": False,
            "needs_refresh": True,
        }

    valid = _validate_cookies(cached)
    return {
        "status": "valid" if valid else "expired",
        "authenticated": valid,
        "cookies_count": len(cached),
        "message": f"Session {'valid' if valid else 'expired'} ({len(cached)} cookies)",
        "needs_refresh": not valid,
    }


def clear_bugcrowd_session() -> dict:
    """Clear cached Bugcrowd session."""
    cleared = []
    for f in [COOKIE_CACHE_FILE, COOKIE_META_FILE]:
        if f.exists():
            f.unlink()
            cleared.append(f.name)
    return {
        "status": "ok",
        "message": f"Cleared: {', '.join(cleared)}" if cleared else "No cached session to clear",
    }
