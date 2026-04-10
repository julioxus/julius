#!/usr/bin/env python3
"""
Bugcrowd Session Management for Bounty Intel
Provides MCP-compatible functions for Bugcrowd authentication and session management.
"""

from pathlib import Path
import sys


def refresh_bugcrowd_session() -> dict:
    """Refresh Bugcrowd session cookie via Playwright browser login.

    Launches a browser window for the user to log in to Bugcrowd.
    After login, the session is automatically:
    1. Cached locally (~/.bugcrowd/)
    2. Available for subsequent API calls
    3. Used for private program access

    Use this when Bugcrowd scraping fails with 'no session' or to access private programs.
    """
    try:
        # Add the skill tools path for imports
        skill_tools = Path(__file__).parent / ".claude" / "skills" / "bugcrowd" / "tools"
        if str(skill_tools) not in sys.path:
            sys.path.insert(0, str(skill_tools))

        from bugcrowd_auth import get_session_cookies

        cookies = get_session_cookies(force_refresh=True)

        if cookies:
            return {
                "status": "ok",
                "cookies_count": len(cookies),
                "message": f"Bugcrowd session refreshed successfully ({len(cookies)} cookies)",
                "cached": True
            }
        else:
            return {
                "error": "Failed to get Bugcrowd session",
                "message": "Login failed or was cancelled",
                "status": "failed"
            }

    except ImportError:
        return {
            "error": "Playwright not installed",
            "message": "Run: pip install playwright && playwright install chromium",
            "status": "missing_dependency"
        }
    except Exception as e:
        return {
            "error": str(e),
            "status": "error"
        }


def get_bugcrowd_session_status() -> dict:
    """Check Bugcrowd session status and validity."""
    try:
        # Add the skill tools path for imports
        skill_tools = Path(__file__).parent / ".claude" / "skills" / "bugcrowd" / "tools"
        if str(skill_tools) not in sys.path:
            sys.path.insert(0, str(skill_tools))

        from bugcrowd_auth import get_cached_cookies, validate_cookies

        cached = get_cached_cookies()

        if not cached:
            return {
                "status": "no_session",
                "message": "No cached Bugcrowd session found",
                "authenticated": False
            }

        # Validate session
        valid = validate_cookies(cached)

        return {
            "status": "valid" if valid else "expired",
            "authenticated": valid,
            "cookies_count": len(cached),
            "message": f"Session is {'valid' if valid else 'expired/invalid'} ({len(cached)} cookies)",
            "needs_refresh": not valid
        }

    except ImportError:
        return {
            "error": "Authentication module not available",
            "status": "missing_dependency"
        }
    except Exception as e:
        return {
            "error": str(e),
            "status": "error"
        }


def clear_bugcrowd_session() -> dict:
    """Clear cached Bugcrowd session."""
    try:
        # Add the skill tools path for imports
        skill_tools = Path(__file__).parent / ".claude" / "skills" / "bugcrowd" / "tools"
        if str(skill_tools) not in sys.path:
            sys.path.insert(0, str(skill_tools))

        from bugcrowd_auth import clear_cache

        clear_cache()

        return {
            "status": "ok",
            "message": "Bugcrowd session cache cleared"
        }

    except ImportError:
        return {
            "error": "Authentication module not available",
            "status": "missing_dependency"
        }
    except Exception as e:
        return {
            "error": str(e),
            "status": "error"
        }