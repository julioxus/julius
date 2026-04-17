"""Bugcrowd delta sync — fetches submissions via researcher session cookies.

Bugcrowd's public `api.bugcrowd.com` is program-owner only; researchers do not
get API tokens. We authenticate against the researcher dashboard endpoint
`bugcrowd.com/submissions.json` using session cookies obtained via Playwright
login (see `.claude/skills/bugcrowd/tools/bugcrowd_auth.py`).

Cookie lookup priority (mirrors intigriti.py):
  1. settings.bugcrowd_cookies_json (env/in-memory override)
  2. ~/.bugcrowd/session_cookies.json (local cache, validated against session_meta.json)
  3. DB-persisted cookies (pushed by /admin/bugcrowd-cookies endpoint)
  4. Playwright browser login (local only)
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from decimal import Decimal
from difflib import SequenceMatcher
from pathlib import Path

from bounty_intel.config import settings
from bounty_intel.db import Program, Submission, SubmissionReport, get_session
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

BASE_URL = "https://bugcrowd.com"
SUBMISSIONS_EP = "/submissions.json"

# Bugcrowd researcher substate → our disposition
# nue = "new, under evaluation" (platform-internal pending state)
BUGCROWD_SUBSTATE_TO_DISPOSITION = {
    "nue": "new",
    "new": "new",
    "triaged": "triaged",
    "unresolved": "triaged",
    "resolved": "accepted",
    "not_reproducible": "not_reproducible",
    "not_applicable": "not_applicable",
    "out_of_scope": "out_of_scope",
    "duplicate": "duplicate",
    "wont_fix": "wont_fix",
    "informational": "informative",
}

DISPOSITION_TO_REPORT_STATUS = {
    "accepted": "accepted",
    "resolved": "accepted",
    "duplicate": "rejected",
    "not_reproducible": "rejected",
    "not_applicable": "rejected",
    "out_of_scope": "rejected",
    "wont_fix": "rejected",
    "informative": "rejected",
    "triaged": "submitted",
    "new": "submitted",
}


def _is_server_environment() -> bool:
    import os
    return bool(
        os.environ.get("K_SERVICE")
        or os.environ.get("KUBERNETES_SERVICE_HOST")
        or os.environ.get("CI")
    )


def _cookies_to_header(cookies: dict) -> str:
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def _get_cookies() -> dict | None:
    """Get Bugcrowd session cookies from multiple sources.

    Priority:
    1. settings.bugcrowd_cookies_json (env var / in-memory override)
    2. Local cache at ~/.bugcrowd/session_cookies.json (validated via session_meta.json)
    3. DB-persisted cookies (pushed by Playwright login or dashboard)
    4. Playwright browser login (local only — auto-launches)
    """
    # 1. Env var / in-memory override
    if settings.bugcrowd_cookies_json:
        try:
            return json.loads(settings.bugcrowd_cookies_json)
        except json.JSONDecodeError:
            print("  [!] BUGCROWD_COOKIES_JSON is not valid JSON")

    # 2. Local file cache
    cache = Path.home() / ".bugcrowd" / "session_cookies.json"
    meta_file = Path.home() / ".bugcrowd" / "session_meta.json"
    if cache.exists() and meta_file.exists():
        import time
        try:
            meta = json.loads(meta_file.read_text())
            if meta.get("expires_at", 0) > time.time() + 60:
                cookies = json.loads(cache.read_text())
                if cookies and _validate_cookies(cookies):
                    return cookies
                elif cookies:
                    print("  [!] Cached Bugcrowd cookies exist but API validation failed")
        except (ValueError, KeyError):
            pass

    # 3. DB-persisted cookies
    try:
        from bounty_intel import service
        db_json = service.get_bugcrowd_cookies()
        if db_json:
            cookies = json.loads(db_json)
            if _validate_cookies(cookies):
                print("  [+] Using DB-persisted Bugcrowd cookies")
                return cookies
            print("  [!] DB Bugcrowd cookies expired")
    except Exception:
        pass

    # 4. Playwright browser login — local only
    if _is_server_environment():
        print("  [!] Bugcrowd cookies expired. No valid cookies in DB or cache.")
        return None

    print("  [*] Bugcrowd cookies expired — launching browser for login...")
    try:
        import sys
        auth_tools = str(Path(__file__).resolve().parents[2] / ".claude" / "skills" / "bugcrowd" / "tools")
        if auth_tools not in sys.path:
            sys.path.insert(0, auth_tools)
        from bugcrowd_auth import get_session_cookies  # type: ignore
        cookies = get_session_cookies()
        _push_cookies_to_server(cookies)
        return cookies
    except ImportError:
        print("  [!] bugcrowd_auth helper not available. Run: cd .claude/skills/bugcrowd/tools && python bugcrowd_auth.py")
    except Exception as e:
        print(f"  [!] Browser login failed: {e}")
    return None


def _push_cookies_to_server(cookies: dict) -> None:
    """Push fresh cookies to Cloud Run API so server-side syncs can use them."""
    import os
    api_url = settings.bounty_intel_api_url or os.environ.get("BOUNTY_INTEL_API_URL", "")
    api_key = settings.bounty_intel_api_key or os.environ.get("BOUNTY_INTEL_API_KEY", "")
    cookies_json = json.dumps(cookies)
    if not api_url or not api_key:
        try:
            from bounty_intel import service
            service.save_bugcrowd_cookies(cookies_json)
            print("  [+] Bugcrowd cookies saved to DB")
        except Exception:
            pass
        return
    try:
        data = json.dumps({"cookies": cookies_json}).encode()
        req = urllib.request.Request(
            f"{api_url}/api/v1/admin/bugcrowd-cookies",
            data=data, method="POST",
        )
        req.add_header("X-API-Key", api_key)
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"  [+] Bugcrowd cookies pushed to Cloud Run ({resp.status})")
    except Exception as e:
        print(f"  [!] Failed to push Bugcrowd cookies to server: {e}")


def _validate_cookies(cookies: dict) -> bool:
    """Quick check if cookies are still valid."""
    req = urllib.request.Request(f"{BASE_URL}{SUBMISSIONS_EP}?offset=0&limit=1")
    req.add_header("Cookie", _cookies_to_header(cookies))
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "BountyIntel/1.0")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return "application/json" in resp.headers.get("Content-Type", "")
    except Exception:
        return False


def _fetch_json(url: str, cookies: dict) -> dict | None:
    req = urllib.request.Request(url)
    req.add_header("Cookie", _cookies_to_header(cookies))
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "BountyIntel/1.0")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"  [!] Bugcrowd HTTP {e.code} for {url}")
        return None
    except Exception as e:
        print(f"  [!] Bugcrowd fetch error: {e}")
        return None


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


_HANDLE_RE = re.compile(r"/engagements/([^/]+)/submissions/")


def _program_handle_from_update_url(update_url: str) -> str:
    """Extract engagement handle from update_url like /engagements/gearset-mbb/submissions/<ref>."""
    m = _HANDLE_RE.search(update_url or "")
    return m.group(1) if m else ""


def fetch_submissions(cookies: dict) -> list[dict]:
    """Fetch all researcher submissions via dashboard endpoint."""
    url = f"{BASE_URL}{SUBMISSIONS_EP}?offset=0&limit=100"
    print("  [Bugcrowd] Fetching submissions...")
    data = _fetch_json(url, cookies)
    if not data:
        return []
    subs = data.get("submissions", []) if isinstance(data, dict) else []
    print(f"  [Bugcrowd] Fetched {len(subs)} submissions")
    return subs


def sync(since: datetime | None = None) -> dict:
    """Fetch Bugcrowd submissions and upsert into DB.

    No server-side delta filter available on the dashboard endpoint, so we fetch
    all and apply client-side watermark based on researcher_updated_at.
    """
    cookies = _get_cookies()
    if not cookies:
        return {"fetched": 0, "upserted": 0, "skipped": 0, "max_updated": since, "error": "no_cookie"}

    all_subs = fetch_submissions(cookies)
    if not all_subs:
        return {"fetched": 0, "upserted": 0, "skipped": 0, "max_updated": since, "error": "no_data"}

    session = get_session()
    upserted = 0
    skipped = 0
    max_updated = since

    for sub in all_subs:
        last_updated = _parse_iso(sub.get("researcher_updated_at") or sub.get("last_activity_date"))
        if since and last_updated and last_updated <= since:
            skipped += 1
            continue

        update_url = sub.get("update_url", "") or ""
        handle = _program_handle_from_update_url(update_url)
        if not handle:
            # Fallback to slugified program name
            handle = (sub.get("program_name", "") or "unknown").lower().replace(" ", "-")
        company = sub.get("program_name") or sub.get("engagement_name") or "Unknown"
        title = sub.get("title") or sub.get("caption") or ""
        substate = (sub.get("substate") or "").lower()
        disposition = BUGCROWD_SUBSTATE_TO_DISPOSITION.get(substate, substate or "unknown")

        # reference_number is the stable researcher-facing ID (hex string)
        ref_number = sub.get("reference_number", "")
        if not ref_number:
            continue

        # Upsert program
        prog_stmt = pg_insert(Program).values(
            platform="bugcrowd",
            platform_handle=handle,
            company_name=company,
        )
        prog_stmt = prog_stmt.on_conflict_do_update(
            constraint="uq_program_platform_handle",
            set_={"company_name": prog_stmt.excluded.company_name},
        )
        program_id = session.execute(prog_stmt.returning(Program.id)).scalar_one()

        # Bugcrowd list response has no severity/bounty — leave as Medium/0 until
        # detail endpoint is discovered. Forecast uses historical payouts anyway.
        sub_stmt = pg_insert(Submission).values(
            platform="bugcrowd",
            platform_id=ref_number,
            program_id=program_id,
            title=title,
            severity="Medium",
            disposition=disposition,
            listed_bounty=Decimal("0"),
            listed_currency="USD",
            created_at=_parse_iso(sub.get("created_at") or sub.get("submitted_at")),
            last_updated=last_updated,
            synced_at=datetime.now(timezone.utc),
        )
        sub_stmt = sub_stmt.on_conflict_do_update(
            constraint="uq_submission_platform_id",
            set_={
                "title": sub_stmt.excluded.title,
                "disposition": sub_stmt.excluded.disposition,
                "last_updated": sub_stmt.excluded.last_updated,
                "synced_at": datetime.now(timezone.utc),
            },
        )
        submission_id = session.execute(sub_stmt.returning(Submission.id)).scalar_one()

        # Reconcile linked SubmissionReport (by platform_submission_id or fuzzy title)
        linked_report = session.scalar(
            select(SubmissionReport).where(
                SubmissionReport.platform == "bugcrowd",
                SubmissionReport.platform_submission_id == ref_number,
            )
        )
        if not linked_report and title:
            candidates = session.scalars(
                select(SubmissionReport).where(
                    SubmissionReport.program_id == program_id,
                    SubmissionReport.platform == "bugcrowd",
                    SubmissionReport.platform_submission_id.is_(None),
                )
            ).all()
            best, best_score = None, 0.0
            for c in candidates:
                if not c.title:
                    continue
                score = SequenceMatcher(None, title.lower(), c.title.lower()).ratio()
                if score > best_score and score > 0.55:
                    best, best_score = c, score
            if best:
                best.platform_submission_id = ref_number
                sub_row = session.scalar(
                    select(Submission).where(Submission.id == submission_id)
                )
                if sub_row and not sub_row.report_id:
                    sub_row.report_id = best.id
                linked_report = best

        if linked_report:
            new_status = DISPOSITION_TO_REPORT_STATUS.get(disposition, linked_report.status)
            if linked_report.status != new_status:
                linked_report.status = new_status

        upserted += 1
        if last_updated and (max_updated is None or last_updated > max_updated):
            max_updated = last_updated

    session.commit()
    session.close()

    return {"fetched": len(all_subs), "upserted": upserted, "skipped": skipped, "max_updated": max_updated}


# Backwards-compat alias for the old name called by delta.py
def sync_bugcrowd_submissions(*, max_updated: str = "") -> dict:
    """Legacy entry point — accepts RFC3339 string; returns stats with datetime max_updated."""
    since = _parse_iso(max_updated) if max_updated else None
    return sync(since=since)
