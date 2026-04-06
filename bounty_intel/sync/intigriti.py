"""Intigriti delta sync — fetches submissions via BFF API and upserts into DB.

Intigriti has no server-side date filter, so we fetch all submissions (typically
<100) and apply client-side watermark filtering. Only changed records get upserted.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from bounty_intel.config import settings
from bounty_intel.db import Payout, Program, Submission, SubmissionReport, get_session
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

DISPOSITION_TO_REPORT_STATUS = {
    "resolved": "accepted", "accepted": "accepted",
    "duplicate": "rejected", "informative": "rejected",
    "not_applicable": "rejected", "wont_fix": "rejected", "out_of_scope": "rejected",
    "triaged": "submitted", "new": "submitted",
}

BASE_URL = "https://app.intigriti.com"
SUBMISSIONS_EP = "/api/core/researcher/submissions"
DETAIL_EP = "/api/core/researcher/submissions/{submission_id}"

CLOSE_REASONS = {1: "resolved", 2: "duplicate", 3: "not_applicable", 4: "informative",
                 5: "out_of_scope", 6: "wont_fix", 7: "not_applicable"}

STATUS_MAP = {1: "new", 2: "triaged", 3: "accepted", 4: "closed", 5: "archived"}

SEVERITY_MAP = {1: "None", 2: "Low", 3: "Medium", 4: "High", 5: "Critical",
                6: "Critical", 7: "Exceptional"}

PAYOUT_STATUS = {1: "Pending", 2: "Processing", 3: "Paid", 4: "Failed", 5: "Completed"}
PAYOUT_TYPE = {1: "Bounty", 2: "Tip", 3: "Bonus", 4: "Swag", 5: "Kudos", 6: "Retest", 7: "Additional"}


def _is_server_environment() -> bool:
    """Detect if running on Cloud Run or other headless server (no browser available)."""
    import os
    return bool(
        os.environ.get("K_SERVICE")           # Cloud Run
        or os.environ.get("KUBERNETES_SERVICE_HOST")  # K8s
        or os.environ.get("CI")               # CI/CD
    )


def _get_cookie() -> str | None:
    """Get Intigriti session cookie, launching browser login if needed.

    Priority:
    1. INTIGRITI_COOKIE env var (for manual override)
    2. Cached cookie from ~/.intigriti/session_cookie.txt (if still valid)
    3. Playwright browser login (automatic on local, skipped on server)
    """
    # 1. Env var override
    if settings.intigriti_cookie:
        return settings.intigriti_cookie

    # 2. Cached cookie — check if file exists AND is still valid
    cached = Path.home() / ".intigriti" / "session_cookie.txt"
    meta_file = Path.home() / ".intigriti" / "session_meta.json"

    if cached.exists() and meta_file.exists():
        import json as _json
        import time
        try:
            meta = _json.loads(meta_file.read_text())
            if meta.get("expires_at", 0) > time.time() + 60:
                cookie = cached.read_text().strip()
                if cookie:
                    if _validate_cookie(cookie):
                        return cookie
                    else:
                        print("  [!] Cached cookie exists but API validation failed")
        except (ValueError, KeyError):
            pass

    # 3. Playwright browser login — automatic on local environments
    if _is_server_environment():
        print("  [!] Intigriti cookie expired. Cannot launch browser on server.")
        print("      Sync locally first: python -m bounty_intel sync --source intigriti")
        return None

    print("  [*] Intigriti cookie expired — launching browser for login...")
    try:
        import sys
        auth_tools = str(Path(__file__).resolve().parents[2] / ".claude" / "skills" / "intigriti" / "tools")
        if auth_tools not in sys.path:
            sys.path.insert(0, auth_tools)
        from intigriti_auth import get_session_cookie
        cookie = get_session_cookie()
        return cookie
    except ImportError:
        print("  [!] Playwright not installed. Run: pip install playwright && playwright install chromium")
    except Exception as e:
        print(f"  [!] Browser login failed: {e}")

    return None


def _validate_cookie(cookie: str) -> bool:
    """Quick check if cookie is still valid."""
    import urllib.error
    import urllib.request
    req = urllib.request.Request("https://app.intigriti.com/api/core/researcher/submissions?offset=0&limit=1")
    req.add_header("Cookie", f"__Host-Intigriti.Web.Researcher={cookie}")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "BountyIntel/1.0")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return "application/json" in resp.headers.get("Content-Type", "")
    except Exception:
        return False


def _fetch_json(url: str, cookie: str) -> dict | list | None:
    req = urllib.request.Request(url)
    req.add_header("Cookie", f"__Host-Intigriti.Web.Researcher={cookie}")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "BountyIntel/1.0")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"  [!] Intigriti HTTP {e.code}")
        return None


def _classify(sub: dict) -> str:
    """Classify submission into disposition."""
    status = sub.get("state", {}).get("status", 0)
    close_reason = sub.get("state", {}).get("closeReason")

    if status in (4, 5) and close_reason in CLOSE_REASONS:
        return CLOSE_REASONS[close_reason]
    if status == 3:
        return "accepted"
    if status == 2:
        return "triaged"
    if status == 1:
        return "new"
    return "unknown"


def _ts_to_dt(ts: int | None) -> datetime | None:
    if not ts:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def fetch_submissions() -> tuple[list[dict], str | None]:
    """Fetch all submissions from Intigriti API.

    Automatically launches browser login if cookie is expired (local only).
    Returns (submissions_list, cookie) tuple.
    """
    cookie = _get_cookie()
    if not cookie:
        return [], None

    url = f"{BASE_URL}{SUBMISSIONS_EP}?offset=0&limit=100"
    print(f"  [Intigriti] Fetching submissions...")
    data = _fetch_json(url, cookie)
    if data is None:
        print("  [!] API returned no data. Cookie may have expired during request.")
        return [], None

    subs = data if isinstance(data, list) else data.get("records", data.get("data", []))
    print(f"  [Intigriti] Fetched {len(subs)} submissions")
    return subs, cookie


def fetch_detail(cookie: str, submission_id: str) -> dict | None:
    """Fetch full submission detail (includes payouts)."""
    url = f"{BASE_URL}{DETAIL_EP.format(submission_id=submission_id)}"
    return _fetch_json(url, cookie)


def sync(since: datetime | None = None) -> dict:
    """Fetch Intigriti submissions and upsert changed ones into DB."""
    all_subs, cookie = fetch_submissions()
    if not all_subs:
        return {"fetched": 0, "upserted": 0, "skipped": 0, "max_updated": since, "error": "no_cookie" if not cookie else "no_data"}
    session = get_session()
    upserted = 0
    skipped = 0
    max_updated = since

    for sub in all_subs:
        last_updated_ts = sub.get("lastUpdatedAt") or sub.get("createdAt", 0)
        last_updated = _ts_to_dt(last_updated_ts)

        # Client-side delta filter
        if since and last_updated and last_updated <= since:
            skipped += 1
            continue

        company = sub.get("companyName") or sub.get("programName") or "Unknown"
        company_handle = sub.get("companyHandle", "")
        program_handle = sub.get("programHandle", "")
        handle = f"{company_handle}/{program_handle}" if company_handle else program_handle
        severity_raw = sub.get("severity", 0)
        severity = SEVERITY_MAP.get(severity_raw, "Medium")
        disposition = _classify(sub)
        bounty = sub.get("bounty", {})
        listed_bounty = bounty.get("value", 0) or 0
        listed_currency = bounty.get("currency", "EUR")

        # Build logo URL from programLogoId
        # Format: "public_bucket_{company_uuid}-{logo_uuid}"
        # URL:    https://app.intigriti.com/cdn/company/{company_uuid}/logo/{logo_uuid}
        logo_url = ""
        logo_id = sub.get("programLogoId", "")
        if logo_id and logo_id.startswith("public_bucket_"):
            parts = logo_id[len("public_bucket_"):].split("-")
            if len(parts) == 10:
                # Two UUIDs, 5 segments each: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
                uuid1 = "-".join(parts[:5])
                uuid2 = "-".join(parts[5:])
                logo_url = f"https://app.intigriti.com/cdn/company/{uuid1}/logo/{uuid2}"

        # Upsert program
        prog_stmt = pg_insert(Program).values(
            platform="intigriti",
            platform_handle=handle,
            company_name=company,
            logo_url=logo_url,
        )
        prog_stmt = prog_stmt.on_conflict_do_update(
            constraint="uq_program_platform_handle",
            set_={
                "company_name": prog_stmt.excluded.company_name,
                "logo_url": prog_stmt.excluded.logo_url,
            },
        )
        program_id = session.execute(prog_stmt.returning(Program.id)).scalar_one()

        # Upsert submission
        sub_stmt = pg_insert(Submission).values(
            platform="intigriti",
            platform_id=str(sub.get("id", "")),
            program_id=program_id,
            title=sub.get("title", ""),
            severity=severity,
            disposition=disposition,
            listed_bounty=Decimal(str(listed_bounty)),
            listed_currency=listed_currency,
            created_at=_ts_to_dt(sub.get("createdAt")),
            last_updated=last_updated,
            synced_at=datetime.now(timezone.utc),
        )
        sub_stmt = sub_stmt.on_conflict_do_update(
            constraint="uq_submission_platform_id",
            set_={
                "title": sub_stmt.excluded.title,
                "severity": sub_stmt.excluded.severity,
                "disposition": sub_stmt.excluded.disposition,
                "listed_bounty": sub_stmt.excluded.listed_bounty,
                "last_updated": sub_stmt.excluded.last_updated,
                "synced_at": datetime.now(timezone.utc),
            },
        )
        submission_id = session.execute(sub_stmt.returning(Submission.id)).scalar_one()

        # Fetch payouts if detail available and cookie exists
        if cookie and (disposition in ("resolved", "accepted") or sub.get("hasBonus")):
            detail = fetch_detail(cookie, str(sub.get("id", "")))
            if detail and "payouts" in detail:
                for p in detail["payouts"]:
                    amt = p.get("amount", {}).get("value", 0)
                    if amt <= 0:
                        continue
                    cur = p.get("amount", {}).get("currency", "EUR")
                    ptype = PAYOUT_TYPE.get(p.get("type"), "Bounty")
                    pstatus = PAYOUT_STATUS.get(p.get("status"), "Pending")
                    paid_ts = p.get("createdAt", 0)
                    paid_date = datetime.fromtimestamp(paid_ts).strftime("%Y-%m-%d") if paid_ts else None

                    existing = session.query(Payout).filter_by(
                        submission_id=submission_id,
                        payout_type=ptype,
                        amount=Decimal(str(amt)),
                    ).first()
                    if not existing:
                        session.add(Payout(
                            submission_id=submission_id,
                            amount=Decimal(str(amt)),
                            currency=cur,
                            payout_type=ptype,
                            status=pstatus,
                            paid_date=paid_date,
                        ))

        # Sync report status if linked
        sub_id_str = str(sub.get("id", ""))
        linked_report = session.scalar(
            select(SubmissionReport).where(SubmissionReport.platform_submission_id == sub_id_str)
        )
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
