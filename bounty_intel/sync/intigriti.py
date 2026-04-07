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
from difflib import SequenceMatcher
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
PROGRAMS_EP = "/api/core/researcher/programs"

# Intigriti program status: 3=open, 4=suspended/closed
PROGRAM_STATUS_MAP = {3: "open", 4: "suspended"}

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
    """Get Intigriti session cookie from multiple sources.

    Priority:
    1. INTIGRITI_COOKIE env var (for manual override / injected by sync API)
    2. Cached cookie from ~/.intigriti/session_cookie.txt (if still valid)
    3. Persisted cookie from DB (pushed by local login or dashboard)
    4. Playwright browser login (local only — auto-launches browser)
    """
    # 1. Env var / in-memory override
    if settings.intigriti_cookie:
        return settings.intigriti_cookie

    # 2. Local file cache
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

    # 3. DB-persisted cookie (pushed by local Playwright or dashboard)
    try:
        from bounty_intel import service
        db_cookie = service.get_intigriti_cookie()
        if db_cookie and _validate_cookie(db_cookie):
            print("  [+] Using DB-persisted Intigriti cookie")
            return db_cookie
        elif db_cookie:
            print("  [!] DB cookie expired")
    except Exception:
        pass  # DB not available (e.g. during local dev without DB)

    # 4. Playwright browser login — local only
    if _is_server_environment():
        print("  [!] Intigriti cookie expired. No valid cookie in DB or cache.")
        return None

    print("  [*] Intigriti cookie expired — launching browser for login...")
    try:
        import sys
        auth_tools = str(Path(__file__).resolve().parents[2] / ".claude" / "skills" / "intigriti" / "tools")
        if auth_tools not in sys.path:
            sys.path.insert(0, auth_tools)
        from intigriti_auth import get_session_cookie
        cookie = get_session_cookie()
        # Auto-push to Cloud Run DB for server-side use
        _push_cookie_to_server(cookie)
        return cookie
    except ImportError:
        print("  [!] Playwright not installed. Run: pip install playwright && playwright install chromium")
    except Exception as e:
        print(f"  [!] Browser login failed: {e}")

    return None


def _push_cookie_to_server(cookie: str) -> None:
    """Push fresh cookie to Cloud Run API so server-side syncs can use it."""
    import os
    api_url = settings.bounty_intel_api_url or os.environ.get("BOUNTY_INTEL_API_URL", "")
    api_key = settings.bounty_intel_api_key or os.environ.get("BOUNTY_INTEL_API_KEY", "")
    if not api_url or not api_key:
        # Try saving to DB directly if we have DB access
        try:
            from bounty_intel import service
            service.save_intigriti_cookie(cookie)
            print("  [+] Cookie saved to DB")
        except Exception:
            pass
        return
    try:
        data = json.dumps({"cookie": cookie}).encode()
        req = urllib.request.Request(
            f"{api_url}/api/v1/admin/intigriti-cookie",
            data=data, method="POST",
        )
        req.add_header("X-API-Key", api_key)
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"  [+] Cookie pushed to Cloud Run ({resp.status})")
    except Exception as e:
        print(f"  [!] Failed to push cookie to server: {e}")


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


def _extract_report_body(detail: dict | None) -> str:
    """Build markdown body from Intigriti submission detail fields."""
    if not detail:
        return ""
    parts = []
    endpoint = detail.get("endpointVulnerableComponent") or ""
    if endpoint:
        parts.append(f"**Endpoint**: `{endpoint}`\n")
    poc = detail.get("pocDescription") or ""
    if poc:
        parts.append(poc)
    impact = detail.get("impact") or ""
    if impact:
        parts.append(f"\n## Impact\n\n{impact}")
    solution = detail.get("recommendedSolution") or ""
    if solution:
        parts.append(f"\n## Recommended Solution\n\n{solution}")
    return "\n".join(parts)


def sync(since: datetime | None = None) -> dict:
    """Fetch Intigriti submissions and upsert changed ones into DB."""
    all_subs, cookie = fetch_submissions()
    if not all_subs:
        # Still sync program states (PAT doesn't need cookie)
        _sync_program_states(cookie)
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

        # Fetch detail if cookie exists and disposition is terminal or has bonus
        detail = None
        needs_detail = disposition in DISPOSITION_TO_REPORT_STATUS or sub.get("hasBonus")
        if cookie and needs_detail:
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
        title = sub.get("title", "")
        linked_report = session.scalar(
            select(SubmissionReport).where(SubmissionReport.platform_submission_id == sub_id_str)
        )
        # Fallback: try fuzzy title match on unlinked reports for this program
        if not linked_report and program_id and title:
            candidates = session.scalars(
                select(SubmissionReport).where(
                    SubmissionReport.program_id == program_id,
                    SubmissionReport.platform == "intigriti",
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
                best.platform_submission_id = sub_id_str
                sub_row = session.scalar(
                    select(Submission).where(Submission.platform == "intigriti", Submission.platform_id == sub_id_str)
                )
                if sub_row and not sub_row.report_id:
                    sub_row.report_id = best.id
                linked_report = best
        # Fallback 2: auto-create report from submission if disposition is terminal
        if not linked_report and disposition in DISPOSITION_TO_REPORT_STATUS and title:
            markdown_body = _extract_report_body(detail)
            new_report = SubmissionReport(
                program_id=program_id,
                platform="intigriti",
                title=title,
                severity=SEVERITY_MAP.get(sub.get("severity", 0), "Medium"),
                markdown_body=markdown_body,
                status=DISPOSITION_TO_REPORT_STATUS[disposition],
                platform_submission_id=sub_id_str,
                submitted_at=_ts_to_dt(sub.get("createdAt")),
            )
            session.add(new_report)
            session.flush()
            sub_row = session.scalar(
                select(Submission).where(Submission.platform == "intigriti", Submission.platform_id == sub_id_str)
            )
            if sub_row and not sub_row.report_id:
                sub_row.report_id = new_report.id
            linked_report = new_report
        if linked_report:
            new_status = DISPOSITION_TO_REPORT_STATUS.get(disposition, linked_report.status)
            if linked_report.status != new_status:
                linked_report.status = new_status
            # Backfill empty report body from platform detail
            if not linked_report.markdown_body:
                if detail:
                    body = _extract_report_body(detail)
                    if body:
                        linked_report.markdown_body = body
                        print(f"  [Intigriti] Backfilled report {linked_report.id} body ({len(body)} chars)")
                    else:
                        print(f"  [Intigriti] Report {linked_report.id}: detail fetched but no body fields found. Keys: {sorted(detail.keys()) if isinstance(detail, dict) else type(detail)}")
                else:
                    print(f"  [Intigriti] Report {linked_report.id}: no detail available (cookie={bool(cookie)}, needs_detail={needs_detail})")

        upserted += 1
        if last_updated and (max_updated is None or last_updated > max_updated):
            max_updated = last_updated

    session.commit()
    session.close()

    # Sync program states (uses PAT primarily, cookie as fallback)
    _sync_program_states(cookie)

    return {"fetched": len(all_subs), "upserted": upserted, "skipped": skipped, "max_updated": max_updated}


def _fetch_programs_via_pat() -> list[dict] | None:
    """Fetch programs from Intigriti External API using PAT (no cookie needed)."""
    import os
    pat = settings.intigriti_pat if hasattr(settings, "intigriti_pat") else os.environ.get("INTIGRITI_PAT", "")
    if not pat:
        return None
    url = "https://api.intigriti.com/external/researcher/v1/programs?limit=200"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {pat}")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "BountyIntel/1.0")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data.get("records", []) if isinstance(data, dict) else data
    except Exception as e:
        print(f"  [!] External API error: {e}")
        return None


def _sync_program_states(cookie: str | None = None) -> None:
    """Fetch program listing from Intigriti and update platform_state in scope.

    Uses PAT (External API) as primary source — no cookie needed.
    Falls back to Core API with cookie if PAT unavailable.
    """
    print("  [Intigriti] Syncing program states...")

    # Primary: PAT-based External API (always available, no expiry)
    programs_list = _fetch_programs_via_pat()
    source = "PAT"

    # Fallback: cookie-based Core API
    if not programs_list and cookie:
        url = f"{BASE_URL}{PROGRAMS_EP}?offset=0&limit=200"
        data = _fetch_json(url, cookie)
        programs_list = data if isinstance(data, list) else (data.get("records", data.get("data", [])) if data else [])
        source = "cookie"

    if not programs_list:
        print("  [!] Could not fetch programs list (no PAT or cookie)")
        return

    print(f"  [Intigriti] Fetched {len(programs_list)} programs via {source}")

    # Build handle → platform_state map
    # External API: status = {"id": 3, "value": "Open"}, handle = program-only
    # Core API: status = 3 (int), companyHandle/handle = company/program
    state_map: dict[str, str] = {}
    for p in programs_list:
        # External API format
        status_raw = p.get("status")
        if isinstance(status_raw, dict):
            status_int = status_raw.get("id", 3)
        else:
            status_int = status_raw if isinstance(status_raw, int) else 3

        company_handle = p.get("companyHandle", "")
        program_handle = p.get("handle", "")
        handle = f"{company_handle}/{program_handle}" if company_handle else program_handle
        state_map[handle] = PROGRAM_STATUS_MAP.get(status_int, "open")

    session = get_session()
    updated = 0
    db_programs = session.scalars(
        select(Program).where(Program.platform == "intigriti")
    ).all()
    for prog in db_programs:
        # Try exact match first, then match by program handle suffix
        platform_state = state_map.get(prog.platform_handle, "")
        if not platform_state:
            # External API only has program handle (no company prefix)
            suffix = prog.platform_handle.split("/")[-1] if "/" in prog.platform_handle else prog.platform_handle
            platform_state = state_map.get(suffix, "")
        if not platform_state:
            continue
        current_state = (prog.scope or {}).get("platform_state", "")
        if current_state != platform_state:
            scope = dict(prog.scope or {})
            scope["platform_state"] = platform_state
            prog.scope = scope
            updated += 1
    session.commit()
    session.close()
    print(f"  [Intigriti] Updated {updated} program states")
