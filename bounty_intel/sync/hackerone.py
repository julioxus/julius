"""HackerOne delta sync — fetches reports via API and upserts into DB.

Reuses normalization logic from report_aggregator.py but writes to PostgreSQL
instead of JSON files. Supports server-side delta via updated_at filter.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from decimal import Decimal

from bounty_intel.config import settings
from bounty_intel.db import Payout, Program, Submission, SubmissionReport, get_session
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

DISPOSITION_TO_REPORT_STATUS = {
    "resolved": "accepted",
    "duplicate": "rejected",
    "informative": "rejected",
    "not_applicable": "rejected",
    "triaged": "submitted",
    "new": "submitted",
    "needs_more_info": "submitted",
}

H1_API_BASE = "https://api.hackerone.com/v1"

H1_STATE_TO_DISPOSITION = {
    "new": "new",
    "triaged": "triaged",
    "needs-more-info": "needs_more_info",
    "resolved": "resolved",
    "informative": "informative",
    "duplicate": "duplicate",
    "spam": "not_applicable",
    "not-applicable": "not_applicable",
}

H1_ESTIMATED_BOUNTY = {
    "Critical": 3000,
    "High": 1500,
    "Medium": 500,
    "Low": 150,
    "None": 0,
}


def _auth_header() -> str | None:
    username = settings.hackerone_username
    token = settings.hackerone_api_token
    if not username or not token:
        return None
    creds = base64.b64encode(f"{username}:{token}".encode()).decode()
    return f"Basic {creds}"


def _fetch(url: str, auth: str) -> dict:
    req = urllib.request.Request(url)
    req.add_header("Authorization", auth)
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "BountyIntel/1.0")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _extract_severity(report: dict) -> str:
    attrs = report.get("attributes", {})
    rating = attrs.get("severity_rating", "")
    if rating:
        return rating.capitalize()
    sev_data = report.get("relationships", {}).get("severity", {}).get("data", {})
    if sev_data:
        rating = sev_data.get("attributes", {}).get("rating", "")
        if rating:
            return rating.capitalize()
    return "Medium"


def _extract_program(report: dict) -> tuple[str, str, str]:
    """Returns (handle, company_name, logo_url)."""
    team = report.get("relationships", {}).get("program", {}).get("data", {})
    if not team:
        team = report.get("relationships", {}).get("team", {}).get("data", {})
    attrs = team.get("attributes", {}) if team else {}
    handle = attrs.get("handle", "unknown")
    name = attrs.get("name", handle)
    # HackerOne provides profile_picture_urls with multiple sizes
    pics = attrs.get("profile_picture_urls", {})
    logo_url = pics.get("medium", "") or pics.get("small", "") or ""
    return handle, name, logo_url


def _extract_bounties(report: dict) -> list[dict]:
    bounties_rel = report.get("relationships", {}).get("bounties", {}).get("data", [])
    payouts = []
    for b in bounties_rel:
        b_attrs = b.get("attributes", {})
        amount = float(b_attrs.get("amount", 0) or 0)
        bonus = float(b_attrs.get("bonus_amount", 0) or 0)
        created = b_attrs.get("created_at", "")
        if amount > 0:
            payouts.append({
                "amount": amount,
                "currency": "USD",
                "payout_type": "Bounty",
                "status": "Paid",
                "paid_date": created[:10] if created else None,
            })
        if bonus > 0:
            payouts.append({
                "amount": bonus,
                "currency": "USD",
                "payout_type": "Bonus",
                "status": "Paid",
                "paid_date": created[:10] if created else None,
            })
    return payouts


def fetch_reports(since: datetime | None = None) -> list[dict]:
    """Fetch H1 reports, optionally filtered by updated_at > since."""
    auth = _auth_header()
    if not auth:
        print("  [!] HackerOne credentials not configured")
        return []

    url = f"{H1_API_BASE}/hackers/me/reports?page%5Bsize%5D=100"
    if since:
        ts = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        url += f"&filter%5Bupdated_at__gt%5D={ts}"

    reports = []
    page = 1
    while url:
        print(f"  [H1] Fetching page {page}...")
        try:
            data = _fetch(url, auth)
        except urllib.error.HTTPError as e:
            print(f"  [!] H1 API error: HTTP {e.code}")
            break
        except urllib.error.URLError as e:
            print(f"  [!] H1 connection error: {e.reason}")
            break

        reports.extend(data.get("data", []))
        url = data.get("links", {}).get("next")
        page += 1

    print(f"  [H1] Fetched {len(reports)} reports")
    return reports


def sync(since: datetime | None = None) -> dict:
    """Fetch H1 reports and upsert into DB. Returns sync stats."""
    reports = fetch_reports(since=since)
    if not reports:
        return {"fetched": 0, "upserted": 0, "max_updated": since}

    session = get_session()
    upserted = 0
    max_updated = since

    for report in reports:
        attrs = report.get("attributes", {})
        handle, company, logo_url = _extract_program(report)
        severity = _extract_severity(report)
        state = attrs.get("state", "new")
        disposition = H1_STATE_TO_DISPOSITION.get(state, "unknown")
        bounties = _extract_bounties(report)
        total_paid = sum(p["amount"] for p in bounties)

        listed_bounty = total_paid if total_paid > 0 else H1_ESTIMATED_BOUNTY.get(severity, 500)

        last_updated = _parse_iso(
            attrs.get("last_activity_at") or attrs.get("updated_at") or attrs.get("created_at")
        )

        # Upsert program
        prog_stmt = pg_insert(Program).values(
            platform="hackerone",
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
            platform="hackerone",
            platform_id=str(report.get("id", "")),
            program_id=program_id,
            title=attrs.get("title", ""),
            severity=severity,
            disposition=disposition,
            listed_bounty=Decimal(str(listed_bounty)),
            listed_currency="USD",
            created_at=_parse_iso(attrs.get("created_at")),
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

        # Upsert payouts
        for p in bounties:
            existing = session.query(Payout).filter_by(
                submission_id=submission_id,
                payout_type=p["payout_type"],
                amount=Decimal(str(p["amount"])),
            ).first()
            if not existing:
                session.add(Payout(
                    submission_id=submission_id,
                    amount=Decimal(str(p["amount"])),
                    currency=p["currency"],
                    payout_type=p["payout_type"],
                    status=p["status"],
                    paid_date=p["paid_date"],
                ))

        # Sync report status: if a submission_report is linked, update its status
        platform_id_str = str(report.get("id", ""))
        linked_report = session.scalar(
            select(SubmissionReport).where(SubmissionReport.platform_submission_id == platform_id_str)
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

    return {"fetched": len(reports), "upserted": upserted, "max_updated": max_updated}
