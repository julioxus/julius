"""Bugcrowd delta sync — fetches submissions via API and upserts into DB.

Follows the same pattern as hackerone.py but for Bugcrowd platform.
Supports server-side delta via updated_at filter.
"""

from __future__ import annotations

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
    "rejected": "rejected",
    "duplicate": "rejected",
    "invalid": "rejected",
    "triaged": "submitted",
    "new": "submitted",
    "unresolved": "submitted",
}

BUGCROWD_API_BASE = "https://api.bugcrowd.com"

BUGCROWD_STATE_TO_DISPOSITION = {
    "new": "new",
    "triaged": "triaged",
    "unresolved": "unresolved",
    "resolved": "resolved",
    "rejected": "rejected",
    "duplicate": "duplicate",
    "invalid": "invalid",
}

BUGCROWD_ESTIMATED_BOUNTY = {
    "Critical": 5000,
    "High": 2500,
    "Medium": 1000,
    "Low": 250,
    "Informational": 0,
}


def _bugcrowd_headers() -> dict[str, str]:
    return {
        "Authorization": f"Token {settings.bugcrowd_token}",
        "Accept": "application/vnd.bugcrowd+json",
        "User-Agent": "BountyIntel/1.0",
    }


def _api_get_bugcrowd(url: str) -> dict | None:
    """GET request to Bugcrowd API with error handling."""
    req = urllib.request.Request(url, headers=_bugcrowd_headers(), method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as e:
        print(f"[bugcrowd] API request failed for {url}: {e}")
        return None


def _upsert_bugcrowd_program(session, program_data: dict) -> int:
    """Upsert Bugcrowd program into database, return program ID."""
    stmt = pg_insert(Program).values(
        platform="bugcrowd",
        handle=program_data["code"],
        company_name=program_data["name"],
        status="open" if program_data.get("state") == "running" else "paused",
        bounty_type="bounty" if program_data.get("bounty_enabled", False) else "vdp",
        tech_stack=[],
        notes=program_data.get("brief", ""),
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["platform", "handle"],
        set_=dict(
            company_name=stmt.excluded.company_name,
            status=stmt.excluded.status,
            bounty_type=stmt.excluded.bounty_type,
            notes=stmt.excluded.notes,
        ),
    )
    result = session.execute(stmt.returning(Program.id))
    return result.scalar()


def _normalize_bugcrowd_submission(raw: dict) -> dict:
    """Convert raw Bugcrowd submission to normalized format."""
    # Map Bugcrowd states to our disposition
    state = raw.get("state", "").lower()
    disposition = BUGCROWD_STATE_TO_DISPOSITION.get(state, state)

    # Extract severity/priority
    severity = raw.get("severity", "Medium")
    if not severity:
        severity = "Medium"

    # Extract bounty amount
    bounty_amount = 0
    bounty_currency = "USD"
    if raw.get("bounty"):
        bounty_data = raw["bounty"]
        if isinstance(bounty_data, dict):
            cents = bounty_data.get("cents", 0)
            bounty_amount = cents / 100 if cents else 0
            bounty_currency = bounty_data.get("currency", "USD")

    # Use estimated bounty if no actual bounty
    if bounty_amount == 0:
        bounty_amount = BUGCROWD_ESTIMATED_BOUNTY.get(severity, 0)

    # Extract program info
    program = raw.get("program", {})
    program_name = program.get("name", "Unknown Program")

    return {
        "platform_id": str(raw.get("uuid", "")),
        "platform": "bugcrowd",
        "title": raw.get("title", ""),
        "severity": severity,
        "disposition": disposition,
        "listed_bounty": bounty_amount,
        "listed_currency": bounty_currency,
        "company_name": program_name,
        "created_at": raw.get("created_at"),
        "updated_at": raw.get("updated_at"),
        "program_code": program.get("code", ""),
    }


def sync_bugcrowd_submissions(*, max_updated: str = "") -> dict:
    """Fetch submissions from Bugcrowd API and sync to database.

    Args:
        max_updated: RFC3339 timestamp - only fetch submissions newer than this

    Returns:
        Dict with sync stats: fetched, upserted, max_updated
    """
    if not settings.bugcrowd_email or not settings.bugcrowd_token:
        print("[bugcrowd] Missing credentials, skipping sync")
        return {"fetched": 0, "upserted": 0, "max_updated": max_updated}

    print(f"[bugcrowd] Starting submission sync (since {max_updated or 'beginning'})")

    with get_session() as session:
        # Build API URL with filters
        url = f"{BUGCROWD_API_BASE}/submissions"
        params = ["limit=100"]  # Bugcrowd API pagination

        if max_updated:
            params.append(f"updated_since={max_updated}")

        if params:
            url += "?" + "&".join(params)

        fetched = 0
        upserted = 0
        latest_updated = max_updated

        while url:
            print(f"[bugcrowd] Fetching: {url}")
            data = _api_get_bugcrowd(url)

            if not data:
                break

            submissions = data.get("submissions", [])

            for submission in submissions:
                try:
                    normalized = _normalize_bugcrowd_submission(submission)
                    fetched += 1

                    # Ensure we have a program for this submission
                    program_code = normalized["program_code"]
                    if program_code:
                        program_id = session.execute(
                            select(Program.id).where(
                                Program.platform == "bugcrowd",
                                Program.handle == program_code
                            )
                        ).scalar()

                        if not program_id:
                            # Fetch and create program if it doesn't exist
                            program_url = f"{BUGCROWD_API_BASE}/programs/{program_code}"
                            program_data = _api_get_bugcrowd(program_url)
                            if program_data:
                                program_id = _upsert_bugcrowd_program(session, program_data)

                        # Upsert submission
                        stmt = pg_insert(Submission).values(
                            platform_id=normalized["platform_id"],
                            platform=normalized["platform"],
                            program_id=program_id,
                            title=normalized["title"],
                            severity=normalized["severity"],
                            disposition=normalized["disposition"],
                            listed_bounty=normalized["listed_bounty"],
                            listed_currency=normalized["listed_currency"],
                            company_name=normalized["company_name"],
                            created_at=datetime.fromisoformat(normalized["created_at"].replace('Z', '+00:00')) if normalized.get("created_at") else datetime.now(timezone.utc),
                        )
                        stmt = stmt.on_conflict_do_update(
                            index_elements=["platform", "platform_id"],
                            set_=dict(
                                disposition=stmt.excluded.disposition,
                                listed_bounty=stmt.excluded.listed_bounty,
                                title=stmt.excluded.title,
                                severity=stmt.excluded.severity,
                            ),
                        )
                        session.execute(stmt)
                        upserted += 1

                    # Track latest timestamp
                    if normalized.get("updated_at"):
                        if not latest_updated or normalized["updated_at"] > latest_updated:
                            latest_updated = normalized["updated_at"]

                except Exception as e:
                    print(f"[bugcrowd] Error processing submission {submission.get('uuid', 'unknown')}: {e}")
                    continue

            # Check for next page
            meta = data.get("meta", {})
            links = meta.get("links", {})
            url = links.get("next")

            # Commit batch
            session.commit()

        print(f"[bugcrowd] Sync complete: {fetched} fetched, {upserted} upserted")
        return {
            "fetched": fetched,
            "upserted": upserted,
            "max_updated": latest_updated,
        }