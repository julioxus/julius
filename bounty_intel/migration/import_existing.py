"""One-shot migration: import existing outputs/ data into the PostgreSQL database.

Reads:
  - outputs/combined-inbox/report_latest.json → programs, submissions, payouts
  - outputs/combined-inbox/ai_evaluation.json → ai_evaluations
  - outputs/hunt_memory.jsonl → hunt_memory
  - outputs/*/processed/findings/*/description.md → engagements, findings
  - outputs/*/reports/submissions/*.md → submission_reports

Usage:
    python -m bounty_intel.migration.import_existing [--base-dir /path/to/julius]
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from sqlalchemy.dialects.postgresql import insert as pg_insert

from bounty_intel.db import (
    AIEvaluation,
    Engagement,
    Finding,
    HuntMemory,
    Payout,
    Program,
    Submission,
    SubmissionReport,
    get_session,
)


def _parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        s = s.replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def _detect_platform_from_dir(dirname: str) -> tuple[str, str]:
    """Extract platform and handle from directory name like 'hackerone-bcny' or 'intigriti-truelayer'."""
    if dirname.startswith("hackerone-"):
        return "hackerone", dirname.removeprefix("hackerone-")
    if dirname.startswith("intigriti-"):
        return "intigriti", dirname.removeprefix("intigriti-")
    return "unknown", dirname


def _normalize_handle(platform: str, handle: str, company: str = "") -> str:
    """Normalize program handle to a canonical form.

    For Intigriti, the canonical form is 'company/program' (from directory names).
    For HackerOne, it's just the handle.
    Handles from report_latest.json may be short ('altera') or long ('altera/altera').
    Directory names are always the short form ('intigriti-altera' → 'altera').
    We use the short form as canonical to avoid duplication.
    """
    if platform == "hackerone":
        return handle
    # For Intigriti: strip to shortest unique form
    # "altera/altera" → "altera", "company/program" stays as-is if different
    if "/" in handle:
        parts = handle.split("/", 1)
        if parts[0] == parts[1]:
            return parts[0]  # "altera/altera" → "altera"
    return handle


def _extract_severity_from_md(content: str) -> tuple[str, str]:
    """Extract severity and CVSS from markdown content."""
    severity = ""
    cvss = ""
    sev_match = re.search(r"\*\*Severity\*\*:?\s*(\w+)", content)
    if sev_match:
        severity = sev_match.group(1)
    cvss_match = re.search(r"(CVSS:3\.\d/[A-Za-z:/]+)", content)
    if cvss_match:
        cvss = cvss_match.group(1)
    return severity, cvss


def import_report_json(base_dir: Path):
    """Import programs and submissions from report_latest.json."""
    report_file = base_dir / "outputs" / "combined-inbox" / "report_latest.json"
    if not report_file.exists():
        print(f"  Skipping report_latest.json (not found)")
        return

    with open(report_file) as f:
        data = json.load(f)

    session = get_session()
    program_cache: dict[str, int] = {}

    all_subs = (
        data.get("paid_submissions", [])
        + data.get("pending_submissions", [])
        + data.get("rejected_submissions", [])
    )

    print(f"  Importing {len(all_subs)} submissions...")

    for sub in all_subs:
        company = sub.get("company") or sub.get("program") or "Unknown"
        platform = sub.get("platform", "intigriti")
        raw_handle = sub.get("program_handle") or sub.get("company_handle") or company.lower().replace(" ", "-")
        handle = _normalize_handle(platform, raw_handle, company)

        cache_key = f"{platform}:{handle}"
        if cache_key not in program_cache:
            stmt = pg_insert(Program).values(
                platform=platform,
                platform_handle=handle,
                company_name=company,
                bounty_type=sub.get("program_type", "bounty"),
            )
            stmt = stmt.on_conflict_do_update(
                constraint="uq_program_platform_handle",
                set_={"company_name": stmt.excluded.company_name},
            )
            result = session.execute(stmt.returning(Program.id))
            program_cache[cache_key] = result.scalar_one()
            session.commit()

        program_id = program_cache[cache_key]

        sub_stmt = pg_insert(Submission).values(
            platform=platform,
            platform_id=str(sub.get("id", "")),
            program_id=program_id,
            title=sub.get("title", ""),
            severity=sub.get("severity", ""),
            disposition=sub.get("disposition", "new"),
            listed_bounty=Decimal(str(sub.get("listed_bounty", 0) or 0)),
            listed_currency=sub.get("listed_currency", "EUR"),
            created_at=_parse_iso(sub.get("created_at")),
            last_updated=_parse_iso(sub.get("last_updated") or sub.get("created_at")),
            synced_at=datetime.now(timezone.utc),
        )
        sub_stmt = sub_stmt.on_conflict_do_update(
            constraint="uq_submission_platform_id",
            set_={
                "disposition": sub_stmt.excluded.disposition,
                "listed_bounty": sub_stmt.excluded.listed_bounty,
                "synced_at": datetime.now(timezone.utc),
            },
        )
        result = session.execute(sub_stmt.returning(Submission.id))
        submission_id = result.scalar_one()
        session.commit()

        for payout in sub.get("payouts", []):
            session.add(Payout(
                submission_id=submission_id,
                amount=Decimal(str(payout.get("amount", 0))),
                currency=payout.get("currency", "EUR"),
                amount_eur=Decimal(str(payout.get("amount_eur", 0))) if payout.get("amount_eur") else None,
                payout_type=payout.get("type", "Bounty"),
                status=payout.get("status", "Paid"),
                paid_date=payout.get("paid_date"),
            ))

    session.commit()
    session.close()
    print(f"  Done: {len(program_cache)} programs, {len(all_subs)} submissions")


def import_ai_evaluations(base_dir: Path):
    """Import AI evaluations from ai_evaluation.json."""
    eval_file = base_dir / "outputs" / "combined-inbox" / "ai_evaluation.json"
    if not eval_file.exists():
        print(f"  Skipping ai_evaluation.json (not found)")
        return

    with open(eval_file) as f:
        data = json.load(f)

    if isinstance(data, dict):
        evals = list(data.values()) if not isinstance(next(iter(data.values()), None), dict) else [data]
    elif isinstance(data, list):
        evals = data
    else:
        print(f"  Unexpected ai_evaluation.json format")
        return

    session = get_session()
    imported = 0

    for ev in evals:
        sub_id_str = str(ev.get("id", ""))
        if not sub_id_str:
            continue

        sub = session.query(Submission).filter_by(platform_id=sub_id_str).first()
        if not sub:
            continue

        existing = session.query(AIEvaluation).filter_by(submission_id=sub.id).first()
        if existing:
            continue

        session.add(AIEvaluation(
            submission_id=sub.id,
            acceptance_probability=ev.get("acceptance_probability"),
            confidence=ev.get("confidence"),
            likely_outcome=ev.get("likely_outcome", ""),
            severity_assessment=ev.get("severity_assessment", ""),
            strengths=ev.get("strengths", []),
            weaknesses=ev.get("weaknesses", []),
            triager_reasoning=ev.get("triager_reasoning", ""),
            suggested_improvements=ev.get("suggested_improvements", []),
        ))
        imported += 1

    session.commit()
    session.close()
    print(f"  Imported {imported} AI evaluations")


def import_hunt_memory(base_dir: Path):
    """Import hunt memory from JSONL file."""
    jsonl_file = base_dir / "outputs" / "hunt_memory.jsonl"
    if not jsonl_file.exists():
        print(f"  Skipping hunt_memory.jsonl (not found)")
        return

    session = get_session()
    count = 0

    with open(jsonl_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            session.add(HuntMemory(
                target=entry.get("target", ""),
                domain=entry.get("domain"),
                vuln_class=entry.get("vuln_class", "unknown"),
                tech_stack=entry.get("tech_stack", []),
                success=entry.get("success", False),
                payout=Decimal(str(entry.get("payout", 0))),
                severity=entry.get("severity", ""),
                technique_summary=entry.get("technique_summary", ""),
                chain=entry.get("chain"),
                platform=entry.get("platform", ""),
                recorded_at=_parse_iso(entry.get("timestamp")),
            ))
            count += 1

    session.commit()
    session.close()
    print(f"  Imported {count} hunt memory entries")


def import_local_findings(base_dir: Path):
    """Scan outputs/*/processed/findings/ and create engagements + findings."""
    outputs_dir = base_dir / "outputs"
    if not outputs_dir.exists():
        print(f"  Skipping local findings (outputs/ not found)")
        return

    session = get_session()
    engagement_count = 0
    finding_count = 0

    for program_dir in sorted(outputs_dir.iterdir()):
        if not program_dir.is_dir():
            continue
        dirname = program_dir.name
        if dirname in ("combined-inbox", "processed"):
            continue

        platform, handle = _detect_platform_from_dir(dirname)
        if platform == "unknown":
            continue

        program = session.query(Program).filter_by(platform=platform, platform_handle=handle).first()
        if not program:
            program = Program(
                platform=platform, platform_handle=handle, company_name=handle.replace("-", " ").title()
            )
            session.add(program)
            session.commit()

        findings_dir = program_dir / "processed" / "findings"
        if not findings_dir.exists():
            continue

        engagement = session.query(Engagement).filter_by(program_id=program.id).first()
        if not engagement:
            engagement = Engagement(program_id=program.id, status="completed")
            session.add(engagement)
            session.commit()
            engagement_count += 1

        for finding_dir in sorted(findings_dir.iterdir()):
            if not finding_dir.is_dir():
                continue

            desc_file = finding_dir / "description.md"
            if not desc_file.exists():
                continue

            content = desc_file.read_text(errors="replace")
            title_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
            title = title_match.group(1).strip() if title_match else finding_dir.name

            severity, cvss = _extract_severity_from_md(content)

            vuln_class = ""
            for vc in ["IDOR", "SSRF", "XSS", "SQLi", "CSRF", "RCE", "auth_bypass", "info_disclosure"]:
                if vc.lower() in content.lower() or vc.lower() in finding_dir.name.lower():
                    vuln_class = vc
                    break

            existing = session.query(Finding).filter_by(
                program_id=program.id, title=title
            ).first()
            if existing:
                continue

            session.add(Finding(
                engagement_id=engagement.id,
                program_id=program.id,
                title=title,
                vuln_class=vuln_class,
                severity=severity,
                cvss_vector=cvss,
                status="discovered",
                description=content[:10000],
            ))
            finding_count += 1

    session.commit()
    session.close()
    print(f"  Imported {finding_count} findings across {engagement_count} new engagements")


def import_submission_reports(base_dir: Path):
    """Import local submission report markdown files into submission_reports table."""
    outputs_dir = base_dir / "outputs"
    if not outputs_dir.exists():
        return

    session = get_session()
    count = 0

    for program_dir in sorted(outputs_dir.iterdir()):
        if not program_dir.is_dir():
            continue

        submissions_dir = program_dir / "reports" / "submissions"
        if not submissions_dir.exists():
            continue

        dirname = program_dir.name
        platform, handle = _detect_platform_from_dir(dirname)
        if platform == "unknown":
            continue

        program = session.query(Program).filter_by(platform=platform, platform_handle=handle).first()
        if not program:
            continue

        for md_file in sorted(submissions_dir.glob("*.md")):
            if md_file.name.startswith(".") or "triage" in md_file.name or "validation" in md_file.name:
                continue

            content = md_file.read_text(errors="replace")
            title_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
            title = title_match.group(1).strip() if title_match else md_file.stem

            severity, cvss = _extract_severity_from_md(content)
            slug = md_file.stem  # e.g. "H1_HIGH_001"

            existing = session.query(SubmissionReport).filter_by(
                program_id=program.id, report_slug=slug
            ).first()
            if existing:
                continue

            session.add(SubmissionReport(
                program_id=program.id,
                platform=platform,
                report_slug=slug,
                title=title,
                severity=severity,
                cvss_vector=cvss,
                markdown_body=content,
                status="submitted",
            ))
            count += 1

    session.commit()
    session.close()
    print(f"  Imported {count} submission reports")


def sync_report_statuses():
    """Cross-reference submission_reports with submissions to update report status.

    Maps platform disposition → report status:
      - resolved/accepted → accepted
      - duplicate/informative/not_applicable/wont_fix/out_of_scope → rejected
      - triaged → submitted (confirmed by platform)
      - new/needs_more_info → submitted (pending)
    """
    session = get_session()
    from sqlalchemy import select

    DISPOSITION_TO_STATUS = {
        "resolved": "accepted",
        "accepted": "accepted",
        "duplicate": "rejected",
        "informative": "rejected",
        "not_applicable": "rejected",
        "wont_fix": "rejected",
        "out_of_scope": "rejected",
        "triaged": "submitted",
        "new": "submitted",
        "needs_more_info": "submitted",
    }

    # Find all submission_reports and try to match with submissions
    reports = session.scalars(select(SubmissionReport)).all()
    updated = 0

    for report in reports:
        # Try to match by title similarity with submissions from same program
        subs = session.scalars(
            select(Submission).where(Submission.program_id == report.program_id)
        ).all()

        best_match = None
        best_score = 0

        for sub in subs:
            if not sub.title or not report.title:
                continue
            # Simple word overlap matching
            report_words = set(report.title.lower().split()[:8])
            sub_words = set(sub.title.lower().split()[:8])
            if not report_words or not sub_words:
                continue
            overlap = len(report_words & sub_words) / max(len(report_words), len(sub_words))
            if overlap > best_score and overlap > 0.3:
                best_score = overlap
                best_match = sub

        if best_match:
            new_status = DISPOSITION_TO_STATUS.get(best_match.disposition, "submitted")
            if report.status != new_status:
                report.status = new_status
                report.platform_submission_id = best_match.platform_id
                updated += 1

    session.commit()
    session.close()
    print(f"  Updated {updated} report statuses from platform data")


def deduplicate_programs():
    """Merge duplicate programs that have the same company_name + platform but different handles."""
    session = get_session()

    # Find duplicates: same (platform, company_name) with multiple handles
    from sqlalchemy import func, select
    dupes = session.execute(
        select(Program.platform, Program.company_name, func.count(Program.id).label("cnt"))
        .group_by(Program.platform, Program.company_name)
        .having(func.count(Program.id) > 1)
    ).all()

    merged = 0
    for platform, company, cnt in dupes:
        programs = session.scalars(
            select(Program)
            .where(Program.platform == platform, Program.company_name == company)
            .order_by(Program.id)
        ).all()

        # Keep the one with most submissions (or lowest ID as tiebreaker)
        keep = programs[0]
        max_subs = 0
        for p in programs:
            sub_count = session.scalar(
                select(func.count(Submission.id)).where(Submission.program_id == p.id)
            ) or 0
            if sub_count > max_subs:
                max_subs = sub_count
                keep = p

        # Merge others into keep
        for p in programs:
            if p.id == keep.id:
                continue
            # Re-parent submissions
            session.execute(
                Submission.__table__.update().where(Submission.program_id == p.id).values(program_id=keep.id)
            )
            # Re-parent findings
            session.execute(
                Finding.__table__.update().where(Finding.program_id == p.id).values(program_id=keep.id)
            )
            # Re-parent reports
            session.execute(
                SubmissionReport.__table__.update().where(SubmissionReport.program_id == p.id).values(program_id=keep.id)
            )
            # Merge notes
            if p.notes and p.notes not in (keep.notes or ""):
                keep.notes = (keep.notes or "") + "\n" + p.notes
            # Merge tech_stack
            if p.tech_stack:
                keep.tech_stack = list(set((keep.tech_stack or []) + p.tech_stack))
            # Delete the duplicate
            session.delete(p)
            merged += 1

    session.commit()
    session.close()
    print(f"  Merged {merged} duplicate programs")


def run_full_import(base_dir: Path | None = None):
    """Run all import steps."""
    if base_dir is None:
        base_dir = Path(__file__).resolve().parents[2]

    print(f"Importing from {base_dir}")
    print()

    print("[1/5] Importing submissions from report_latest.json...")
    import_report_json(base_dir)

    print("[2/5] Importing AI evaluations...")
    import_ai_evaluations(base_dir)

    print("[3/5] Importing hunt memory...")
    import_hunt_memory(base_dir)

    print("[4/5] Scanning local findings...")
    import_local_findings(base_dir)

    print("[5/5] Importing submission reports...")
    import_submission_reports(base_dir)

    print("[6/7] Deduplicating programs...")
    deduplicate_programs()

    print("[7/7] Syncing report statuses from platform data...")
    sync_report_statuses()

    print()
    print("Import complete.")


if __name__ == "__main__":
    import sys
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    run_full_import(base)
