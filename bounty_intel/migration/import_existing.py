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
    ActivityLog,
    Engagement,
    EvidenceFile,
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
            amount = Decimal(str(payout.get("amount", 0)))
            currency = payout.get("currency", "EUR")
            payout_type = payout.get("type", "Bounty")
            # Dedup: skip if same (submission_id, amount, currency, payout_type) already exists
            existing_payout = session.query(Payout).filter_by(
                submission_id=submission_id, amount=amount, currency=currency, payout_type=payout_type
            ).first()
            if existing_payout:
                continue
            session.add(Payout(
                submission_id=submission_id,
                amount=amount,
                currency=currency,
                amount_eur=Decimal(str(payout.get("amount_eur", 0))) if payout.get("amount_eur") else None,
                payout_type=payout_type,
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
            target = entry.get("target", "")
            vuln_class = entry.get("vuln_class", "unknown")
            technique = entry.get("technique_summary", "")
            # Dedup by (target, vuln_class, technique_summary)
            existing = session.query(HuntMemory).filter_by(
                target=target, vuln_class=vuln_class, technique_summary=technique
            ).first()
            if existing:
                continue
            session.add(HuntMemory(
                target=target,
                domain=entry.get("domain"),
                vuln_class=vuln_class,
                tech_stack=entry.get("tech_stack", []),
                success=entry.get("success", False),
                payout=Decimal(str(entry.get("payout", 0))),
                severity=entry.get("severity", ""),
                technique_summary=technique,
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


def _classify_recon_file(filepath: Path) -> str:
    """Classify a recon file into a category based on name patterns."""
    name = filepath.name.lower()
    if "subdomain" in name or "subdomains" in name:
        return "subdomains"
    if "endpoint" in name or "api" in name and name.endswith((".txt", ".md")):
        return "endpoints"
    if "openapi" in name or "graphql" in name or "swagger" in name:
        return "api_specs"
    if "live_host" in name or "live-host" in name:
        return "live_hosts"
    if "summary" in name:
        return "summaries"
    return "other"


def _is_binary_file(filepath: Path) -> bool:
    """Check if a file is binary by reading first 8KB."""
    try:
        chunk = filepath.read_bytes()[:8192]
        # Null bytes are a strong indicator of binary content
        if b"\x00" in chunk:
            return True
        # Check for high ratio of non-text bytes
        text_chars = set(range(32, 127)) | {9, 10, 13}  # printable + tab/newline/cr
        non_text = sum(1 for b in chunk if b not in text_chars)
        return non_text / max(len(chunk), 1) > 0.3
    except OSError:
        return True


def _read_recon_file(filepath: Path, max_bytes: int = 50_000) -> str:
    """Read a recon file, truncating if too large. Skips binary files."""
    try:
        if _is_binary_file(filepath):
            return ""
        size = filepath.stat().st_size
        if size > max_bytes:
            content = filepath.read_text(errors="replace")[:max_bytes]
            return content + f"\n... [truncated, {size} bytes total]"
        content = filepath.read_text(errors="replace")
        # Strip null bytes that PostgreSQL JSONB cannot store
        return content.replace("\x00", "")
    except (OSError, UnicodeDecodeError):
        return ""


def import_recon_data(base_dir: Path):
    """Import recon/ directory contents into engagement.recon_data JSONB."""
    outputs_dir = base_dir / "outputs"
    if not outputs_dir.exists():
        print("  Skipping recon data (outputs/ not found)")
        return

    session = get_session()
    imported = 0

    for program_dir in sorted(outputs_dir.iterdir()):
        if not program_dir.is_dir():
            continue
        dirname = program_dir.name
        if dirname in ("combined-inbox", "processed"):
            continue

        platform, handle = _detect_platform_from_dir(dirname)
        if platform == "unknown":
            continue

        # Collect recon files from multiple possible locations
        recon_dirs = []
        for candidate in ["recon", "evidence", "processed/reconnaissance"]:
            d = program_dir / candidate
            if d.is_dir():
                recon_dirs.append(d)

        if not recon_dirs:
            continue

        program = session.query(Program).filter_by(platform=platform, platform_handle=handle).first()
        if not program:
            continue

        engagement = session.query(Engagement).filter_by(program_id=program.id).first()
        if not engagement:
            engagement = Engagement(program_id=program.id, status="completed")
            session.add(engagement)
            session.commit()

        # Build structured recon data
        recon: dict[str, list] = {
            "subdomains": [], "endpoints": [], "api_specs": [],
            "live_hosts": [], "summaries": [], "other": [],
        }

        for recon_dir in recon_dirs:
            for filepath in sorted(recon_dir.rglob("*")):
                if not filepath.is_file():
                    continue
                if filepath.suffix.lower() in (
                    ".pyc", ".class", ".exe", ".bin", ".so", ".dylib",
                    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg",
                    ".mp4", ".mp3", ".wav", ".zip", ".gz", ".tar", ".rar",
                    ".pdf", ".woff", ".woff2", ".ttf", ".eot", ".xapk", ".apk",
                    ".dex", ".jar", ".dSYM",
                ):
                    continue

                category = _classify_recon_file(filepath)
                content = _read_recon_file(filepath)
                if not content.strip():
                    continue

                entry = {
                    "filename": str(filepath.relative_to(program_dir)),
                    "content": content,
                }

                # For line-based files, also provide parsed lines
                if category in ("subdomains", "live_hosts", "endpoints") and filepath.suffix in (".txt", ".csv"):
                    lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]
                    entry["lines"] = lines[:10_000]
                    entry["total_lines"] = len(lines)

                recon[category].append(entry)

        # Only update if we found something
        total_items = sum(len(v) for v in recon.values())
        if total_items > 0:
            engagement.recon_data = recon
            session.commit()
            imported += 1

    session.close()
    print(f"  Imported recon data for {imported} engagements")


def import_attack_surface(base_dir: Path):
    """Derive attack surface from scope.json + recon data into engagement.attack_surface."""
    outputs_dir = base_dir / "outputs"
    if not outputs_dir.exists():
        print("  Skipping attack surface (outputs/ not found)")
        return

    session = get_session()
    imported = 0

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
            continue

        engagement = session.query(Engagement).filter_by(program_id=program.id).first()
        if not engagement:
            continue

        surface: dict = {}

        # Read scope.json if present
        scope_file = program_dir / "scope.json"
        if scope_file.exists():
            try:
                scope = json.loads(scope_file.read_text(errors="replace"))
                surface["domains"] = scope.get("domains", [])
                surface["ips"] = scope.get("ips", [])
                surface["oos"] = scope.get("oos", [])
                surface["domain_count"] = len(surface["domains"])
            except (json.JSONDecodeError, OSError):
                pass

        # Read PROGRAM.md if present
        program_md = program_dir / "PROGRAM.md"
        if program_md.exists():
            try:
                surface["program_notes"] = program_md.read_text(errors="replace")[:10_000]
            except OSError:
                pass

        # Read SUMMARY.md if present
        summary_md = program_dir / "SUMMARY.md"
        if not summary_md.exists():
            summary_md = program_dir / "findings" / "SUMMARY.md"
        if summary_md.exists():
            try:
                surface["assessment_summary"] = summary_md.read_text(errors="replace")[:10_000]
            except OSError:
                pass

        # Derive counts from recon_data
        recon = engagement.recon_data or {}
        subdomain_count = 0
        endpoint_count = 0
        live_host_count = 0
        for entry in recon.get("subdomains", []):
            subdomain_count += entry.get("total_lines", 0) or len(entry.get("lines", []))
        for entry in recon.get("endpoints", []):
            endpoint_count += entry.get("total_lines", 0) or len(entry.get("lines", []))
        for entry in recon.get("live_hosts", []):
            live_host_count += entry.get("total_lines", 0) or len(entry.get("lines", []))

        surface["subdomain_count"] = subdomain_count
        surface["endpoint_count"] = endpoint_count
        surface["live_host_count"] = live_host_count
        surface["coverage"] = {
            "subdomains_enumerated": subdomain_count > 0,
            "endpoints_mapped": endpoint_count > 0,
            "api_specs_found": len(recon.get("api_specs", [])) > 0,
            "live_hosts_scanned": live_host_count > 0,
        }

        if surface:
            engagement.attack_surface = surface
            session.commit()
            imported += 1

    session.close()
    print(f"  Imported attack surface for {imported} engagements")


def _find_poc_file(directory: Path) -> Path | None:
    """Find a PoC file in a directory."""
    for pattern in ["poc.py", "poc.sh", "poc.c", "poc.html", "poc.js", "poc_*.py", "poc_*.c"]:
        matches = list(directory.glob(pattern))
        if matches:
            return matches[0]
    return None


def enrich_findings(base_dir: Path):
    """Enrich existing findings with PoC/workflow data and import top-level findings."""
    outputs_dir = base_dir / "outputs"
    if not outputs_dir.exists():
        print("  Skipping findings enrichment (outputs/ not found)")
        return

    session = get_session()
    enriched = 0
    new_findings = 0

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
            continue

        engagement = session.query(Engagement).filter_by(program_id=program.id).first()

        # Part 1: Enrich processed findings with PoC/workflow
        processed_dir = program_dir / "processed" / "findings"
        if processed_dir.exists():
            for finding_dir in sorted(processed_dir.iterdir()):
                if not finding_dir.is_dir():
                    continue

                desc_file = finding_dir / "description.md"
                if not desc_file.exists():
                    continue

                content = desc_file.read_text(errors="replace")
                title_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
                title = title_match.group(1).strip() if title_match else finding_dir.name

                existing = session.query(Finding).filter_by(program_id=program.id, title=title).first()
                if not existing:
                    continue

                updates = {}
                # PoC code
                if not existing.poc_code:
                    poc_file = _find_poc_file(finding_dir)
                    if poc_file:
                        updates["poc_code"] = poc_file.read_text(errors="replace")[:20_000]

                # PoC output
                if not existing.poc_output:
                    for name in ["poc_output.txt", "poc_output.json"]:
                        out_file = finding_dir / name
                        if out_file.exists():
                            updates["poc_output"] = out_file.read_text(errors="replace")[:20_000]
                            break

                # Steps to reproduce
                if not existing.steps_to_reproduce:
                    workflow = finding_dir / "workflow.md"
                    if workflow.exists():
                        updates["steps_to_reproduce"] = workflow.read_text(errors="replace")[:10_000]

                if updates:
                    for k, v in updates.items():
                        setattr(existing, k, v)
                    enriched += 1

        # Part 2: Import top-level findings (not in processed/)
        findings_dir = program_dir / "findings"
        if findings_dir.exists() and findings_dir != processed_dir:
            for finding_dir in sorted(findings_dir.iterdir()):
                if not finding_dir.is_dir():
                    continue
                if finding_dir.name.upper() == "SUMMARY.MD":
                    continue

                # Find the main report file
                report_file = None
                for candidate in ["report.md", "description.md"]:
                    f = finding_dir / candidate
                    if f.exists():
                        report_file = f
                        break

                if not report_file:
                    continue

                content = report_file.read_text(errors="replace")
                title_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
                title = title_match.group(1).strip() if title_match else finding_dir.name

                # Check for existing by title
                existing = session.query(Finding).filter_by(program_id=program.id, title=title).first()
                if existing:
                    continue

                severity, cvss = _extract_severity_from_md(content)
                vuln_class = ""
                for vc in ["IDOR", "SSRF", "XSS", "SQLi", "CSRF", "RCE", "auth_bypass", "info_disclosure",
                           "DoS", "null_deref", "command_injection", "path_traversal"]:
                    if vc.lower() in content.lower() or vc.lower() in finding_dir.name.lower():
                        vuln_class = vc
                        break

                # Ensure engagement exists
                if not engagement:
                    engagement = Engagement(program_id=program.id, status="completed")
                    session.add(engagement)
                    session.commit()

                poc_code = ""
                poc_file = _find_poc_file(finding_dir)
                if poc_file:
                    poc_code = poc_file.read_text(errors="replace")[:20_000]

                poc_output = ""
                for name in ["poc_output.txt", "poc_output.json", "crash_evidence.txt"]:
                    out_file = finding_dir / name
                    if out_file.exists():
                        poc_output = out_file.read_text(errors="replace")[:20_000]
                        break

                session.add(Finding(
                    engagement_id=engagement.id,
                    program_id=program.id,
                    title=title,
                    vuln_class=vuln_class,
                    severity=severity,
                    cvss_vector=cvss,
                    status="discovered",
                    description=content[:10_000],
                    poc_code=poc_code,
                    poc_output=poc_output,
                ))
                new_findings += 1

    session.commit()
    session.close()
    print(f"  Enriched {enriched} findings, imported {new_findings} new top-level findings")


def import_activity_logs(base_dir: Path):
    """Import JSONL activity logs from processed/activity/ directories."""
    outputs_dir = base_dir / "outputs"
    if not outputs_dir.exists():
        print("  Skipping activity logs (outputs/ not found)")
        return

    session = get_session()
    imported = 0

    for program_dir in sorted(outputs_dir.iterdir()):
        if not program_dir.is_dir():
            continue
        dirname = program_dir.name
        if dirname in ("combined-inbox", "processed"):
            continue

        activity_dir = program_dir / "processed" / "activity"
        if not activity_dir.exists():
            continue

        platform, handle = _detect_platform_from_dir(dirname)
        if platform == "unknown":
            continue

        program = session.query(Program).filter_by(platform=platform, platform_handle=handle).first()
        if not program:
            continue

        engagement = session.query(Engagement).filter_by(program_id=program.id).first()
        if not engagement:
            continue

        for log_file in sorted(activity_dir.glob("*.log")):
            try:
                lines = log_file.read_text(errors="replace").splitlines()
            except OSError:
                continue

            batch = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                ts = _parse_iso(entry.get("ts")) or _parse_iso(entry.get("timestamp"))
                action = entry.get("action", "unknown")

                # Dedup check
                existing = session.query(ActivityLog).filter_by(
                    engagement_id=engagement.id, action=action, created_at=ts
                ).first()
                if existing:
                    continue

                batch.append(ActivityLog(
                    engagement_id=engagement.id,
                    action=action,
                    details=entry,
                    created_at=ts,
                ))

            if batch:
                session.add_all(batch)
                session.commit()
                imported += len(batch)

    session.close()
    print(f"  Imported {imported} activity log entries")


def _guess_content_type(filepath: Path) -> str:
    """Guess content type from file extension."""
    import mimetypes
    ct, _ = mimetypes.guess_type(str(filepath))
    if ct:
        return ct
    ext_map = {
        ".txt": "text/plain", ".md": "text/markdown", ".json": "application/json",
        ".html": "text/html", ".py": "text/x-python", ".c": "text/x-c",
        ".sh": "text/x-shellscript", ".log": "text/plain", ".csv": "text/csv",
        ".xml": "application/xml", ".yaml": "application/yaml", ".yml": "application/yaml",
        ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".gif": "image/gif", ".webp": "image/webp", ".mp4": "video/mp4",
    }
    return ext_map.get(filepath.suffix.lower(), "application/octet-stream")


def import_evidence_metadata(base_dir: Path):
    """Catalog local evidence files into evidence_files table (no GCS upload)."""
    outputs_dir = base_dir / "outputs"
    if not outputs_dir.exists():
        print("  Skipping evidence metadata (outputs/ not found)")
        return

    session = get_session()
    imported = 0

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
            continue

        # Collect all evidence directories
        evidence_paths: list[tuple[Path, int | None]] = []  # (dir, finding_id or None)

        # Top-level evidence/
        top_evidence = program_dir / "evidence"
        if top_evidence.is_dir():
            evidence_paths.append((top_evidence, None))

        # Per-finding evidence in processed/findings/*/evidence/
        for finding_parent in [program_dir / "processed" / "findings", program_dir / "findings"]:
            if not finding_parent.is_dir():
                continue
            for finding_dir in sorted(finding_parent.iterdir()):
                if not finding_dir.is_dir():
                    continue
                ev_dir = finding_dir / "evidence"
                if not ev_dir.is_dir():
                    continue

                # Try to match finding by title from description/report
                finding_id = None
                for desc_name in ["description.md", "report.md"]:
                    desc_file = finding_dir / desc_name
                    if desc_file.exists():
                        content = desc_file.read_text(errors="replace")
                        title_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
                        if title_match:
                            title = title_match.group(1).strip()
                            finding = session.query(Finding).filter_by(
                                program_id=program.id, title=title
                            ).first()
                            if finding:
                                finding_id = finding.id
                        break

                evidence_paths.append((ev_dir, finding_id))

        # Also evidence in reports/submissions/evidence/
        sub_evidence = program_dir / "reports" / "submissions" / "evidence"
        if sub_evidence.is_dir():
            evidence_paths.append((sub_evidence, None))

        # Process all evidence directories
        for ev_dir, finding_id in evidence_paths:
            for filepath in sorted(ev_dir.rglob("*")):
                if not filepath.is_file():
                    continue
                # Skip very small or binary-only files
                if filepath.stat().st_size == 0:
                    continue

                abs_path = str(filepath.resolve())

                # Dedup by local_path
                existing = session.query(EvidenceFile).filter_by(local_path=abs_path).first()
                if existing:
                    continue

                session.add(EvidenceFile(
                    finding_id=finding_id,
                    local_path=abs_path,
                    gcs_path="",
                    filename=filepath.name,
                    content_type=_guess_content_type(filepath),
                    size_bytes=filepath.stat().st_size,
                ))
                imported += 1

                if imported % 500 == 0:
                    session.flush()

    session.commit()
    session.close()
    print(f"  Cataloged {imported} evidence files")


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
                status="draft",
            ))
            count += 1

    session.commit()
    session.close()
    print(f"  Imported {count} submission reports")


def sync_report_statuses():
    """Cross-reference submission_reports with submissions to update status and link bidirectionally.

    Matches by title similarity across programs with the same company name (handles
    duplicate program entries from import vs sync).  Links both directions:
      - report.platform_submission_id ← submission.platform_id
      - submission.report_id ← report.id

    Maps platform disposition → report status:
      - resolved/accepted → accepted
      - duplicate/informative/not_applicable/wont_fix/out_of_scope → rejected
      - triaged → submitted (confirmed by platform)
      - new/needs_more_info → submitted (pending)
    """
    from difflib import SequenceMatcher

    from sqlalchemy import select
    from sqlalchemy.orm import joinedload

    session = get_session()

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

    # Load all programs, reports, and submissions
    programs = {p.id: p for p in session.scalars(select(Program)).all()}
    reports = session.scalars(
        select(SubmissionReport).options(joinedload(SubmissionReport.submission))
    ).unique().all()
    all_subs = session.scalars(
        select(Submission).options(joinedload(Submission.program))
    ).unique().all()

    # Build company-name lookup: normalize company → [program_ids]
    company_to_pids: dict[str, set[int]] = {}
    for p in programs.values():
        key = p.company_name.lower().strip()
        company_to_pids.setdefault(key, set()).add(p.id)

    # For each program, find all sibling program_ids (same company, any handle)
    pid_siblings: dict[int, set[int]] = {}
    for p in programs.values():
        key = p.company_name.lower().strip()
        pid_siblings[p.id] = company_to_pids.get(key, {p.id})

    # Index submissions by program_id for fast lookup
    subs_by_pid: dict[int, list] = {}
    for sub in all_subs:
        subs_by_pid.setdefault(sub.program_id, []).append(sub)

    updated = 0
    linked = 0
    used_sub_ids: set[int] = set()

    # Sort reports by ID for deterministic matching
    for report in sorted(reports, key=lambda r: r.id):
        # Already linked?
        if report.submission is not None:
            used_sub_ids.add(report.submission.id)
            continue

        # Collect candidate submissions from same company (across program duplicates)
        r_prog = programs.get(report.program_id)
        if not r_prog:
            continue
        sibling_pids = pid_siblings.get(report.program_id, {report.program_id})

        candidates = []
        for pid in sibling_pids:
            candidates.extend(subs_by_pid.get(pid, []))

        # Also try fuzzy company match for H1 programs (company names differ)
        if report.platform == "hackerone" and r_prog:
            r_company = r_prog.company_name.lower().strip()
            for cname, pids in company_to_pids.items():
                if cname != r_company and SequenceMatcher(None, r_company, cname).ratio() > 0.5:
                    for pid in pids:
                        candidates.extend(subs_by_pid.get(pid, []))

        best_match = None
        best_score = 0.0

        for sub in candidates:
            if sub.id in used_sub_ids:
                continue
            if sub.platform != report.platform:
                continue
            if not sub.title or not report.title:
                continue
            score = SequenceMatcher(None, report.title.lower(), sub.title.lower()).ratio()
            if score > best_score and score > 0.55:
                best_score = score
                best_match = sub

        if best_match:
            # Bidirectional link
            report.platform_submission_id = best_match.platform_id
            best_match.report_id = report.id
            used_sub_ids.add(best_match.id)
            linked += 1

            # Update report status from disposition
            new_status = DISPOSITION_TO_STATUS.get(best_match.disposition, "submitted")
            if report.status != new_status:
                report.status = new_status
                updated += 1

    session.commit()
    session.close()
    print(f"  Linked {linked} reports ↔ submissions, updated {updated} report statuses")


def _normalize_company(name: str) -> str:
    """Normalize company name for dedup: lowercase, strip common suffixes and noise."""
    import re
    n = name.lower().strip()
    # Remove common suffixes that differ between import and sync
    for suffix in ("bugbounty", "bug bounty", "_bbp", " bbp", " o2"):
        n = n.replace(suffix, "")
    n = re.sub(r"[^a-z0-9]", "", n)  # keep only alphanumeric
    return n


def deduplicate_programs():
    """Merge duplicate programs with same normalized company_name + platform."""
    session = get_session()

    from sqlalchemy import func, select

    # Load all programs and group by (platform, normalized_company)
    all_programs = session.scalars(select(Program)).all()
    groups: dict[tuple[str, str], list] = {}
    for p in all_programs:
        key = (p.platform, _normalize_company(p.company_name))
        groups.setdefault(key, []).append(p)

    # Pre-compute submission counts (before any mutations)
    sub_counts: dict[int, int] = {}
    for p in all_programs:
        sub_counts[p.id] = session.scalar(
            select(func.count(Submission.id)).where(Submission.program_id == p.id)
        ) or 0

    merged = 0
    for (platform, norm_name), programs in groups.items():
        if len(programs) < 2:
            continue
        programs.sort(key=lambda p: p.id)

        # Keep the one with most submissions (or lowest ID as tiebreaker)
        keep = max(programs, key=lambda p: (sub_counts.get(p.id, 0), -p.id))

        # Merge others into keep
        with session.no_autoflush:
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
                # Re-parent engagements
                from bounty_intel.db import Engagement
                session.execute(
                    Engagement.__table__.update().where(Engagement.program_id == p.id).values(program_id=keep.id)
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

    print("[1/12] Importing submissions from report_latest.json...")
    import_report_json(base_dir)

    print("[2/12] Importing AI evaluations...")
    import_ai_evaluations(base_dir)

    print("[3/12] Importing hunt memory...")
    import_hunt_memory(base_dir)

    print("[4/12] Scanning local findings (processed/)...")
    import_local_findings(base_dir)

    print("[5/12] Enriching findings + importing top-level findings...")
    enrich_findings(base_dir)

    print("[6/12] Importing recon data...")
    import_recon_data(base_dir)

    print("[7/12] Deriving attack surface...")
    import_attack_surface(base_dir)

    print("[8/12] Importing activity logs...")
    import_activity_logs(base_dir)

    print("[9/12] Cataloging evidence files...")
    import_evidence_metadata(base_dir)

    print("[10/12] Importing submission reports...")
    import_submission_reports(base_dir)

    print("[11/12] Deduplicating programs...")
    deduplicate_programs()

    print("[12/12] Syncing report statuses from platform data...")
    sync_report_statuses()

    print()
    print("Import complete.")


if __name__ == "__main__":
    import sys
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    run_full_import(base)
