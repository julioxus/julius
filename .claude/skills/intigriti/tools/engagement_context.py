#!/usr/bin/env python3
"""
Engagement Context Gatherer

Scans local outputs, memory files, and submission data to produce a structured
context summary for AI triager evaluation and program recommendations.

Usage:
  python3 engagement_context.py --output outputs/intigriti-inbox/engagement_context.json
"""

import argparse
import glob
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

OUTPUTS_DIR = "outputs"
MEMORY_DIR = os.path.expanduser("~/.claude/projects/-Users-jmartinez-repos-julius/memory")


def scan_engagement_dir(engagement_path):
    """Extract key metrics from an engagement directory."""
    name = os.path.basename(engagement_path)
    if name.startswith("hackerone-"):
        program_handle = name.replace("hackerone-", "")
        platform = "hackerone"
    else:
        program_handle = name.replace("intigriti-", "")
        platform = "intigriti"

    findings_dir = os.path.join(engagement_path, "findings")
    submissions_dir = os.path.join(engagement_path, "reports", "submissions")
    activity_dir = os.path.join(engagement_path, "processed", "activity")

    findings = glob.glob(os.path.join(findings_dir, "**", "*.md"), recursive=True) if os.path.isdir(findings_dir) else []
    submissions = [f for f in glob.glob(os.path.join(submissions_dir, "*.md")) if "triage" not in os.path.basename(f).lower()] if os.path.isdir(submissions_dir) else []

    # Extract finding titles and severities from filenames/content
    finding_summaries = []
    for f in findings[:15]:  # limit to avoid reading too many
        fname = os.path.basename(f)
        try:
            content = Path(f).read_text(errors="replace")[:500]
            title_match = re.search(r'^#\s+(.+)', content, re.MULTILINE)
            sev_match = re.search(r'severity[:\s]*(critical|high|medium|low|informational)', content, re.IGNORECASE)
            finding_summaries.append({
                "file": fname,
                "title": title_match.group(1).strip() if title_match else fname,
                "severity": sev_match.group(1).capitalize() if sev_match else "Unknown",
            })
        except Exception:
            finding_summaries.append({"file": fname, "title": fname, "severity": "Unknown"})

    # Count file types for effort estimation
    all_files = glob.glob(os.path.join(engagement_path, "**", "*"), recursive=True)
    py_scripts = [f for f in all_files if f.endswith(".py")]
    screenshots = [f for f in all_files if any(f.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif"))]

    return {
        "handle": program_handle,
        "platform": platform,
        "dir": engagement_path,
        "total_files": len(all_files),
        "findings_count": len(findings),
        "submissions_count": len(submissions),
        "poc_scripts": len(py_scripts),
        "screenshots": len(screenshots),
        "finding_summaries": finding_summaries,
    }


def scan_memory_files():
    """Read all memory files for engagement context."""
    memories = []
    memory_dir = Path(MEMORY_DIR)
    if not memory_dir.exists():
        return memories

    for f in memory_dir.glob("*.md"):
        if f.name == "MEMORY.md":
            continue
        try:
            content = f.read_text(errors="replace")
            # Extract frontmatter
            name_match = re.search(r'^name:\s*(.+)', content, re.MULTILINE)
            type_match = re.search(r'^type:\s*(.+)', content, re.MULTILINE)
            # Get body (after frontmatter)
            body = re.split(r'^---\s*$', content, maxsplit=2, flags=re.MULTILINE)
            body_text = body[-1].strip() if len(body) > 2 else content

            memories.append({
                "file": f.name,
                "name": name_match.group(1).strip() if name_match else f.stem,
                "type": type_match.group(1).strip() if type_match else "unknown",
                "content": body_text,
            })
        except Exception:
            pass

    return memories


def build_program_stats(engagements, submissions_data):
    """Cross-reference engagements with submission outcomes."""
    stats = {}

    # Index submissions by company/program handle
    for sub in submissions_data:
        company = sub.get("company", "Unknown")
        if company not in stats:
            stats[company] = {
                "submissions": [],
                "paid_count": 0,
                "rejected_count": 0,
                "pending_count": 0,
                "total_earned_original": [],
                "rejection_reasons": [],
            }

        stats[company]["submissions"].append({
            "id": sub["id"],
            "title": sub["title"],
            "severity": sub["severity"],
            "disposition": sub["disposition"],
            "listed_bounty": sub["listed_bounty"],
            "listed_currency": sub["listed_currency"],
            "total_paid": sub.get("total_paid", 0),
        })

        if sub.get("total_paid", 0) > 0:
            stats[company]["paid_count"] += 1
            stats[company]["total_earned_original"].append({
                "amount": sub["total_paid"],
                "currency": sub.get("total_paid_currency", sub["listed_currency"]),
            })
        elif sub["disposition"] in ("new", "triaged", "accepted"):
            stats[company]["pending_count"] += 1
        else:
            stats[company]["rejected_count"] += 1
            stats[company]["rejection_reasons"].append(sub["disposition"])

    # Merge with engagement data (findings not submitted)
    for eng in engagements:
        handle = eng["handle"]
        # Try to match engagement to company
        matched = False
        for company in stats:
            if handle.lower() in company.lower() or company.lower() in handle.lower():
                stats[company]["local_findings"] = eng["findings_count"]
                stats[company]["local_submissions"] = eng["submissions_count"]
                stats[company]["total_files"] = eng["total_files"]
                stats[company]["finding_summaries"] = eng["finding_summaries"]
                matched = True
                break
        if not matched:
            # Engagement exists but no submissions yet
            stats[handle] = {
                "submissions": [],
                "paid_count": 0,
                "rejected_count": 0,
                "pending_count": 0,
                "total_earned_original": [],
                "rejection_reasons": [],
                "local_findings": eng["findings_count"],
                "local_submissions": eng["submissions_count"],
                "total_files": eng["total_files"],
                "finding_summaries": eng["finding_summaries"],
                "no_submissions_yet": True,
            }

    return stats


def main():
    parser = argparse.ArgumentParser(description="Gather engagement context for AI analysis")
    parser.add_argument("--submissions", default="outputs/intigriti-inbox/submissions_latest.json",
                        help="Path to submissions data")
    parser.add_argument("--output", default="outputs/intigriti-inbox/engagement_context.json")
    args = parser.parse_args()

    # 1. Scan engagement directories
    print("[*] Scanning engagement directories...")
    engagements = []
    all_dirs = (glob.glob(os.path.join(OUTPUTS_DIR, "intigriti-*/")) +
                glob.glob(os.path.join(OUTPUTS_DIR, "hackerone-*/")))
    for d in sorted(all_dirs):
        if "inbox" in d:
            continue
        eng = scan_engagement_dir(d)
        engagements.append(eng)
        print(f"  {eng['handle']}: {eng['findings_count']} findings, {eng['submissions_count']} submissions")

    # 2. Read memory files
    print("[*] Reading memory files...")
    memories = scan_memory_files()
    print(f"  Found {len(memories)} memory entries")

    # 3. Load submissions data
    print("[*] Loading submissions data...")
    subs_path = Path(args.submissions)
    submissions = []
    if subs_path.exists():
        submissions = json.loads(subs_path.read_text())
        print(f"  {len(submissions)} submissions loaded")
    else:
        print(f"  [!] {subs_path} not found — run inbox_exporter first")

    # 4. Build program stats
    print("[*] Building program statistics...")
    program_stats = build_program_stats(engagements, submissions)

    # 5. Compute researcher profile
    total_submitted = sum(s["paid_count"] + s["rejected_count"] + s["pending_count"] for s in program_stats.values())
    total_paid = sum(s["paid_count"] for s in program_stats.values())
    total_rejected = sum(s["rejected_count"] for s in program_stats.values())
    total_pending = sum(s["pending_count"] for s in program_stats.values())
    total_findings_local = sum(e["findings_count"] for e in engagements)
    all_rejection_reasons = []
    for s in program_stats.values():
        all_rejection_reasons.extend(s["rejection_reasons"])

    # Programs with work but no submissions
    explored_not_submitted = [
        handle for handle, s in program_stats.items()
        if s.get("no_submissions_yet") and s.get("local_findings", 0) > 0
    ]

    context = {
        "generated_at": datetime.now().isoformat(),
        "researcher_profile": {
            "total_programs_explored": len(engagements),
            "total_programs_submitted": len([s for s in program_stats.values() if s["submissions"]]),
            "total_findings_local": total_findings_local,
            "total_submitted": total_submitted,
            "total_paid": total_paid,
            "total_rejected": total_rejected,
            "total_pending": total_pending,
            "acceptance_rate": round(total_paid / max(total_paid + total_rejected, 1), 2),
            "submission_rate": round(total_submitted / max(total_findings_local, 1), 2),
            "rejection_breakdown": {r: all_rejection_reasons.count(r) for r in set(all_rejection_reasons)},
        },
        "program_stats": program_stats,
        "explored_not_submitted": explored_not_submitted,
        "memories": memories,
        "engagements_summary": [
            {"handle": e["handle"], "platform": e.get("platform", "intigriti"),
             "findings": e["findings_count"],
             "submissions": e["submissions_count"], "files": e["total_files"]}
            for e in engagements
        ],
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(context, indent=2))
    print(f"\n[+] Context saved to {out}")

    # Print summary
    print(f"\n{'='*60}")
    print(f"RESEARCHER CONTEXT SUMMARY")
    print(f"{'='*60}")
    p = context["researcher_profile"]
    print(f"Programs explored: {p['total_programs_explored']}")
    print(f"Programs submitted: {p['total_programs_submitted']}")
    print(f"Local findings: {p['total_findings_local']}")
    print(f"Submitted: {p['total_submitted']} (paid: {p['total_paid']}, rejected: {p['total_rejected']}, pending: {p['total_pending']})")
    print(f"Acceptance rate: {p['acceptance_rate']:.0%}")
    print(f"Submission rate: {p['submission_rate']:.0%} (of local findings)")
    print(f"Rejection breakdown: {p['rejection_breakdown']}")
    if explored_not_submitted:
        print(f"\nPrograms with findings but NO submissions yet:")
        for h in explored_not_submitted:
            s = program_stats[h]
            print(f"  {h}: {s['local_findings']} findings, {s['total_files']} files")


if __name__ == "__main__":
    main()
