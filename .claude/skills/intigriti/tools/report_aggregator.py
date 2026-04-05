#!/usr/bin/env python3
"""
Report Aggregator — fetches HackerOne reports via API, merges with Intigriti inbox export.

Reads existing Intigriti report_latest.json, fetches HackerOne submissions via API,
normalizes both to a common schema, and outputs a combined report.

Auth: HACKERONE_USERNAME + HACKERONE_API_TOKEN from .env (HTTP Basic Auth)

Usage:
  python3 report_aggregator.py \
    --intigriti outputs/intigriti-inbox/report_latest.json \
    --output outputs/combined-inbox/report_latest.json
"""

import argparse
import base64
import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

H1_API_BASE = "https://api.hackerone.com/v1"

# Estimated bounty by severity when H1 report has no bounty yet
H1_ESTIMATED_BOUNTY = {
    "Critical": 3000,
    "High": 1500,
    "Medium": 500,
    "Low": 150,
    "None": 0,
}

H1_STATE_TO_DISPOSITION = {
    "new": "new",
    "triaged": "triaged",
    "needs-more-info": "new",
    "resolved": "resolved",
    "informative": "informative",
    "duplicate": "duplicate",
    "spam": "not_applicable",
    "not-applicable": "not_applicable",
}

H1_PENDING_STATES = {"new", "triaged", "needs-more-info"}
H1_PAID_STATES = {"resolved"}
H1_REJECTED_STATES = {"informative", "duplicate", "spam", "not-applicable"}


def load_env():
    """Load .env file from repo root."""
    env_path = Path(__file__).resolve().parents[4] / ".env"
    if not env_path.exists():
        # Try CWD
        env_path = Path.cwd() / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                os.environ.setdefault(key.strip(), val.strip())


def h1_auth_header():
    """Build HTTP Basic Auth header from env vars."""
    username = os.environ.get("HACKERONE_USERNAME", "")
    token = os.environ.get("HACKERONE_API_TOKEN", "")
    if not username or not token:
        return None
    creds = base64.b64encode(f"{username}:{token}".encode()).decode()
    return f"Basic {creds}"


def h1_fetch(url, auth):
    """Fetch JSON from HackerOne API."""
    req = urllib.request.Request(url)
    req.add_header("Authorization", auth)
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "BountyForecaster/1.0")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_h1_reports(auth):
    """Fetch all researcher reports from HackerOne API with pagination."""
    reports = []
    url = f"{H1_API_BASE}/hackers/me/reports?page%5Bsize%5D=100"
    page = 1
    while url:
        print(f"  [*] Fetching H1 reports page {page}...")
        try:
            data = h1_fetch(url, auth)
        except urllib.error.HTTPError as e:
            print(f"  [!] H1 API error: HTTP {e.code}", file=sys.stderr)
            if e.code == 401:
                print("  [!] Check HACKERONE_USERNAME and HACKERONE_API_TOKEN in .env", file=sys.stderr)
            break
        except urllib.error.URLError as e:
            print(f"  [!] H1 API connection error: {e.reason}", file=sys.stderr)
            break

        for item in data.get("data", []):
            reports.append(item)

        next_url = data.get("links", {}).get("next")
        url = next_url if next_url else None
        page += 1

    print(f"  [+] Fetched {len(reports)} H1 reports")
    return reports


def normalize_h1_severity(report):
    """Extract severity from H1 report."""
    attrs = report.get("attributes", {})
    # severity_rating is directly on attributes
    rating = attrs.get("severity_rating", "")
    if rating:
        return rating.capitalize()
    # Fallback: check relationships.severity
    sev_data = report.get("relationships", {}).get("severity", {}).get("data", {})
    if sev_data:
        rating = sev_data.get("attributes", {}).get("rating", "")
        if rating:
            return rating.capitalize()
    return "Medium"


def extract_h1_bounties(report):
    """Extract bounty/payout info from H1 report."""
    bounties_rel = report.get("relationships", {}).get("bounties", {}).get("data", [])
    payouts = []
    total_paid = 0
    total_currency = "USD"

    for b in bounties_rel:
        b_attrs = b.get("attributes", {})
        amount = float(b_attrs.get("amount", 0) or 0)
        bonus = float(b_attrs.get("bonus_amount", 0) or 0)
        created = b_attrs.get("created_at", "")

        if amount > 0:
            payouts.append({
                "amount": amount,
                "currency": "USD",
                "status": "Paid",
                "type": "Bounty",
                "paid_date": created[:10] if created else None,
            })
            total_paid += amount

        if bonus > 0:
            payouts.append({
                "amount": bonus,
                "currency": "USD",
                "status": "Paid",
                "type": "Bonus",
                "paid_date": created[:10] if created else None,
            })
            total_paid += bonus

    return payouts, total_paid, total_currency


def extract_h1_program_info(report):
    """Extract program/team info from H1 report."""
    team_rel = report.get("relationships", {}).get("program", {}).get("data", {})
    if not team_rel:
        team_rel = report.get("relationships", {}).get("team", {}).get("data", {})
    team_attrs = team_rel.get("attributes", {}) if team_rel else {}
    handle = team_attrs.get("handle", "unknown")
    name = team_attrs.get("name", handle)
    return handle, name


def normalize_h1_report(report):
    """Convert a single H1 API report to the normalized schema."""
    attrs = report.get("attributes", {})
    state = attrs.get("state", "new")
    severity = normalize_h1_severity(report)
    payouts, total_paid, total_currency = extract_h1_bounties(report)
    handle, company = extract_h1_program_info(report)

    disposition = H1_STATE_TO_DISPOSITION.get(state, "unknown")

    # Listed bounty: use actual payout if paid, otherwise estimate
    if total_paid > 0:
        listed_bounty = total_paid
    else:
        listed_bounty = H1_ESTIMATED_BOUNTY.get(severity, 500)

    return {
        "id": report.get("id", ""),
        "program": company,
        "company": company,
        "title": attrs.get("title", ""),
        "severity": severity,
        "severity_raw": None,
        "cvss_vector": attrs.get("severity", {}).get("cvss_vector_string") if isinstance(attrs.get("severity"), dict) else None,
        "status": state.replace("-", " ").title(),
        "disposition": disposition,
        "close_reason": disposition.replace("_", " ").title() if state in H1_REJECTED_STATES else "N/A",
        "listed_bounty": listed_bounty,
        "listed_currency": "USD",
        "has_bonus": any(p["type"] == "Bonus" for p in payouts),
        "paid": total_paid > 0,
        "payouts": payouts,
        "total_paid": total_paid,
        "total_paid_currency": total_currency if total_paid > 0 else None,
        "awaiting_feedback": state == "needs-more-info",
        "program_handle": handle,
        "created_at": attrs.get("created_at", ""),
        "last_updated": attrs.get("last_activity_at") or attrs.get("updated_at"),
        "platform": "hackerone",
    }


def classify_h1_submissions(normalized_reports):
    """Split H1 reports into paid, pending, rejected."""
    paid = []
    pending = []
    rejected = []

    for r in normalized_reports:
        state = r["status"].lower().replace(" ", "-")
        if r["total_paid"] > 0:
            paid.append(r)
        elif state in {"new", "triaged", "needs-more-info"}:
            pending.append(r)
        else:
            rejected.append(r)

    return paid, pending, rejected


def tag_platform(submissions, platform):
    """Add platform tag to submissions that don't have one."""
    for s in submissions:
        if "platform" not in s:
            s["platform"] = platform


def merge_reports(intigriti_report, h1_paid, h1_pending, h1_rejected):
    """Merge Intigriti report with H1 classified submissions."""
    # Tag Intigriti submissions
    for key in ("paid_submissions", "pending_submissions", "rejected_submissions"):
        tag_platform(intigriti_report.get(key, []), "intigriti")

    # Merge arrays
    all_paid = intigriti_report.get("paid_submissions", []) + h1_paid
    all_pending = intigriti_report.get("pending_submissions", []) + h1_pending
    all_rejected = intigriti_report.get("rejected_submissions", []) + h1_rejected

    # Sort
    all_paid.sort(key=lambda x: x.get("total_paid", 0), reverse=True)
    all_pending.sort(key=lambda x: x.get("listed_bounty", 0), reverse=True)
    all_rejected.sort(key=lambda x: x.get("listed_bounty", 0), reverse=True)

    # Recompute earnings
    paid_by_currency = {}
    for s in all_paid:
        cur = s.get("total_paid_currency") or "?"
        paid_by_currency.setdefault(cur, 0)
        paid_by_currency[cur] += s.get("total_paid", 0)

    pending_by_currency = {}
    for s in all_pending:
        cur = s.get("listed_currency", "EUR")
        pending_by_currency.setdefault(cur, 0)
        pending_by_currency[cur] += s.get("listed_bounty", 0)

    return {
        "generated_at": datetime.now().isoformat(),
        "total_submissions": len(all_paid) + len(all_pending) + len(all_rejected),
        "platforms": ["intigriti", "hackerone"],
        "breakdown": {
            "paid": len(all_paid),
            "pending": len(all_pending),
            "rejected": len(all_rejected),
        },
        "earnings": {
            "paid": paid_by_currency,
            "pending_potential": pending_by_currency,
        },
        "paid_submissions": all_paid,
        "pending_submissions": all_pending,
        "rejected_submissions": all_rejected,
    }


def print_summary(report, h1_count):
    """Print combined report summary."""
    print(f"\n{'='*60}")
    print(f"COMBINED BOUNTY INBOX — {report['generated_at'][:10]}")
    print(f"{'='*60}")
    print(f"Total submissions: {report['total_submissions']} (Intigriti + {h1_count} HackerOne)")
    print(f"  Paid:     {report['breakdown']['paid']}")
    print(f"  Pending:  {report['breakdown']['pending']}")
    print(f"  Rejected: {report['breakdown']['rejected']}")

    print(f"\nEARNINGS (confirmed paid):")
    for cur, amt in report["earnings"]["paid"].items():
        print(f"  {cur} {amt:,.2f}")

    print(f"\nPENDING POTENTIAL:")
    for cur, amt in report["earnings"]["pending_potential"].items():
        print(f"  {cur} {amt:,.2f}")

    # Platform breakdown
    inti_count = sum(1 for s in report["paid_submissions"] + report["pending_submissions"] + report["rejected_submissions"]
                     if s.get("platform") == "intigriti")
    h1_total = sum(1 for s in report["paid_submissions"] + report["pending_submissions"] + report["rejected_submissions"]
                   if s.get("platform") == "hackerone")
    print(f"\nBy platform: Intigriti={inti_count}, HackerOne={h1_total}")


def main():
    parser = argparse.ArgumentParser(description="Aggregate Intigriti + HackerOne bounty reports")
    parser.add_argument("--intigriti", default="outputs/intigriti-inbox/report_latest.json",
                        help="Path to Intigriti report_latest.json")
    parser.add_argument("--output", default="outputs/combined-inbox/report_latest.json",
                        help="Output path for combined report")
    parser.add_argument("--skip-h1", action="store_true",
                        help="Skip HackerOne API fetch (use existing data only)")
    args = parser.parse_args()

    load_env()

    # 1. Load Intigriti report
    inti_path = Path(args.intigriti)
    if inti_path.exists():
        print(f"[*] Loading Intigriti report from {inti_path}...")
        intigriti_report = json.loads(inti_path.read_text())
        inti_total = intigriti_report.get("total_submissions", 0)
        print(f"[+] Intigriti: {inti_total} submissions")
    else:
        print(f"[!] Intigriti report not found at {inti_path} — continuing with H1 only")
        intigriti_report = {
            "paid_submissions": [], "pending_submissions": [],
            "rejected_submissions": [], "breakdown": {"paid": 0, "pending": 0, "rejected": 0},
            "earnings": {"paid": {}, "pending_potential": {}},
        }

    # 2. Fetch HackerOne reports
    h1_paid, h1_pending, h1_rejected = [], [], []
    h1_count = 0

    if not args.skip_h1:
        auth = h1_auth_header()
        if not auth:
            print("[!] HACKERONE_USERNAME or HACKERONE_API_TOKEN not set in .env — skipping H1")
        else:
            print("[*] Fetching HackerOne reports via API...")
            raw_reports = fetch_h1_reports(auth)
            h1_count = len(raw_reports)

            if raw_reports:
                normalized = [normalize_h1_report(r) for r in raw_reports]
                h1_paid, h1_pending, h1_rejected = classify_h1_submissions(normalized)
                print(f"[+] H1: {len(h1_paid)} paid, {len(h1_pending)} pending, {len(h1_rejected)} rejected")

    # 3. Merge
    print("[*] Merging reports...")
    combined = merge_reports(intigriti_report, h1_paid, h1_pending, h1_rejected)

    # 4. Save
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(combined, indent=2))
    print(f"[+] Combined report saved to {out_path}")

    # Also save timestamped copy
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ts_path = out_path.parent / f"report_{ts}.json"
    ts_path.write_text(json.dumps(combined, indent=2))

    # Symlink latest
    latest = out_path.parent / "report_latest.json"
    if latest.is_symlink() or latest.exists():
        latest.unlink()
    latest.symlink_to(ts_path.name)

    print_summary(combined, h1_count)


if __name__ == "__main__":
    main()
