#!/usr/bin/env python3
"""
Intigriti Inbox Exporter
Extracts all submissions from authenticated Intigriti session via BFF API.

Authentication (in order of priority):
  1. --cookie "VALUE"           explicit cookie value
  2. --cookie-file /path        file containing cookie
  3. Cached session             ~/.intigriti/session_cookie.txt
  4. Playwright browser login   opens browser for login + MFA

Output: JSON file with all submissions + payout details at outputs/intigriti-inbox/
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

BASE_URL = "https://app.intigriti.com"
SUBMISSIONS_EP = "/api/core/researcher/submissions"
SUBMISSION_DETAIL_EP = "/api/core/researcher/submissions/{submission_id}"

CLOSE_REASONS = {
    1: "Resolved",
    2: "Duplicate",
    3: "Not Applicable",
    4: "Informative",
    5: "Out of Scope",
    6: "Won't Fix",
    7: "Not Applicable",
}

STATUS_MAP = {
    1: "New",
    2: "Triaged",
    3: "Accepted",
    4: "Closed",
    5: "Archived",
}

SEVERITY_MAP = {
    1: "None",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    6: "Critical",
    7: "Exceptional",
}

PAYOUT_STATUS = {
    1: "Pending",
    2: "Processing",
    3: "Paid",
    4: "Failed",
    5: "Completed",
}

PAYOUT_TYPE = {
    1: "Bounty",
    2: "Tip",
    3: "Bonus",
    4: "Swag",
    5: "Kudos",
    6: "Retest",
    7: "Additional",
}


def fetch_json(url, cookie):
    req = urllib.request.Request(url)
    req.add_header("Cookie", f"__Host-Intigriti.Web.Researcher={cookie}")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "Mozilla/5.0 IntiExporter/1.0")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"  HTTP {e.code} for {url}", file=sys.stderr)
        return None


def fetch_submissions(cookie):
    url = f"{BASE_URL}{SUBMISSIONS_EP}?offset=0&limit=100"
    print(f"[*] Fetching submissions list...")
    data = fetch_json(url, cookie)
    if data is None:
        print("[!] Failed to fetch submissions. Check cookie.", file=sys.stderr)
        sys.exit(1)
    print(f"[+] Found {len(data)} submissions")
    return data


def fetch_submission_detail(cookie, submission_id):
    url = f"{BASE_URL}{SUBMISSION_DETAIL_EP.format(submission_id=submission_id)}"
    return fetch_json(url, cookie)


def classify_submission(sub):
    status = sub.get("state", {}).get("status", 0)
    close_reason = sub.get("state", {}).get("closeReason")
    bounty_val = sub.get("bounty", {}).get("value", 0)
    bounty_cur = sub.get("bounty", {}).get("currency", "EUR")
    has_bonus = sub.get("hasBonus", False)

    if status in (4, 5) and close_reason == 1:
        disposition = "resolved"
    elif status == 3:
        disposition = "accepted"
    elif status in (4, 5) and close_reason == 2:
        disposition = "duplicate"
    elif status in (4, 5) and close_reason == 3:
        disposition = "not_applicable"
    elif status in (4, 5) and close_reason == 4:
        disposition = "informative"
    elif status in (4, 5) and close_reason == 5:
        disposition = "out_of_scope"
    elif status in (4, 5) and close_reason == 6:
        disposition = "wont_fix"
    elif status in (4, 5) and close_reason == 7:
        disposition = "not_applicable"
    elif status in (4, 5) and close_reason is not None:
        disposition = "closed_other"
    elif status == 2:
        disposition = "triaged"
    elif status == 1:
        disposition = "new"
    else:
        disposition = "unknown"

    paid = disposition in ("resolved", "accepted") or has_bonus

    return {
        "disposition": disposition,
        "paid": paid,
        "has_bonus": has_bonus,
        "status_label": STATUS_MAP.get(status, f"Unknown({status})"),
        "close_reason_label": CLOSE_REASONS.get(close_reason, "N/A") if close_reason else "N/A",
    }


def extract_summary(sub, classification, payouts=None):
    bounty = sub.get("bounty", {})
    severity = sub.get("severity", 0)

    summary = {
        "id": sub.get("id"),
        "program": sub.get("programName"),
        "company": sub.get("companyName"),
        "title": sub.get("title"),
        "severity": SEVERITY_MAP.get(severity, f"Unknown({severity})"),
        "severity_raw": severity,
        "cvss_vector": sub.get("severityVector"),
        "status": classification["status_label"],
        "disposition": classification["disposition"],
        "close_reason": classification["close_reason_label"],
        "listed_bounty": bounty.get("value", 0),
        "listed_currency": bounty.get("currency", "EUR"),
        "has_bonus": classification["has_bonus"],
        "paid": classification["paid"],
        "payouts": [],
        "total_paid": 0,
        "total_paid_currency": None,
        "awaiting_feedback": sub.get("awaitingFeedback", False),
        "created_at": datetime.fromtimestamp(sub.get("createdAt", 0)).isoformat(),
        "last_updated": datetime.fromtimestamp(sub.get("lastUpdatedAt", 0)).isoformat() if sub.get("lastUpdatedAt") else None,
    }

    if payouts:
        for p in payouts:
            paid_ts = p.get("createdAt", 0)
            payout_entry = {
                "amount": p.get("amount", {}).get("value", 0),
                "currency": p.get("amount", {}).get("currency", ""),
                "status": PAYOUT_STATUS.get(p.get("status"), f"Unknown({p.get('status')})"),
                "type": PAYOUT_TYPE.get(p.get("type"), f"Unknown({p.get('type')})"),
                "paid_date": datetime.fromtimestamp(paid_ts).strftime("%Y-%m-%d") if paid_ts else None,
            }
            summary["payouts"].append(payout_entry)
            if p.get("status") in (3, 5):  # Paid or Completed
                summary["total_paid"] += payout_entry["amount"]
                summary["total_paid_currency"] = payout_entry["currency"]

    return summary


def generate_report(summaries):
    paid_subs = [s for s in summaries if s["total_paid"] > 0]
    pending_subs = [s for s in summaries if s["disposition"] in ("new", "triaged", "accepted") and s["total_paid"] == 0]
    rejected_subs = [s for s in summaries if s["disposition"] in ("duplicate", "informative", "not_applicable", "out_of_scope", "wont_fix", "closed_other")]

    # Group paid by currency
    paid_by_currency = {}
    for s in paid_subs:
        cur = s["total_paid_currency"] or "?"
        paid_by_currency.setdefault(cur, 0)
        paid_by_currency[cur] += s["total_paid"]

    # Group pending by currency
    pending_by_currency = {}
    for s in pending_subs:
        cur = s["listed_currency"]
        pending_by_currency.setdefault(cur, 0)
        pending_by_currency[cur] += s["listed_bounty"]

    report = {
        "generated_at": datetime.now().isoformat(),
        "total_submissions": len(summaries),
        "breakdown": {
            "paid": len(paid_subs),
            "pending": len(pending_subs),
            "rejected": len(rejected_subs),
        },
        "earnings": {
            "paid": paid_by_currency,
            "pending_potential": pending_by_currency,
        },
        "paid_submissions": sorted(paid_subs, key=lambda x: x["total_paid"], reverse=True),
        "pending_submissions": sorted(pending_subs, key=lambda x: x["listed_bounty"], reverse=True),
        "rejected_submissions": sorted(rejected_subs, key=lambda x: x["listed_bounty"], reverse=True),
    }
    return report


def main():
    parser = argparse.ArgumentParser(description="Export Intigriti inbox submissions")
    parser.add_argument("--cookie", help="__Host-Intigriti.Web.Researcher cookie value")
    parser.add_argument("--cookie-file", help="File containing the cookie value")
    parser.add_argument("--output", default="outputs/intigriti-inbox", help="Output directory")
    parser.add_argument("--fetch-details", action="store_true", help="Fetch full detail for paid/bonus submissions (slower)")
    parser.add_argument("--fetch-all-details", action="store_true", help="Fetch full detail for ALL submissions (slowest)")
    args = parser.parse_args()

    # Get cookie (priority: explicit > file > cache > browser login)
    cookie = args.cookie
    if args.cookie_file:
        cookie = Path(args.cookie_file).read_text().strip()
    if not cookie:
        try:
            from intigriti_auth import get_session_cookie
            cookie = get_session_cookie()
        except ImportError:
            # Try direct import from same directory
            script_dir = Path(__file__).parent
            sys.path.insert(0, str(script_dir))
            try:
                from intigriti_auth import get_session_cookie
                cookie = get_session_cookie()
            except ImportError:
                print("[!] No cookie provided and intigriti_auth.py not found.", file=sys.stderr)
                print("[!] Use --cookie, --cookie-file, or install Playwright for auto-login.", file=sys.stderr)
                sys.exit(1)

    # Fetch submissions
    submissions = fetch_submissions(cookie)

    # Process each submission
    summaries = []
    for i, sub in enumerate(submissions):
        classification = classify_submission(sub)
        need_detail = (
            args.fetch_all_details
            or (args.fetch_details and (classification["has_bonus"] or classification["paid"]))
        )

        payouts = None
        if need_detail:
            print(f"  [{i+1}/{len(submissions)}] Fetching detail for {sub['id']}...")
            detail = fetch_submission_detail(cookie, sub["id"])
            if detail:
                payouts = detail.get("payouts", [])
            time.sleep(0.3)  # rate limit

        summary = extract_summary(sub, classification, payouts)
        summaries.append(summary)

    # Generate report
    report = generate_report(summaries)

    # Save outputs
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Raw summaries
    raw_path = out_dir / f"submissions_{ts}.json"
    with open(raw_path, "w") as f:
        json.dump(summaries, f, indent=2)
    print(f"[+] Raw data: {raw_path}")

    # Report
    report_path = out_dir / f"report_{ts}.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Report: {report_path}")

    # Latest symlinks
    latest_raw = out_dir / "submissions_latest.json"
    latest_report = out_dir / "report_latest.json"
    for link, target in [(latest_raw, raw_path), (latest_report, report_path)]:
        link.unlink(missing_ok=True)
        link.symlink_to(target.name)

    # Print summary to stdout
    print(f"\n{'='*60}")
    print(f"INTIGRITI INBOX SUMMARY - {report['generated_at'][:10]}")
    print(f"{'='*60}")
    print(f"Total submissions: {report['total_submissions']}")
    print(f"  Paid:     {report['breakdown']['paid']}")
    print(f"  Pending:  {report['breakdown']['pending']}")
    print(f"  Rejected: {report['breakdown']['rejected']}")

    print(f"\nEARNINGS (confirmed paid):")
    if report["earnings"]["paid"]:
        for cur, amt in report["earnings"]["paid"].items():
            print(f"  {cur} {amt:,.2f}")
    else:
        print("  (none confirmed - run with --fetch-details to get payout data)")

    print(f"\nPENDING POTENTIAL:")
    for cur, amt in report["earnings"]["pending_potential"].items():
        print(f"  {cur} {amt:,.2f}")

    print(f"\nPAID SUBMISSIONS:")
    for s in report["paid_submissions"]:
        payout_str = ""
        if s["payouts"]:
            payout_str = " | ".join(f"{p['type']}: {p['currency']} {p['amount']:,.0f}" for p in s["payouts"])
        else:
            payout_str = f"bounty: {s['listed_currency']} {s['listed_bounty']:,.0f}"
        print(f"  [{s['severity']}] {s['program']}: {s['title'][:60]}...")
        print(f"    {payout_str}")

    print(f"\nPENDING SUBMISSIONS:")
    for s in report["pending_submissions"]:
        print(f"  [{s['severity']}] {s['disposition'].upper()} | {s['program']}: {s['title'][:55]}...")
        print(f"    potential: {s['listed_currency']} {s['listed_bounty']:,.0f}")

    print(f"\nREJECTED ({len(report['rejected_submissions'])}):")
    for s in report["rejected_submissions"]:
        print(f"  [{s['close_reason']}] {s['program']}: {s['title'][:55]}...")


if __name__ == "__main__":
    main()
