#!/usr/bin/env python3
"""
Pending Reports Scanner — finds INTI_*_*.md reports not yet submitted to Intigriti.

Scans outputs/intigriti-*/reports/submissions/INTI_*_*.md, cross-references with
Intigriti API submissions, and checks program status.

Usage:
  python3 pending_reports_scanner.py --output outputs/intigriti-inbox/pending_reports.json
"""

import argparse
import json
import os
import re
import sys
import urllib.request
import urllib.error
from glob import glob
from pathlib import Path


COOKIE_CACHE = Path.home() / ".intigriti" / "session_cookie.txt"
SESSION_COOKIE_NAME = "__Host-Intigriti.Web.Researcher"
API_BASE = "https://app.intigriti.com/api/core/researcher"

# Map local directory names to Intigriti company handles
# (directory: intigriti-{program} → company handle comes from API)


def get_cookie():
    if COOKIE_CACHE.exists():
        return COOKIE_CACHE.read_text().strip()
    return None


def api_get(path, cookie):
    url = f"{API_BASE}{path}"
    req = urllib.request.Request(url)
    req.add_header("Cookie", f"{SESSION_COOKIE_NAME}={cookie}")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "IntiPendingScanner/1.0")
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_all_submissions(cookie):
    """Fetch all researcher submissions from Intigriti."""
    subs = api_get("/submissions?offset=0&limit=100", cookie)
    return subs


def fetch_program_status(company_handle, program_handle, cookie):
    """Fetch program status. Returns status int: 3=Open, 4=Suspended, 5=Closed."""
    try:
        data = api_get(f"/programs/{company_handle}/{program_handle}", cookie)
        return data.get("status", 0), data.get("name", "")
    except (urllib.error.HTTPError, urllib.error.URLError):
        return 0, ""


def extract_title_from_md(filepath):
    """Extract the submission title from an INTI markdown file."""
    with open(filepath, "r") as f:
        lines = f.readlines()

    # Strategy 1: First non-blank line after "## Title" heading (most structured format)
    for i, line in enumerate(lines[:30]):
        if line.strip() == "## Title":
            for j in range(i + 1, min(i + 4, len(lines))):
                candidate = lines[j].strip()
                if candidate and not candidate.startswith("#") and len(candidate) > 5:
                    return candidate
            break

    # Strategy 2: **Title**: value (inside Metadata sections)
    for line in lines[:30]:
        m = re.match(r'[-*]*\s*\*\*Title\*\*\s*:\s*(.+)', line.strip())
        if m and len(m.group(1).strip()) > 5:
            return m.group(1).strip()

    # Strategy 3: **Title:** value (bold with colon inside)
    for line in lines[:30]:
        m = re.match(r'\*\*Title:\*\*\s*(.+)', line.strip())
        if m and len(m.group(1).strip()) > 5:
            return m.group(1).strip()

    # Strategy 4: First H1 heading (skip generic "Intigriti Submission" prefixes)
    for line in lines[:10]:
        if line.startswith("# "):
            title = line[2:].strip()
            if not re.match(r'Intigriti Submission[:\s—-]*$', title):
                # Strip "Intigriti Submission:" prefix if followed by content
                title = re.sub(r'^Intigriti Submission[:\s—-]+', '', title).strip()
                if len(title) > 5:
                    return title

    # Strategy 5: First H1 as-is (last resort)
    for line in lines[:10]:
        if line.startswith("# "):
            return line[2:].strip()

    return Path(filepath).stem


def extract_severity_from_md(filepath):
    """Extract severity from INTI markdown file."""
    with open(filepath, "r") as f:
        content = f.read(3000)

    # Look for **Severity** or severity badges
    for pattern in [
        r'\*\*(?:Severity|severity)[:\s]*\*?\*?\s*(Exceptional|Critical|High|Medium|Low)',
        r'\*\*(Exceptional|Critical|High|Medium|Low)\*\*',
        r'Severity.*?(Exceptional|Critical|High|Medium|Low)',
    ]:
        m = re.search(pattern, content, re.IGNORECASE)
        if m:
            return m.group(1).capitalize()
    return "Unknown"


def scan_local_reports(base_dir):
    """Scan for all INTI_*_*.md files in outputs/intigriti-*/reports/submissions/."""
    pattern = os.path.join(base_dir, "outputs", "intigriti-*", "reports", "submissions", "INTI_*_*.md")
    files = glob(pattern)
    reports = []
    for f in sorted(files):
        parts = Path(f).parts
        # Extract program directory name (intigriti-{name})
        for p in parts:
            if p.startswith("intigriti-"):
                program_dir = p.replace("intigriti-", "")
                break
        else:
            program_dir = "unknown"

        reports.append({
            "file": f,
            "filename": Path(f).name,
            "program_dir": program_dir,
            "title": extract_title_from_md(f),
            "severity": extract_severity_from_md(f),
        })
    return reports


def match_submission(report_title, submissions, program_dir=None):
    """Check if a local report title matches any existing Intigriti submission.
    Also checks by program_dir to narrow matching scope."""
    rt = report_title.lower().strip()
    # Strip generic prefixes
    for prefix in ["intigriti submission:", "intigriti submission —", "intigriti submission -"]:
        if rt.startswith(prefix):
            rt = rt[len(prefix):].strip()

    for sub in submissions:
        st = sub.get("title", "").lower().strip()
        # Exact match
        if rt == st:
            return sub
        # Substring match (title may be truncated on Intigriti — API truncates at ~100 chars)
        if len(rt) > 15 and (rt[:50] in st or st[:50] in rt):
            return sub
        # Key phrase overlap (at least 3 significant words in common)
        stop_words = {"the", "and", "via", "with", "from", "that", "this", "into", "for", "all"}
        r_words = set(w for w in re.split(r'\W+', rt) if len(w) > 3 and w not in stop_words)
        s_words = set(w for w in re.split(r'\W+', st) if len(w) > 3 and w not in stop_words)
        overlap = len(r_words & s_words)
        if overlap >= 3 and overlap / max(len(r_words), 1) > 0.35:
            return sub

    # Fallback: if program_dir matches a companyHandle and there's only 1 unmatched sub
    # for that company with similar severity, consider it a match
    if program_dir:
        pd = program_dir.lower()
        company_subs = [s for s in submissions
                        if pd in s.get("companyHandle", "").lower()
                        or pd in s.get("programHandle", "").lower()]
        # Check for very short title match (program name only)
        for sub in company_subs:
            st = sub.get("title", "").lower()
            # If local title is just the program name, can't match reliably
            if len(rt) < 10:
                continue
            # Try matching first 40 chars
            if rt[:40] in st or st[:40] in rt:
                return sub

    return None


def resolve_program_handle(program_dir, submissions, cookie=None):
    """Resolve company/program handles from existing submissions or API search."""
    pd = program_dir.lower()

    # Strategy 1: Match from existing submissions
    for sub in submissions:
        ch = sub.get("companyHandle", "").lower()
        ph = sub.get("programHandle", "").lower()
        if pd == ch or pd == ph or pd in ph or ph in pd:
            return sub.get("companyHandle", ""), sub.get("programHandle", "")

    # Strategy 2: Search programs API (handles program_dirs with no existing submissions)
    if cookie:
        try:
            programs = api_get("/programs?statusId=4&limit=200", cookie)
            for p in programs:
                ph = p.get("handle", "").lower()
                ch = p.get("companyHandle", "").lower()
                name = p.get("name", "").lower()
                if pd == ph or pd == ch or pd in ph or pd in name or ph in pd:
                    return p.get("companyHandle", ""), p.get("handle", "")
        except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError):
            pass

    return None, None


def main():
    parser = argparse.ArgumentParser(description="Scan for pending INTI reports not yet submitted")
    parser.add_argument("--base-dir", default=".", help="Repository root directory")
    parser.add_argument("--output", default="outputs/intigriti-inbox/pending_reports.json")
    args = parser.parse_args()

    cookie = get_cookie()
    if not cookie:
        print("[!] No Intigriti session cookie. Run intigriti_auth.py first.", file=sys.stderr)
        sys.exit(1)

    # Step 1: Scan local INTI reports
    print("[*] Scanning for local INTI_*_*.md reports...")
    local_reports = scan_local_reports(args.base_dir)
    print(f"[+] Found {len(local_reports)} local INTI reports")

    if not local_reports:
        print("[*] No local reports found.")
        result = {"pending": [], "already_submitted": [], "programs": {}}
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(result, indent=2))
        return

    # Step 2: Fetch all submissions from Intigriti
    print("[*] Fetching submissions from Intigriti API...")
    submissions = fetch_all_submissions(cookie)
    print(f"[+] Found {len(submissions)} submissions on Intigriti")

    # Step 3: Cross-reference
    print("[*] Cross-referencing local reports with Intigriti submissions...")
    pending = []
    already_submitted = []
    program_dirs_seen = set()

    for report in local_reports:
        match = match_submission(report["title"], submissions, program_dir=report["program_dir"])
        if match:
            already_submitted.append({
                **report,
                "submission_id": match["id"],
                "submission_status": match["state"]["status"],
            })
        else:
            pending.append(report)
        program_dirs_seen.add(report["program_dir"])

    print(f"[+] Pending (not submitted): {len(pending)}")
    print(f"[+] Already submitted: {len(already_submitted)}")

    # Step 4: Check program status for pending reports
    print("[*] Checking program status for pending reports...")
    STATUS_MAP = {1: "draft", 2: "review", 3: "open", 4: "suspended", 5: "closed"}
    program_status = {}

    for pd in program_dirs_seen:
        ch, ph = resolve_program_handle(pd, submissions, cookie=cookie)
        if ch and ph:
            status_code, name = fetch_program_status(ch, ph, cookie)
            program_status[pd] = {
                "company_handle": ch,
                "program_handle": ph,
                "name": name,
                "status": STATUS_MAP.get(status_code, "unknown"),
                "status_code": status_code,
            }
        else:
            # Try direct lookup with program_dir as both handles
            try:
                # Search in the full program list
                status_code, name = 0, ""
                program_status[pd] = {
                    "company_handle": pd,
                    "program_handle": pd,
                    "name": pd,
                    "status": "unknown",
                    "status_code": 0,
                }
            except Exception:
                pass

    # Annotate pending reports with program status
    for p in pending:
        pd = p["program_dir"]
        if pd in program_status:
            p["program_name"] = program_status[pd].get("name", pd)
            p["program_status"] = program_status[pd].get("status", "unknown")
        else:
            p["program_name"] = pd
            p["program_status"] = "unknown"

    # Step 5: Output
    result = {
        "scan_date": __import__("datetime").datetime.now().isoformat(),
        "total_local_reports": len(local_reports),
        "pending_count": len(pending),
        "already_submitted_count": len(already_submitted),
        "pending": pending,
        "already_submitted": already_submitted,
        "programs": program_status,
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(f"[+] Saved to {out}")

    # Summary
    print(f"\n{'='*60}")
    print("PENDING REPORTS (not yet submitted)")
    print(f"{'='*60}")
    for p in pending:
        status_tag = f"[{p['program_status'].upper()}]" if p["program_status"] != "open" else ""
        print(f"  {p['filename']:<35} {p['severity']:<8} {p['program_name']} {status_tag}")
        print(f"    {p['title'][:80]}")


if __name__ == "__main__":
    main()
