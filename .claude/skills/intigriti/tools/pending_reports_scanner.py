#!/usr/bin/env python3
"""
Pending Reports Scanner — finds INTI_*_*.md and H1_*_*.md reports not yet submitted.

Scans outputs/intigriti-*/reports/submissions/INTI_*_*.md and
outputs/hackerone-*/reports/submissions/H1_*_*.md, cross-references with
platform APIs, and checks program status.

Usage:
  python3 pending_reports_scanner.py --output outputs/combined-inbox/pending_reports.json
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
    """Scan for INTI_*_*.md and H1_*_*.md files in outputs/*/reports/submissions/."""
    inti_pattern = os.path.join(base_dir, "outputs", "intigriti-*", "reports", "submissions", "INTI_*_*.md")
    h1_pattern = os.path.join(base_dir, "outputs", "hackerone-*", "reports", "submissions", "H1_*_*.md")
    files = glob(inti_pattern) + glob(h1_pattern)
    reports = []
    for f in sorted(files):
        parts = Path(f).parts
        filename = Path(f).name
        # Detect platform from filename prefix
        if filename.startswith("H1_"):
            platform = "hackerone"
            prefix = "hackerone-"
        else:
            platform = "intigriti"
            prefix = "intigriti-"
        # Extract program directory name
        for p in parts:
            if p.startswith(prefix):
                program_dir = p.replace(prefix, "")
                break
        else:
            program_dir = "unknown"

        reports.append({
            "file": f,
            "filename": filename,
            "program_dir": program_dir,
            "platform": platform,
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


def _load_env():
    """Load .env file from repo root."""
    env_path = Path(__file__).resolve().parents[4] / ".env"
    if not env_path.exists():
        env_path = Path.cwd() / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                os.environ.setdefault(key.strip(), val.strip())


def fetch_h1_reports_for_matching():
    """Fetch H1 reports for cross-referencing. Returns list of dicts with id, title, state."""
    import base64
    _load_env()
    username = os.environ.get("HACKERONE_USERNAME", "")
    token = os.environ.get("HACKERONE_API_TOKEN", "")
    if not username or not token:
        return []
    creds = base64.b64encode(f"{username}:{token}".encode()).decode()
    reports = []
    url = "https://api.hackerone.com/v1/hackers/me/reports?page%5Bsize%5D=100"
    while url:
        try:
            req = urllib.request.Request(url)
            req.add_header("Authorization", f"Basic {creds}")
            req.add_header("Accept", "application/json")
            req.add_header("User-Agent", "PendingScanner/1.0")
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            for item in data.get("data", []):
                attrs = item.get("attributes", {})
                reports.append({
                    "id": item.get("id"),
                    "title": attrs.get("title", ""),
                    "state": {"status": attrs.get("state", "new")},
                })
            url = data.get("links", {}).get("next")
        except (urllib.error.HTTPError, urllib.error.URLError):
            break
    return reports


def main():
    parser = argparse.ArgumentParser(description="Scan for pending local reports not yet submitted")
    parser.add_argument("--base-dir", default=".", help="Repository root directory")
    parser.add_argument("--output", default="outputs/combined-inbox/pending_reports.json")
    args = parser.parse_args()

    # Step 1: Scan local reports (both INTI and H1)
    print("[*] Scanning for local INTI_*_*.md and H1_*_*.md reports...")
    local_reports = scan_local_reports(args.base_dir)
    inti_reports = [r for r in local_reports if r.get("platform") == "intigriti"]
    h1_reports = [r for r in local_reports if r.get("platform") == "hackerone"]
    print(f"[+] Found {len(inti_reports)} INTI + {len(h1_reports)} H1 = {len(local_reports)} local reports")

    if not local_reports:
        print("[*] No local reports found.")
        result = {"pending": [], "already_submitted": [], "programs": {}}
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(result, indent=2))
        return

    # Step 2: Fetch submissions from both platforms
    inti_submissions = []
    cookie = get_cookie()
    if cookie and inti_reports:
        print("[*] Fetching submissions from Intigriti API...")
        inti_submissions = fetch_all_submissions(cookie)
        print(f"[+] Found {len(inti_submissions)} submissions on Intigriti")
    elif inti_reports:
        print("[!] No Intigriti session cookie — skipping INTI cross-reference")

    h1_submissions = []
    if h1_reports:
        print("[*] Fetching submissions from HackerOne API...")
        h1_submissions = fetch_h1_reports_for_matching()
        print(f"[+] Found {len(h1_submissions)} submissions on HackerOne")

    # Step 3: Cross-reference by platform
    print("[*] Cross-referencing local reports with platform submissions...")
    pending = []
    already_submitted = []
    program_dirs_seen = set()

    for report in local_reports:
        if report.get("platform") == "hackerone":
            subs = h1_submissions
        else:
            subs = inti_submissions
        match = match_submission(report["title"], subs, program_dir=report["program_dir"])
        if match:
            already_submitted.append({
                **report,
                "submission_id": match["id"],
                "submission_status": match.get("state", {}).get("status"),
            })
        else:
            pending.append(report)
        program_dirs_seen.add((report["program_dir"], report.get("platform", "intigriti")))

    print(f"[+] Pending (not submitted): {len(pending)}")
    print(f"[+] Already submitted: {len(already_submitted)}")

    # Step 4: Check program status for pending Intigriti reports
    print("[*] Checking program status for pending reports...")
    STATUS_MAP = {1: "draft", 2: "review", 3: "open", 4: "suspended", 5: "closed"}
    program_status = {}

    for pd, platform in program_dirs_seen:
        if platform == "intigriti" and cookie:
            ch, ph = resolve_program_handle(pd, inti_submissions, cookie=cookie)
            if ch and ph:
                status_code, name = fetch_program_status(ch, ph, cookie)
                program_status[pd] = {
                    "company_handle": ch,
                    "program_handle": ph,
                    "name": name,
                    "platform": "intigriti",
                    "status": STATUS_MAP.get(status_code, "unknown"),
                    "status_code": status_code,
                }
            else:
                program_status[pd] = {
                    "company_handle": pd, "program_handle": pd,
                    "name": pd, "platform": "intigriti",
                    "status": "unknown", "status_code": 0,
                }
        elif platform == "hackerone":
            # H1 programs: mark as open (no easy status check via API)
            program_status[pd] = {
                "company_handle": pd, "program_handle": pd,
                "name": pd, "platform": "hackerone",
                "status": "open", "status_code": 3,
            }

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
        platform_tag = f"[{p.get('platform', 'inti').upper()[:4]}]"
        status_tag = f"[{p['program_status'].upper()}]" if p["program_status"] != "open" else ""
        print(f"  {platform_tag} {p['filename']:<35} {p['severity']:<8} {p['program_name']} {status_tag}")
        print(f"    {p['title'][:80]}")


if __name__ == "__main__":
    main()
