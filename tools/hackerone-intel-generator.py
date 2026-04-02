#!/usr/bin/env python3
"""
HackerOne Intelligence Generator

Downloads disclosed HackerOne reports (data.csv) and generates
hackerone-intel.md files per attack skill folder.

Usage:
    python3 tools/hackerone-intel-generator.py [--csv path/to/data.csv]

Without --csv, fetches latest from GitHub.
"""

import csv
import io
import os
import sys
import json
import urllib.request
from collections import defaultdict
from datetime import datetime
from pathlib import Path

CSV_URL = "https://raw.githubusercontent.com/reddelexc/hackerone-reports/master/data.csv"
ATTACKS_DIR = Path(".claude/skills/pentest/attacks")
PROGRAM_INTEL_DIR = Path(".claude/skills/pentest/program-intel")
INTEL_INDEX_PATH = Path(".claude/skills/pentest/hackerone-intel-index.json")

# Maps our attack skill folders to HackerOne vuln_type patterns (case-insensitive substring match)
# and title keyword fallbacks for reports with empty vuln_type
CATEGORY_MAP = {
    "injection/sql-injection": {
        "vuln_types": ["sql injection"],
        "title_keywords": ["sqli", "sql inj", "sql command"],
    },
    "injection/nosql-injection": {
        "vuln_types": ["nosql injection"],
        "title_keywords": ["nosql"],
    },
    "injection/command-injection": {
        "vuln_types": ["command injection", "os command injection", "argument injection"],
        "title_keywords": ["command injection", "rce", "remote code execution"],
    },
    "injection/ssti": {
        "vuln_types": ["server-side template injection", "ssti", "code injection"],
        "title_keywords": ["ssti", "template injection"],
    },
    "injection/xxe": {
        "vuln_types": ["xml external entities", "xxe"],
        "title_keywords": ["xxe", "xml external entity", "xml entity"],
    },
    "client-side/xss": {
        "vuln_types": [
            "cross-site scripting",
            "xss",
        ],
        "title_keywords": ["xss", "cross site scripting", "cross-site scripting"],
    },
    "client-side/csrf": {
        "vuln_types": ["cross-site request forgery", "csrf"],
        "title_keywords": ["csrf", "xsrf", "cross site request forgery"],
    },
    "client-side/cors": {
        "vuln_types": ["cors misconfiguration"],
        "title_keywords": ["cors"],
    },
    "client-side/clickjacking": {
        "vuln_types": ["clickjacking"],
        "title_keywords": ["clickjacking", "click jacking", "ui redressing"],
    },
    "client-side/prototype-pollution": {
        "vuln_types": ["prototype pollution"],
        "title_keywords": ["prototype pollution"],
    },
    "client-side/dom-based": {
        "vuln_types": ["dom-based xss", "xss - dom"],
        "title_keywords": ["dom xss", "dom-based", "domxss"],
    },
    "server-side/ssrf": {
        "vuln_types": ["server-side request forgery", "ssrf"],
        "title_keywords": ["ssrf", "server side request forgery"],
    },
    "server-side/path-traversal": {
        "vuln_types": ["path traversal", "directory traversal"],
        "title_keywords": ["path traversal", "directory traversal", "lfi", "rfi", "file inclusion", "file reading"],
    },
    "server-side/file-upload": {
        "vuln_types": ["unrestricted file upload", "file upload"],
        "title_keywords": ["file upload", "unrestricted upload"],
    },
    "server-side/http-smuggling": {
        "vuln_types": ["http request smuggling"],
        "title_keywords": ["request smuggling", "http smuggling", "desync"],
    },
    "server-side/deserialization": {
        "vuln_types": ["deserialization"],
        "title_keywords": ["deserialization", "insecure deserialization", "unserialize"],
    },
    "server-side/host-header": {
        "vuln_types": ["host header injection"],
        "title_keywords": ["host header"],
    },
    "server-side/information-disclosure": {
        "vuln_types": ["information disclosure", "information exposure"],
        "title_keywords": ["information disclosure", "info disclosure", "data leak", "data exposure", "pii"],
    },
    "server-side/access-control": {
        "vuln_types": [
            "improper access control",
            "insecure direct object reference",
            "idor",
            "broken access control",
            "authorization bypass",
        ],
        "title_keywords": ["idor", "insecure direct object", "access control", "authorization bypass", "broken access"],
    },
    "server-side/business-logic": {
        "vuln_types": ["business logic"],
        "title_keywords": ["business logic", "logic flaw", "logic error"],
    },
    "server-side/race-conditions": {
        "vuln_types": ["race condition", "time-of-check time-of-use"],
        "title_keywords": ["race condition", "toctou"],
    },
    "server-side/cache-deception": {
        "vuln_types": ["web cache deception"],
        "title_keywords": ["cache deception"],
    },
    "server-side/web-cache-poisoning": {
        "vuln_types": ["web cache poisoning"],
        "title_keywords": ["cache poisoning"],
    },
    "authentication/auth-bypass": {
        "vuln_types": [
            "improper authentication",
            "authentication bypass",
            "missing authentication",
        ],
        "title_keywords": ["auth bypass", "authentication bypass", "2fa bypass", "mfa bypass"],
    },
    "authentication/jwt": {
        "vuln_types": [],
        "title_keywords": ["jwt", "json web token"],
    },
    "authentication/oauth": {
        "vuln_types": ["oauth", "open redirect"],
        "title_keywords": ["oauth", "openid", "saml", "sso"],
    },
    "authentication/password-attacks": {
        "vuln_types": ["weak password", "brute force", "credential stuffing"],
        "title_keywords": ["password reset", "brute force", "account takeover", "credential"],
    },
    "api-security/graphql": {
        "vuln_types": [],
        "title_keywords": ["graphql"],
    },
    "api-security/rest-api": {
        "vuln_types": ["improper input validation"],
        "title_keywords": ["api", "rest api", "api endpoint"],
    },
    "api-security/websockets": {
        "vuln_types": [],
        "title_keywords": ["websocket", "ws://", "wss://"],
    },
    "web-applications/access-control": {
        "vuln_types": ["privilege escalation", "improper authorization"],
        "title_keywords": ["privilege escalation", "unauthorized access", "permission"],
    },
    "web-applications/business-logic": {
        "vuln_types": ["business logic"],
        "title_keywords": ["logic flaw", "manipulation", "functionality"],
    },
    "web-applications/race-conditions": {
        "vuln_types": ["race condition"],
        "title_keywords": ["race condition"],
    },
    "web-applications/info-disclosure": {
        "vuln_types": ["information disclosure"],
        "title_keywords": ["information disclosure", "data leak"],
    },
    "web-applications/cache-poisoning": {
        "vuln_types": ["web cache poisoning"],
        "title_keywords": ["cache poisoning"],
    },
    "web-applications/cache-deception": {
        "vuln_types": ["web cache deception"],
        "title_keywords": ["cache deception"],
    },
    "system/privilege-escalation": {
        "vuln_types": ["privilege escalation"],
        "title_keywords": ["privilege escalation", "privesc", "root access"],
    },
    "ip-infrastructure/dos": {
        "vuln_types": ["denial of service", "uncontrolled resource consumption"],
        "title_keywords": ["dos", "denial of service", "resource consumption", "redos"],
    },
    "ip-infrastructure/dns": {
        "vuln_types": ["subdomain takeover"],
        "title_keywords": ["subdomain takeover", "dns", "dangling cname"],
    },
    "cloud-containers/aws": {
        "vuln_types": [],
        "title_keywords": ["aws", "s3 bucket", "amazon", "ec2", "lambda"],
    },
    "cloud-containers/gcp": {
        "vuln_types": [],
        "title_keywords": ["gcp", "google cloud", "firebase"],
    },
    "cloud-containers/azure": {
        "vuln_types": [],
        "title_keywords": ["azure", "microsoft cloud"],
    },
    "cloud-containers/kubernetes": {
        "vuln_types": [],
        "title_keywords": ["kubernetes", "k8s", "kubectl"],
    },
    "cloud-containers/docker": {
        "vuln_types": [],
        "title_keywords": ["docker", "container escape"],
    },
}


def download_csv(csv_path=None):
    """Download or read the CSV data."""
    if csv_path and os.path.exists(csv_path):
        print(f"[*] Reading local CSV: {csv_path}")
        with open(csv_path, "r", encoding="utf-8") as f:
            return f.read()

    print(f"[*] Downloading CSV from GitHub...")
    req = urllib.request.Request(CSV_URL, headers={"User-Agent": "julius-intel-generator/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read().decode("utf-8")
    print(f"[+] Downloaded {len(data):,} bytes")
    return data


def parse_csv(raw_csv):
    """Parse CSV into list of report dicts."""
    reader = csv.DictReader(io.StringIO(raw_csv))
    reports = []
    for row in reader:
        try:
            bounty = float(row.get("bounty", 0) or 0)
        except (ValueError, TypeError):
            bounty = 0.0
        try:
            upvotes = int(row.get("upvotes", 0) or 0)
        except (ValueError, TypeError):
            upvotes = 0

        reports.append({
            "program": row.get("program", "").strip(),
            "title": row.get("title", "").strip(),
            "link": row.get("link", "").strip(),
            "upvotes": upvotes,
            "bounty": bounty,
            "vuln_type": row.get("vuln_type", "").strip(),
        })
    return reports


def match_report(report, vuln_types, title_keywords):
    """Check if a report matches a category by vuln_type or title keywords."""
    vt = report["vuln_type"].lower()
    title = report["title"].lower()

    # Primary: match by vuln_type
    for pattern in vuln_types:
        if pattern.lower() in vt:
            return True

    # Fallback: match by title keywords (only if vuln_type didn't match anything)
    for kw in title_keywords:
        if kw.lower() in title:
            return True

    return False


def categorize_reports(reports):
    """Assign reports to attack categories."""
    categorized = defaultdict(list)

    for report in reports:
        for folder, rules in CATEGORY_MAP.items():
            if match_report(report, rules["vuln_types"], rules["title_keywords"]):
                categorized[folder].append(report)

    return categorized


def compute_stats(reports):
    """Compute statistics for a set of reports."""
    paid = [r for r in reports if r["bounty"] > 0]
    bounties = [r["bounty"] for r in paid]

    programs = defaultdict(int)
    for r in reports:
        if r["program"]:
            programs[r["program"]] += 1

    top_programs = sorted(programs.items(), key=lambda x: -x[1])[:10]

    stats = {
        "total": len(reports),
        "paid_count": len(paid),
        "paid_pct": round(len(paid) / len(reports) * 100, 1) if reports else 0,
        "bounty_min": min(bounties) if bounties else 0,
        "bounty_max": max(bounties) if bounties else 0,
        "bounty_median": sorted(bounties)[len(bounties) // 2] if bounties else 0,
        "bounty_avg": round(sum(bounties) / len(bounties), 0) if bounties else 0,
        "bounty_total": sum(bounties),
        "top_programs": top_programs,
    }
    return stats


def extract_patterns(reports):
    """Extract common attack patterns from report titles."""
    pattern_signals = defaultdict(int)

    # Common pattern keywords to look for in titles
    pattern_keywords = {
        "parameter manipulation": ["parameter", "param", "query string", "url parameter"],
        "API endpoint": ["api", "endpoint", "/api/", "graphql", "rest"],
        "authentication context": ["login", "password", "session", "cookie", "token", "auth"],
        "file/path based": ["file", "path", "directory", "upload", "download"],
        "input field": ["search", "input", "form", "comment", "message", "name field"],
        "header injection": ["header", "host header", "referer", "user-agent", "x-forwarded"],
        "redirect/URL": ["redirect", "url", "callback", "return_to", "next="],
        "admin/internal": ["admin", "internal", "dashboard", "panel", "management"],
        "mobile/app": ["mobile", "android", "ios", "app", "apk"],
        "email based": ["email", "mail", "smtp", "notification"],
        "payment/billing": ["payment", "billing", "price", "cart", "checkout", "stripe"],
    }

    for report in reports:
        title_lower = report["title"].lower()
        for pattern_name, keywords in pattern_keywords.items():
            for kw in keywords:
                if kw in title_lower:
                    pattern_signals[pattern_name] += 1
                    break

    total = len(reports)
    patterns = []
    for name, count in sorted(pattern_signals.items(), key=lambda x: -x[1]):
        pct = round(count / total * 100) if total else 0
        if pct >= 3:  # Only include patterns that appear in 3%+ of reports
            patterns.append((name, pct, count))

    return patterns[:8]


def generate_intel_md(folder, reports, stats, patterns):
    """Generate the hackerone-intel.md content for a category."""
    category_name = folder.split("/")[-1].replace("-", " ").title()
    parent_category = folder.split("/")[0].replace("-", " ").title()

    # Sort reports by score (bounty * 0.4 + upvotes * 0.6) for "most impactful"
    scored = sorted(reports, key=lambda r: r["bounty"] * 0.4 + r["upvotes"] * 0.6, reverse=True)
    top_reports = scored[:20]

    lines = []
    lines.append(f"# HackerOne Intel: {category_name}")
    lines.append(f"<!-- Auto-generated by hackerone-intel-generator.py | {datetime.now().strftime('%Y-%m-%d')} | {stats['total']} reports -->")
    lines.append(f"<!-- Source: github.com/reddelexc/hackerone-reports | Refresh: python3 tools/hackerone-intel-generator.py -->")
    lines.append("")

    # Quick stats block
    lines.append("## Stats")
    lines.append(f"- **Total disclosed reports**: {stats['total']}")
    lines.append(f"- **Paid**: {stats['paid_count']} ({stats['paid_pct']}%)")
    if stats["paid_count"] > 0:
        lines.append(f"- **Bounty range**: ${stats['bounty_min']:,.0f} - ${stats['bounty_max']:,.0f}")
        lines.append(f"- **Median bounty**: ${stats['bounty_median']:,.0f} | **Avg**: ${stats['bounty_avg']:,.0f}")
    lines.append("")

    # Top programs
    if stats["top_programs"]:
        lines.append("## Top Programs")
        prog_line = " | ".join(f"{p}({c})" for p, c in stats["top_programs"][:8])
        lines.append(prog_line)
        lines.append("")

    # Attack pattern signals
    if patterns:
        lines.append("## Attack Surface Signals")
        for name, pct, count in patterns:
            lines.append(f"- {pct}% {name} ({count} reports)")
        lines.append("")

    # Top reports table (compressed pipe-delimited)
    lines.append("## Top Reports (by impact score)")
    lines.append("Title|Program|Bounty|Upvotes|ID")
    lines.append("---|---|---|---|---")
    for r in top_reports:
        report_id = r["link"].split("/")[-1] if "/" in r["link"] else r["link"]
        title_short = r["title"][:80] + ("..." if len(r["title"]) > 80 else "")
        bounty_str = f"${r['bounty']:,.0f}" if r["bounty"] > 0 else "-"
        lines.append(f"{title_short}|{r['program']}|{bounty_str}|{r['upvotes']}|{report_id}")

    lines.append("")

    # Bounty distribution (for paid reports)
    if stats["paid_count"] > 2:
        paid = sorted([r for r in reports if r["bounty"] > 0], key=lambda r: r["bounty"])
        brackets = [
            ("$1-$500", 1, 500),
            ("$501-$2,000", 501, 2000),
            ("$2,001-$5,000", 2001, 5000),
            ("$5,001-$15,000", 5001, 15000),
            ("$15,001+", 15001, float("inf")),
        ]
        lines.append("## Bounty Distribution")
        for label, lo, hi in brackets:
            count = sum(1 for r in paid if lo <= r["bounty"] <= hi)
            if count > 0:
                pct = round(count / len(paid) * 100)
                lines.append(f"- {label}: {count} ({pct}%)")
        lines.append("")

    # Usage hint for executor
    lines.append("## Usage")
    lines.append("This intel is auto-loaded by the executor during skill folder reading.")
    lines.append("Use top report IDs to fetch full writeups: `https://hackerone.com/reports/{ID}`")
    lines.append("Pattern signals inform which injection points and contexts to prioritize.")

    return "\n".join(lines) + "\n"


def generate_program_index(reports):
    """Generate a JSON index of reports by program for the on-demand fetcher."""
    programs = defaultdict(lambda: {"reports": [], "vuln_types": defaultdict(int), "total_bounty": 0})

    for r in reports:
        prog = r["program"]
        if not prog:
            continue
        programs[prog]["reports"].append({
            "title": r["title"],
            "link": r["link"],
            "upvotes": r["upvotes"],
            "bounty": r["bounty"],
            "vuln_type": r["vuln_type"],
        })
        if r["vuln_type"]:
            programs[prog]["vuln_types"][r["vuln_type"]] += 1
        programs[prog]["total_bounty"] += r["bounty"]

    # Build summary index (not full reports - just stats per program)
    index = {}
    for prog, data in programs.items():
        top_vulns = sorted(data["vuln_types"].items(), key=lambda x: -x[1])[:5]
        paid = [r for r in data["reports"] if r["bounty"] > 0]
        index[prog] = {
            "report_count": len(data["reports"]),
            "total_bounty": data["total_bounty"],
            "avg_bounty": round(data["total_bounty"] / len(paid)) if paid else 0,
            "top_vuln_types": top_vulns,
            "top_reports": sorted(data["reports"], key=lambda r: r["bounty"] * 0.4 + r["upvotes"] * 0.6, reverse=True)[:10],
        }

    return index


def main():
    csv_path = None
    if "--csv" in sys.argv:
        idx = sys.argv.index("--csv")
        if idx + 1 < len(sys.argv):
            csv_path = sys.argv[idx + 1]

    # Download/read CSV
    raw_csv = download_csv(csv_path)
    reports = parse_csv(raw_csv)
    print(f"[+] Parsed {len(reports):,} reports")

    # Categorize
    categorized = categorize_reports(reports)
    print(f"[+] Mapped to {len(categorized)} attack categories")

    # Generate per-category intel files
    generated = 0
    skipped = 0
    for folder, cat_reports in sorted(categorized.items()):
        target_dir = ATTACKS_DIR / folder
        if not target_dir.exists():
            print(f"  [-] Folder not found, skipping: {folder}")
            skipped += 1
            continue

        stats = compute_stats(cat_reports)
        patterns = extract_patterns(cat_reports)
        content = generate_intel_md(folder, cat_reports, stats, patterns)

        intel_path = target_dir / "hackerone-intel.md"
        intel_path.write_text(content, encoding="utf-8")
        generated += 1
        print(f"  [+] {folder}: {stats['total']} reports, {stats['paid_count']} paid → {intel_path}")

    print(f"\n[+] Generated {generated} intel files ({skipped} skipped)")

    # Generate program index for on-demand fetcher
    print(f"[*] Building program intelligence index...")
    program_index = generate_program_index(reports)

    INTEL_INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(INTEL_INDEX_PATH, "w", encoding="utf-8") as f:
        json.dump(program_index, f, indent=None, separators=(",", ":"))

    print(f"[+] Program index: {len(program_index)} programs → {INTEL_INDEX_PATH}")
    print(f"[+] Index size: {os.path.getsize(INTEL_INDEX_PATH):,} bytes")

    # Summary stats
    total_mapped = sum(len(v) for v in categorized.values())
    unmapped = len(reports) - len(set(id(r) for cats in categorized.values() for r in cats))
    print(f"\n=== Summary ===")
    print(f"Total reports: {len(reports):,}")
    print(f"Category assignments: {total_mapped:,} (reports can map to multiple categories)")
    unique_mapped = len(set(id(r) for cats in categorized.values() for r in cats))
    print(f"Unique reports mapped: {unique_mapped:,} ({round(unique_mapped/len(reports)*100)}%)")
    print(f"Unmapped: {unmapped:,} ({round(unmapped/len(reports)*100)}%)")
    print(f"Intel files generated: {generated}")
    print(f"Programs indexed: {len(program_index)}")


if __name__ == "__main__":
    main()
