#!/usr/bin/env python3
"""
HackerOne Technique Extractor

Analyzes 14.5K+ report titles to extract real-world attack techniques,
vectors, bypass methods, and contexts. Generates hackerone-techniques.md
per attack category with actionable methodology for the executor.

Usage:
    python3 tools/hackerone-technique-extractor.py [--csv path/to/data.csv]
"""

import csv
import io
import os
import re
import sys
import urllib.request
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path

CSV_URL = "https://raw.githubusercontent.com/reddelexc/hackerone-reports/master/data.csv"
ATTACKS_DIR = Path(".claude/skills/pentest/attacks")

# ═══════════════════════════════════════════════════════════════
# TECHNIQUE TAXONOMY — patterns extracted from report titles
# Each entry: (regex_pattern, technique_label, category)
# ═══════════════════════════════════════════════════════════════

TECHNIQUE_PATTERNS = {
    # ── Injection Points (WHERE to inject) ──
    "injection_points": [
        (r"\bparameters?\b|\bparams?\b|\bquery.?string\b", "URL/query parameters"),
        (r"\bheaders?\b|\bhost.?header\b|\breferer\b|\buser.?agent\b|\bx-forwarded\b", "HTTP headers"),
        (r"\bcookies?\b|\bsession\b", "cookies/session tokens"),
        (r"\bjson\b|\bjson.?body\b|\brequest.?body\b|\bpost.?body\b", "JSON request body"),
        (r"\bxml\b|\bsoap\b", "XML/SOAP body"),
        (r"\bfile.?name\b|\bupload\b|\bmultipart\b|\bfile.?upload\b", "file upload/filename"),
        (r"\bpath\b|\burl.?path\b|\broute\b|\bslug\b", "URL path/route"),
        (r"\bwebsocket\b|\bws://\b|\bwss://\b", "WebSocket messages"),
        (r"\bemail\b|\bmail\b|\bsmtp\b", "email fields"),
        (r"\bmarkdown\b|\brich.?text\b|\beditor\b|\bwysiwyg\b", "rich text/markdown input"),
        (r"\bsvg\b", "SVG content"),
        (r"\bpdf\b", "PDF generation/upload"),
        (r"\bimage\b|\bthumbnail\b|\bavatar\b|\bpicture\b|\bphoto\b", "image/media processing"),
        (r"\bimport\b|\bexport\b|\bcsv\b|\bexcel\b", "import/export functionality"),
        (r"\bwebhook\b|\bcallback\b", "webhook/callback URLs"),
        (r"\bgraphql\b|\bmutation\b|\bquery\b.*\bgraphql\b", "GraphQL queries/mutations"),
        (r"\bsearch\b|\bfilter\b|\bsort\b|\bquery\b(?!.?string)", "search/filter/sort"),
        (r"\bcomment\b|\breview\b|\bfeedback\b|\bmessage\b|\bchat\b", "user-generated content (comments, messages)"),
        (r"\bprofile\b|\bbio\b|\busername\b|\bdisplay.?name\b", "profile fields"),
        (r"\bredirect\b|\breturn.?url\b|\bnext=\b|\bcallback.?url\b|\bgoto\b|\breturn_to\b", "redirect/callback parameters"),
    ],

    # ── Attack Techniques (HOW to exploit) ──
    "techniques": [
        (r"\bblind\b(?!.*xss)", "blind/out-of-band"),
        (r"\btime.?based\b|\bsleep\b|\bdelay\b", "time-based/delay injection"),
        (r"\bunion\b(?!.*jack)", "UNION-based extraction"),
        (r"\berror.?based\b", "error-based extraction"),
        (r"\bstacked\b|\bbatch\b.*\bquer", "stacked queries"),
        (r"\bsecond.?order\b", "second-order injection"),
        (r"\bstored\b", "stored/persistent"),
        (r"\breflected\b", "reflected/non-persistent"),
        (r"\bdom\b.?(?:based|xss)|\bdom\b", "DOM-based"),
        (r"\bself.?xss\b", "self-XSS (requires chaining)"),
        (r"\bmutation\b.*\bxss\b|\bmxss\b", "mutation XSS (mXSS)"),
        (r"\brace.?condition\b|\btoctou\b|\bconcurren", "race condition/TOCTOU"),
        (r"\bopen.?redirect\b", "open redirect"),
        (r"\bfull.?read\b|\bfull.?response\b|\bfull.?ssrf\b", "full-read (non-blind)"),
        (r"\bblind.?ssrf\b|\bout.?of.?band\b|\boob\b", "blind/OOB SSRF"),
        (r"\bdns.?rebinding\b", "DNS rebinding"),
        (r"\bprototype.?pollution\b", "prototype pollution"),
        (r"\bdeserialization\b|\bunserialize\b|\bpickle\b|\byaml\b.*\bload\b", "insecure deserialization"),
        (r"\btemplate.?injection\b|\bssti\b|\bjinja\b|\btwig\b|\bfreemarker\b", "template injection (SSTI)"),
        (r"\brequest.?smuggling\b|\bhttp.?desync\b|\bcl.te\b|\bte.cl\b", "HTTP request smuggling"),
        (r"\bcache.?poison\b", "cache poisoning"),
        (r"\bcache.?deception\b", "cache deception"),
        (r"\bhost.?header\b", "host header injection"),
        (r"\bcrlf\b|\bheader.?injection\b|\bresponse.?split\b", "CRLF/header injection"),
        (r"\bxxe\b|\bxml.?external\b|\bxml.?entity\b", "XXE"),
        (r"\bidns?\b|\bhomograph\b|\bpunycode\b", "IDN/homograph attack"),
        (r"\bclickjack\b|\bui.?redress\b|\bframe\b.*\bjack\b", "clickjacking/UI redressing"),
        (r"\bsubdomain.?takeover\b|\bdangling.?cname\b", "subdomain takeover"),
        (r"\baccount.?takeover\b|\bato\b", "account takeover"),
        (r"\bprivilege.?escalation\b|\bprivesc\b|\bescalat\b.*\bprivileg\b", "privilege escalation"),
    ],

    # ── Bypass Methods (how to evade defenses) ──
    "bypasses": [
        (r"\bwaf\b|\bfirewall\b|\bbypass\b.*\bwaf\b|\bwaf\b.*\bbypass\b", "WAF bypass"),
        (r"\bcsp\b.*\bbypass\b|\bbypass\b.*\bcsp\b|\bcontent.?security.?policy\b", "CSP bypass"),
        (r"\bcors\b.*\bbypass\b|\bbypass\b.*\bcors\b", "CORS bypass"),
        (r"\bsame.?origin\b.*\bbypass\b|\bbypass\b.*\bsame.?origin\b", "SOP bypass"),
        (r"\bsandbox\b.*\b(?:bypass|escap)\b", "sandbox escape"),
        (r"\bfilter\b.*\b(?:bypass|evasion)\b|\bbypass\b.*\bfilter\b", "filter bypass/evasion"),
        (r"\brate.?limit\b.*\bbypass\b|\bbypass\b.*\brate.?limit\b", "rate limit bypass"),
        (r"\b(?:2fa|mfa|otp)\b.*\bbypass\b|\bbypass\b.*\b(?:2fa|mfa|otp)\b", "2FA/MFA bypass"),
        (r"\bauth\w*\b.*\bbypass\b|\bbypass\b.*\bauth\w*\b", "authentication bypass"),
        (r"\bauthoriz\w*\b.*\bbypass\b|\bbypass\b.*\bauthoriz\w*\b", "authorization bypass"),
        (r"\bip\b.*\b(?:restrict|whitelist|block)\b.*\bbypass\b", "IP restriction bypass"),
        (r"\bencod\b|\bdouble.?encod\b|\bunicode\b|\butf-?\d\b|\bhex\b", "encoding bypass (URL, double, unicode, hex)"),
        (r"\bnull.?byte\b|\b%00\b", "null byte injection"),
        (r"\bcase\b.*\b(?:sensitiv|bypass)\b|\bupper\b|\blower\b", "case manipulation"),
        (r"\btruncation\b|\boverlong\b", "string truncation/overlong encoding"),
        (r"\bip\b.*\b(?:spoof|bypass)\b|\b(?:127|0x7f|localhost|0\.0\.0\.0)\b", "IP address bypass (decimal, hex, octal)"),
        (r"\bprotocol\b.*\bsmuggl\b|\bscheme\b.*\bbypass\b", "protocol/scheme bypass"),
        (r"\bpath\b.*\bnormali[sz]\b|\bdouble\b.*\bslash\b|\b\.\.[\\/]\b", "path normalization bypass"),
        (r"\bhttp\b.*\bmethod\b.*\boverride\b|\b_method\b", "HTTP method override"),
    ],

    # ── Contexts (WHERE in the app) ──
    "contexts": [
        (r"\blogin\b|\bsign.?in\b|\bauthenticat\b", "login/authentication flow"),
        (r"\bregistr\b|\bsign.?up\b|\bcreate.?account\b", "registration/signup"),
        (r"\bpassword\b.*\breset\b|\bforgot\b.*\bpassword\b|\breset\b.*\bpassword\b", "password reset flow"),
        (r"\boauth\b|\boidc\b|\bsso\b|\bsaml\b|\bcas\b", "OAuth/SSO/SAML flow"),
        (r"\badmin\b|\bmanagement\b|\bdashboard\b|\bpanel\b|\bbackend\b", "admin/management panel"),
        (r"\bapi\b(?!.*\bgraph)|\bendpoint\b|\brest\b", "REST API endpoints"),
        (r"\bmobile\b|\bandroid\b|\bios\b|\bapk\b|\bdeeplink\b", "mobile app/deeplinks"),
        (r"\bpayment\b|\bbilling\b|\bcheckout\b|\bstripe\b|\binvoice\b|\bsubscription\b", "payment/billing"),
        (r"\bnotification\b|\bpush\b|\balert\b", "notification system"),
        (r"\bci\b.*\bcd\b|\bpipeline\b|\bgithub.?action\b|\bjenkins\b|\bgitlab.?ci\b", "CI/CD pipeline"),
        (r"\bcloud\b|\baws\b|\bs3\b|\bgcp\b|\bazure\b|\blambda\b|\bec2\b", "cloud infrastructure"),
        (r"\bkubernetes\b|\bk8s\b|\bdocker\b|\bcontainer\b|\bhelm\b", "container/orchestration"),
        (r"\binternal\b|\bintranet\b|\b(?:10|172|192)\.\d+\.\d+\.\d+\b|\blocalhost\b", "internal network/services"),
        (r"\bmetadata\b|\b169\.254\b|\bimds\b|\bcloud.?metadata\b", "cloud metadata service"),
        (r"\bactive.?storage\b|\bs3.?bucket\b|\bblob\b|\bstorage\b", "object storage"),
        (r"\bexport\b|\breport\b|\bpdf\b.*\bgenerat\b", "export/report generation"),
    ],

    # ── Impact/Escalation Chains ──
    "escalations": [
        (r"\b(?:leads?\s+to|chain\w*|escala\w+\s+to|→|->)\b.*\brce\b|\brce\b", "escalation to RCE"),
        (r"\b(?:leads?\s+to|chain|→|->)\b.*\baccount.?takeover\b", "escalation to account takeover"),
        (r"\b(?:leads?\s+to|chain|→|->)\b.*\b(?:data|info)\b.*\b(?:leak|disclos|exfil)\b", "escalation to data exfiltration"),
        (r"\b(?:leads?\s+to|chain|→|->)\b.*\bssrf\b", "chained to SSRF"),
        (r"\baws\b.*\bkey\b|\baws\b.*\bcredential\b|\baccess.?key\b|\bsecret.?key\b", "cloud credential exposure"),
        (r"\btoken\b.*\b(?:leak|expos|disclos)\b|\b(?:leak|expos|disclos)\b.*\btoken\b", "token/secret leakage"),
        (r"\bsource.?code\b.*\b(?:disclos|leak|read)\b", "source code disclosure"),
        (r"\bpii\b|\bpersonal\b.*\bdata\b|\buser\b.*\bdata\b.*\b(?:leak|expos)\b", "PII exposure"),
        (r"\bfull.?read\b|\b(?:local|remote)\b.*\bfile\b.*\b(?:read|inclus)\b", "arbitrary file read"),
        (r"\bremote\b.*\bcode\b.*\bexecut\b|\brce\b", "remote code execution"),
    ],

    # ── Technology-Specific Vectors ──
    "tech_vectors": [
        (r"\bnode\.?js\b|\bnpm\b|\bexpress\b", "Node.js/npm ecosystem"),
        (r"\brails\b|\bruby\b|\berb\b", "Ruby on Rails"),
        (r"\bdjango\b|\bflask\b|\bpython\b", "Python/Django/Flask"),
        (r"\bphp\b|\blaravel\b|\bwordpress\b|\bsymfon\b", "PHP/Laravel/WordPress"),
        (r"\bjava\b|\bspring\b|\btomcat\b|\bjndi\b", "Java/Spring"),
        (r"\b\.net\b|\basp\.net\b|\bazure\b.*\bfunc\b", ".NET/ASP.NET"),
        (r"\bnginx\b|\bapache\b|\biis\b|\bcaddy\b", "web server specific"),
        (r"\bredis\b|\bmemcache\b|\belastic\b|\bmongo\b|\bpostgre\b|\bmysql\b|\bclickhouse\b", "specific database/cache"),
        (r"\bsentry\b|\bgrafana\b|\bkibana\b|\bjenkins\b|\bjira\b|\bconfluence\b", "specific product/tool"),
        (r"\bgit\b(?!hub)|\b\.git\b|\bgitlab\b", "git/version control exposure"),
        (r"\boauth\b.*\b(?:token|code|implicit)\b|\bjwt\b|\bjwk\b|\bjwe\b", "JWT/OAuth token handling"),
        (r"\bwasm\b|\bservice.?worker\b|\bweb.?worker\b", "browser APIs (WASM, SW)"),
    ],
}


def download_csv(csv_path=None):
    if csv_path and os.path.exists(csv_path):
        with open(csv_path, "r", encoding="utf-8") as f:
            return f.read()
    req = urllib.request.Request(CSV_URL, headers={"User-Agent": "julius-intel-generator/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


def parse_csv(raw_csv):
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


# Reuse category map from intel generator
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
        "vuln_types": ["cross-site scripting", "xss"],
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
        "vuln_types": ["improper access control", "insecure direct object reference", "idor", "broken access control", "authorization bypass"],
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
        "vuln_types": ["improper authentication", "authentication bypass", "missing authentication"],
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


def match_report_to_category(report, vuln_types, title_keywords):
    vt = report["vuln_type"].lower()
    title = report["title"].lower()
    for pattern in vuln_types:
        if pattern.lower() in vt:
            return True
    for kw in title_keywords:
        if kw.lower() in title:
            return True
    return False


def extract_techniques(reports, taxonomy):
    """Extract technique patterns from a set of reports."""
    results = {}
    for dimension, patterns in taxonomy.items():
        dimension_hits = defaultdict(list)
        for report in reports:
            title = report["title"]
            for regex, label, *_ in patterns:
                if re.search(regex, title, re.IGNORECASE):
                    dimension_hits[label].append(report)
        results[dimension] = dimension_hits
    return results


def score_report(r):
    """Impact score for sorting."""
    return r["bounty"] * 0.4 + r["upvotes"] * 0.6


def generate_techniques_md(folder, reports, techniques):
    """Generate actionable technique file for executor consumption."""
    category_name = folder.split("/")[-1].replace("-", " ").title()
    total = len(reports)

    lines = []
    lines.append(f"# Real-World Techniques: {category_name}")
    lines.append(f"<!-- Auto-generated from {total} disclosed HackerOne reports | {datetime.now().strftime('%Y-%m-%d')} -->")
    lines.append(f"<!-- These patterns come from successful bug bounty reports — use them to guide testing priorities -->")
    lines.append("")

    # ── Injection Points ──
    ip_data = techniques.get("injection_points", {})
    if ip_data:
        lines.append("## Where to Inject (by frequency in successful reports)")
        ranked = sorted(ip_data.items(), key=lambda x: -len(x[1]))
        for label, hits in ranked:
            pct = round(len(hits) / total * 100)
            if pct < 2:
                continue
            # Get best example
            best = max(hits, key=score_report)
            report_id = best["link"].split("/")[-1] if "/" in best["link"] else ""
            lines.append(f"- **{label}** — {pct}% ({len(hits)} reports)")
            lines.append(f"  - Example: [{best['title'][:70]}](https://hackerone.com/reports/{report_id})")
            # Show bounty signal
            paid = [h for h in hits if h["bounty"] > 0]
            if paid:
                avg_b = sum(h["bounty"] for h in paid) / len(paid)
                lines.append(f"  - Avg bounty: ${avg_b:,.0f} ({len(paid)} paid)")
        lines.append("")

    # ── Attack Techniques ──
    tech_data = techniques.get("techniques", {})
    if tech_data:
        lines.append("## How to Exploit (techniques from successful reports)")
        ranked = sorted(tech_data.items(), key=lambda x: -len(x[1]))
        for label, hits in ranked:
            if len(hits) < 2:
                continue
            pct = round(len(hits) / total * 100)
            best = max(hits, key=score_report)
            report_id = best["link"].split("/")[-1] if "/" in best["link"] else ""
            bounty_str = f"${best['bounty']:,.0f}" if best["bounty"] > 0 else "no bounty"
            lines.append(f"- **{label}** — {len(hits)} reports ({pct}%)")
            lines.append(f"  - Top: [{best['title'][:70]}](https://hackerone.com/reports/{report_id}) ({bounty_str})")
        lines.append("")

    # ── Bypass Methods ──
    bypass_data = techniques.get("bypasses", {})
    if bypass_data:
        active_bypasses = {k: v for k, v in bypass_data.items() if len(v) >= 2}
        if active_bypasses:
            lines.append("## Defense Bypasses (used in successful reports)")
            ranked = sorted(active_bypasses.items(), key=lambda x: -len(x[1]))
            for label, hits in ranked:
                best = max(hits, key=score_report)
                report_id = best["link"].split("/")[-1] if "/" in best["link"] else ""
                lines.append(f"- **{label}** — {len(hits)} reports")
                lines.append(f"  - Example: [{best['title'][:70]}](https://hackerone.com/reports/{report_id})")
            lines.append("")

    # ── Application Contexts ──
    ctx_data = techniques.get("contexts", {})
    if ctx_data:
        lines.append("## Application Contexts (where vulns were found)")
        ranked = sorted(ctx_data.items(), key=lambda x: -len(x[1]))
        for label, hits in ranked:
            if len(hits) < 2:
                continue
            pct = round(len(hits) / total * 100)
            lines.append(f"- **{label}** — {pct}% ({len(hits)} reports)")
        lines.append("")

    # ── Escalation Chains ──
    esc_data = techniques.get("escalations", {})
    if esc_data:
        active_esc = {k: v for k, v in esc_data.items() if len(v) >= 1}
        if active_esc:
            lines.append("## Escalation Chains (how researchers increased impact)")
            ranked = sorted(active_esc.items(), key=lambda x: -max(score_report(r) for r in x[1]))
            for label, hits in ranked:
                best = max(hits, key=score_report)
                report_id = best["link"].split("/")[-1] if "/" in best["link"] else ""
                bounty_str = f"${best['bounty']:,.0f}" if best["bounty"] > 0 else ""
                lines.append(f"- **{label}** — {len(hits)} reports")
                lines.append(f"  - [{best['title'][:70]}](https://hackerone.com/reports/{report_id}) {bounty_str}")
            lines.append("")

    # ── Technology-Specific Vectors ──
    tv_data = techniques.get("tech_vectors", {})
    if tv_data:
        active_tv = {k: v for k, v in tv_data.items() if len(v) >= 2}
        if active_tv:
            lines.append("## Technology-Specific Vectors")
            ranked = sorted(active_tv.items(), key=lambda x: -len(x[1]))
            for label, hits in ranked:
                lines.append(f"- **{label}** — {len(hits)} reports")
            lines.append("")

    # ── High-Value Technique Combinations ──
    # Find reports that match multiple technique dimensions — these are the most instructive
    lines.append("## High-Value Reports (multi-technique, study for methodology)")
    multi_tech = defaultdict(set)
    for dimension, dim_data in techniques.items():
        for label, hits in dim_data.items():
            for h in hits:
                multi_tech[h["link"]].add(f"{dimension}:{label}")

    multi_reports = []
    for link, tags in multi_tech.items():
        if len(tags) >= 3:
            report = next((r for r in reports if r["link"] == link), None)
            if report:
                multi_reports.append((report, tags))

    multi_reports.sort(key=lambda x: score_report(x[0]), reverse=True)
    for report, tags in multi_reports[:10]:
        report_id = report["link"].split("/")[-1] if "/" in report["link"] else ""
        bounty_str = f"${report['bounty']:,.0f}" if report["bounty"] > 0 else "-"
        tag_summary = ", ".join(t.split(":")[1] for t in sorted(tags)[:4])
        lines.append(f"- [{report['title'][:75]}](https://hackerone.com/reports/{report_id})")
        lines.append(f"  - {bounty_str} | {report['upvotes']} upvotes | Techniques: {tag_summary}")

    lines.append("")
    lines.append("## Executor Guidance")
    lines.append("1. Start with the highest-frequency injection points listed above")
    lines.append("2. Apply the most common techniques for this category")
    lines.append("3. If blocked, try the bypass methods in order of frequency")
    lines.append("4. Check the escalation chains — even a low-severity finding can become high/critical")
    lines.append("5. Study the high-value multi-technique reports for advanced methodology")

    return "\n".join(lines) + "\n"


def main():
    csv_path = None
    if "--csv" in sys.argv:
        idx = sys.argv.index("--csv")
        if idx + 1 < len(sys.argv):
            csv_path = sys.argv[idx + 1]

    print("[*] Loading report data...")
    raw_csv = download_csv(csv_path)
    reports = parse_csv(raw_csv)
    print(f"[+] Parsed {len(reports):,} reports")

    # Categorize reports
    categorized = defaultdict(list)
    for report in reports:
        for folder, rules in CATEGORY_MAP.items():
            if match_report_to_category(report, rules["vuln_types"], rules["title_keywords"]):
                categorized[folder].append(report)

    print(f"[+] Mapped to {len(categorized)} categories")

    # Extract techniques per category and generate files
    generated = 0
    total_techniques = 0
    for folder, cat_reports in sorted(categorized.items()):
        target_dir = ATTACKS_DIR / folder
        if not target_dir.exists():
            continue

        techniques = extract_techniques(cat_reports, TECHNIQUE_PATTERNS)
        content = generate_techniques_md(folder, cat_reports, techniques)

        tech_path = target_dir / "hackerone-techniques.md"
        tech_path.write_text(content, encoding="utf-8")
        generated += 1

        # Count unique techniques found
        n_techs = sum(len(v) for dim in techniques.values() for v in dim.values() if len(v) >= 2)
        total_techniques += n_techs
        print(f"  [+] {folder}: {len(cat_reports)} reports → {n_techs} technique signals → {tech_path.name}")

    print(f"\n=== Summary ===")
    print(f"Technique files generated: {generated}")
    print(f"Total technique signals extracted: {total_techniques:,}")
    print(f"Dimensions analyzed: {len(TECHNIQUE_PATTERNS)} (injection points, techniques, bypasses, contexts, escalations, tech vectors)")


if __name__ == "__main__":
    main()
