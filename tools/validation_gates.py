#!/usr/bin/env python3
"""
Validation Gates — mandatory checks before any finding submission.

Consolidates:
- 5-gate infrastructure/evidence validation
- Never-Submit Table (conditional hard blocks)
- CVSS consistency check
- Output path validation

Referenced by: /bounty-validation, /hackerone, /intigriti, /bugcrowd, /pentest
"""

import os
import re
from typing import Dict, List, Optional


class ValidationError(Exception):
    """Raised when a validation gate fails."""
    pass


# ── Never-Submit Table ────────────────────────────────────────

NEVER_SUBMIT_TABLE: List[Dict] = [
    {"type": "open_redirect", "label": "Open Redirect",
     "block_if": "Standalone, no chain",
     "valid_when": "Chained with OAuth/SSO token theft -> ATO demonstrated"},
    {"type": "cors_misconfig", "label": "CORS Misconfiguration",
     "block_if": "No data exfil PoC",
     "valid_when": "Credentialed cross-origin fetch extracts real user data"},
    {"type": "cors_3xx", "label": "CORS on 3xx Response",
     "block_if": "Redirect-only response",
     "valid_when": "Same CORS on 200 authenticated response + data exfil"},
    {"type": "missing_headers", "label": "Missing Security Headers",
     "block_if": "CSP/HSTS/X-Frame absent without exploit",
     "valid_when": "Absence enables specific exploit (XSS fires because no CSP)"},
    {"type": "version_disclosure", "label": "Version Disclosure",
     "block_if": "Server banner, X-Powered-By only",
     "valid_when": "Version maps to exploitable CVE with working PoC"},
    {"type": "stack_trace", "label": "Stack Trace / Debug Info",
     "block_if": "Error pages with paths only",
     "valid_when": "Leaked info enables follow-up exploitation"},
    {"type": "self_xss", "label": "Self-XSS",
     "block_if": "Only fires in own session",
     "valid_when": "Chained with CSRF/login CSRF to fire in victim session"},
    {"type": "csrf_logout", "label": "CSRF on Logout",
     "block_if": "Log out another user only",
     "valid_when": "Chained with login CSRF -> session fixation -> ATO"},
    {"type": "csrf_nonsensitive", "label": "CSRF on Non-Sensitive Form",
     "block_if": "Language/theme change",
     "valid_when": "Form changes security-critical state (email, password, 2FA)"},
    {"type": "username_enum", "label": "Username Enumeration",
     "block_if": "Different error messages only",
     "valid_when": "Enables credential stuffing with demonstrated account compromise"},
    {"type": "rate_limit", "label": "Rate Limit Absence",
     "block_if": "No rate limit on endpoint only",
     "valid_when": "Brute-force with demonstrated account compromise"},
    {"type": "clickjacking", "label": "Clickjacking",
     "block_if": "Non-sensitive page framed",
     "valid_when": "Framed page has state-changing action (delete, transfer)"},
    {"type": "internal_ip", "label": "Info Disclosure (Internal IP)",
     "block_if": "Private IPs in headers only",
     "valid_when": "Internal IP enables SSRF pivot with response data"},
    {"type": "email_spoofing", "label": "Email Spoofing",
     "block_if": "Missing SPF/DKIM/DMARC only",
     "valid_when": "Spoofed email delivered to major provider + phishing chain"},
    {"type": "subdomain_takeover", "label": "Subdomain Takeover",
     "block_if": "Dangling CNAME only",
     "valid_when": "Claimed subdomain serves attacker-controlled content"},
    {"type": "host_header", "label": "Host Header Injection",
     "block_if": "Reflected in response only",
     "valid_when": "Password reset poisoning or cache poisoning PoC"},
    {"type": "weak_tls", "label": "Expired/Weak TLS",
     "block_if": "TLS 1.0/weak ciphers only",
     "valid_when": "Demonstrated MITM or downgrade attack PoC"},
]

# Mapping from common vuln description keywords to table types
_VULN_KEYWORD_MAP = {
    "open redirect": "open_redirect",
    "redirect": "open_redirect",
    "cors": "cors_misconfig",
    "cross-origin": "cors_misconfig",
    "missing header": "missing_headers",
    "missing security header": "missing_headers",
    "csp": "missing_headers",
    "hsts": "missing_headers",
    "x-frame": "missing_headers",
    "version disclosure": "version_disclosure",
    "server banner": "version_disclosure",
    "x-powered-by": "version_disclosure",
    "stack trace": "stack_trace",
    "debug info": "stack_trace",
    "verbose error": "stack_trace",
    "self-xss": "self_xss",
    "self xss": "self_xss",
    "csrf logout": "csrf_logout",
    "csrf non-sensitive": "csrf_nonsensitive",
    "csrf language": "csrf_nonsensitive",
    "csrf theme": "csrf_nonsensitive",
    "username enumeration": "username_enum",
    "account enumeration": "username_enum",
    "user enumeration": "username_enum",
    "rate limit": "rate_limit",
    "brute force": "rate_limit",
    "clickjacking": "clickjacking",
    "internal ip": "internal_ip",
    "private ip": "internal_ip",
    "email spoofing": "email_spoofing",
    "spf": "email_spoofing",
    "dkim": "email_spoofing",
    "dmarc": "email_spoofing",
    "subdomain takeover": "subdomain_takeover",
    "dangling cname": "subdomain_takeover",
    "host header": "host_header",
    "weak tls": "weak_tls",
    "tls 1.0": "weak_tls",
    "expired cert": "weak_tls",
}


# ── CVSS Ranges ───────────────────────────────────────────────

CVSS_RANGES = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.9),
    "medium": (4.0, 6.9),
    "low": (0.1, 3.9),
    "informational": (0.0, 0.0),
    "info": (0.0, 0.0),
    "none": (0.0, 0.0),
}


# ── Validation Gates ──────────────────────────────────────────

def check_never_submit(vuln_class: str, has_exploit_chain: bool = False) -> Optional[Dict]:
    """Check if a finding type is on the Never-Submit list.

    Returns the blocking rule if matched and chain not proven, else None.
    """
    vuln_lower = vuln_class.lower()
    matched_type = None

    for keyword, table_type in _VULN_KEYWORD_MAP.items():
        if keyword in vuln_lower:
            matched_type = table_type
            break

    if not matched_type:
        return None

    for rule in NEVER_SUBMIT_TABLE:
        if rule["type"] == matched_type:
            if has_exploit_chain:
                return None  # Chain proven, submission allowed
            return {
                "blocked": True,
                "rule": rule["label"],
                "reason": rule["block_if"],
                "required": rule["valid_when"],
            }
    return None


def check_cvss_consistency(severity: str, cvss_score: float) -> Optional[str]:
    """Verify severity label matches CVSS score. Returns error message or None."""
    sev_lower = severity.lower()
    if sev_lower not in CVSS_RANGES:
        return f"Unknown severity '{severity}'"

    min_score, max_score = CVSS_RANGES[sev_lower]
    if not (min_score <= cvss_score <= max_score):
        expected = [s for s, (lo, hi) in CVSS_RANGES.items()
                    if lo <= cvss_score <= hi and s not in ("info", "none")]
        return (f"CVSS {cvss_score} labeled '{severity}' — "
                f"should be '{expected[0].upper() if expected else 'UNKNOWN'}'")
    return None


def check_evidence_exists(evidence_path: str) -> List[str]:
    """Check required evidence files exist. Returns list of missing items."""
    missing = []
    if not evidence_path or not os.path.isdir(evidence_path):
        return ["evidence directory does not exist"]

    files = os.listdir(evidence_path) if os.path.exists(evidence_path) else []
    file_str = " ".join(files).lower()

    # Check for any evidence at all
    if not files:
        missing.append("evidence directory is empty")

    return missing


def check_poc_exists(finding_path: str) -> List[str]:
    """Check PoC files exist in finding directory. Returns missing items."""
    missing = []
    if not finding_path or not os.path.isdir(finding_path):
        return ["finding directory does not exist"]

    files = os.listdir(finding_path)
    required = {"poc.py": False, "poc_output.txt": False, "description.md": False}
    for f in files:
        if f in required:
            required[f] = True

    for name, found in required.items():
        if not found:
            missing.append(f"missing {name}")

    if "evidence" not in files and not os.path.isdir(os.path.join(finding_path, "evidence")):
        missing.append("missing evidence/ directory")

    return missing


def check_infrastructure(target_url: str, timeout: int = 10) -> Optional[str]:
    """Gate 1: Verify target is a real application, not a placeholder.

    Returns error message or None if OK.
    """
    import urllib.request
    import urllib.error

    tests = [
        f"{target_url.rstrip('/')}/",
        f"{target_url.rstrip('/')}/definitely-fake-endpoint-{os.getpid()}",
    ]

    responses = []
    for url in tests:
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "ValidationGates/1.0")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(200).decode("utf-8", errors="ignore")
                responses.append((resp.status, body))
        except urllib.error.HTTPError as e:
            responses.append((e.code, ""))
        except Exception:
            responses.append((0, ""))

    # All return identical 200 → likely placeholder
    if (len(responses) >= 2
            and all(r[0] == 200 for r in responses)
            and len(set(r[1] for r in responses)) == 1):
        return "All endpoints return identical 200 responses — likely placeholder server"

    # None respond
    if all(r[0] == 0 for r in responses):
        return "Target is unreachable"

    return None


def check_business_logic(description: str, vuln_type: str) -> Optional[str]:
    """Gate 4: Flag potential by-design behavior. Returns warning or None."""
    text = f"{description} {vuln_type}".lower()

    by_design_signals = [
        ("people search", "Exposing personal data may be the core service"),
        ("public api", "Public API access may be intentional"),
        ("public registry", "Public registry data is by design"),
        ("store locator", "Store location data is intentionally public"),
        ("documentation", "Documentation endpoints are public by design"),
        ("contact information", "Contact info is typically public"),
        ("robots.txt", "robots.txt directives are informational, not security controls"),
        ("sitemap", "Sitemaps are designed to be public"),
        ("whois", "WHOIS data is public by design"),
        ("dns record", "DNS records are public by design"),
    ]

    for signal, reason in by_design_signals:
        if signal in text:
            return f"Potential by-design: '{signal}' detected — {reason}"

    return None


# ── Output Path Validation ────────────────────────────────────

VALID_SUBDIRS = {"data", "reports", "logs", "processed", "components"}


def get_output_path(engagement: str, file_type: str, filename: str,
                    finding_id: str = "") -> str:
    """Get standardized output path."""
    base = f"outputs/{engagement}"
    if file_type == "evidence":
        if not finding_id:
            raise ValueError("finding_id required for evidence files")
        return f"{base}/reports/appendix/{finding_id}/{filename}"
    elif file_type == "finding":
        if not finding_id:
            raise ValueError("finding_id required for finding files")
        return f"{base}/processed/findings/{finding_id}/{filename}"
    elif file_type == "data":
        subtype = filename.split("-")[0] if "-" in filename else "general"
        return f"{base}/data/{subtype}/{filename}"
    elif file_type == "log":
        return f"{base}/logs/{filename}"
    return f"{base}/processed/{file_type}/{filename}"


def validate_output_path(path: str, engagement: str) -> bool:
    """Validate path follows output standards. Raises ValueError if invalid."""
    prefix = f"outputs/{engagement}/"
    if not path.startswith(prefix):
        raise ValueError(f"Path must start with {prefix}, got: {path}")

    parts = path.split("/")
    if len(parts) < 4 or parts[2] not in VALID_SUBDIRS:
        raise ValueError(f"Invalid subdirectory in path: {path}")

    if ".." in path:
        raise ValueError(f"Path traversal detected: {path}")

    return True


# ── Main Validator ────────────────────────────────────────────

class MandatoryValidator:
    """Run all validation gates before external communication."""

    @staticmethod
    def validate(finding: dict, engagement: str) -> Dict:
        """Validate a finding. Returns result dict with pass/fail and details."""
        results = {"passed": True, "gates": {}, "warnings": [], "errors": []}

        title = finding.get("title", "Unknown")
        target = finding.get("target", "")
        severity = finding.get("severity", "")
        cvss = finding.get("cvss_score", 0.0)
        vuln_type = finding.get("vuln_type", finding.get("description", ""))
        has_chain = finding.get("has_exploit_chain", False)
        finding_path = finding.get("finding_path", "")
        evidence_path = finding.get("evidence_path", "")

        # Gate 1: Never-Submit Table
        ns_result = check_never_submit(vuln_type, has_chain)
        if ns_result:
            results["gates"]["never_submit"] = "BLOCKED"
            results["errors"].append(
                f"Never-Submit: {ns_result['rule']} — {ns_result['reason']}. "
                f"Required: {ns_result['required']}")
            results["passed"] = False
        else:
            results["gates"]["never_submit"] = "PASS"

        # Gate 2: CVSS Consistency
        if severity and cvss:
            cvss_err = check_cvss_consistency(severity, cvss)
            if cvss_err:
                results["gates"]["cvss"] = "FAIL"
                results["errors"].append(f"CVSS: {cvss_err}")
                results["passed"] = False
            else:
                results["gates"]["cvss"] = "PASS"

        # Gate 3: Infrastructure Reality (only if target provided)
        if target:
            infra_err = check_infrastructure(target)
            if infra_err:
                results["gates"]["infrastructure"] = "FAIL"
                results["errors"].append(f"Infrastructure: {infra_err}")
                results["passed"] = False
            else:
                results["gates"]["infrastructure"] = "PASS"

        # Gate 4: Business Logic
        bl_warn = check_business_logic(
            finding.get("description", ""), vuln_type)
        if bl_warn:
            results["gates"]["business_logic"] = "WARNING"
            results["warnings"].append(bl_warn)
        else:
            results["gates"]["business_logic"] = "PASS"

        # Gate 5: Evidence & PoC existence
        if finding_path:
            poc_missing = check_poc_exists(finding_path)
            if poc_missing:
                results["gates"]["poc"] = "FAIL"
                results["errors"].extend(
                    [f"PoC: {m}" for m in poc_missing])
                results["passed"] = False
            else:
                results["gates"]["poc"] = "PASS"

        if evidence_path:
            ev_missing = check_evidence_exists(evidence_path)
            if ev_missing:
                results["gates"]["evidence"] = "FAIL"
                results["errors"].extend(
                    [f"Evidence: {m}" for m in ev_missing])
                results["passed"] = False
            else:
                results["gates"]["evidence"] = "PASS"

        return results

    @staticmethod
    def validate_and_raise(finding: dict, engagement: str) -> bool:
        """Validate and raise ValidationError if any gate fails."""
        result = MandatoryValidator.validate(finding, engagement)
        if not result["passed"]:
            errors = "; ".join(result["errors"])
            raise ValidationError(f"Validation failed: {errors}")
        return True


# ── CLI ───────────────────────────────────────────────────────

if __name__ == "__main__":
    import json

    # Self-test
    print("=== Never-Submit Table Tests ===")
    tests = [
        ("open redirect", False, True),   # should block
        ("open redirect with ATO", True, False),  # chain proven
        ("CORS misconfiguration", False, True),
        ("SQL Injection", False, False),   # not in table
        ("clickjacking", False, True),
        ("missing HSTS header", False, True),
    ]
    for vuln, chain, expect_block in tests:
        result = check_never_submit(vuln, chain)
        blocked = result is not None
        status = "PASS" if blocked == expect_block else "FAIL"
        print(f"  {status}: '{vuln}' chain={chain} -> "
              f"{'BLOCKED' if blocked else 'ALLOWED'}")

    print("\n=== CVSS Consistency Tests ===")
    cvss_tests = [
        ("Critical", 9.5, None),
        ("High", 5.3, "error"),  # should fail
        ("Medium", 5.3, None),
        ("Low", 3.0, None),
    ]
    for sev, score, expect in cvss_tests:
        err = check_cvss_consistency(sev, score)
        status = "PASS" if (err is None) == (expect is None) else "FAIL"
        print(f"  {status}: {sev}/{score} -> {err or 'OK'}")

    print("\n=== Output Path Tests ===")
    try:
        p = get_output_path("test-eng", "evidence", "shot.png", "f-001")
        print(f"  Evidence: {p}")
        validate_output_path(p, "test-eng")
        print("  Validation: PASS")
    except ValueError as e:
        print(f"  Validation: FAIL - {e}")
