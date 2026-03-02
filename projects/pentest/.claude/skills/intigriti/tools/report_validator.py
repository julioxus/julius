"""
Intigriti Report Validator

Validates vulnerability reports meet Intigriti submission requirements.
"""

import re
from pathlib import Path
from typing import Tuple, List

VULN_TYPES = [
    "Cross-Site Scripting (XSS)", "SQL Injection", "Server-Side Request Forgery (SSRF)",
    "Remote Code Execution (RCE)", "XML External Entity (XXE)",
    "Insecure Direct Object Reference (IDOR)", "Cross-Site Request Forgery (CSRF)",
    "Authentication Bypass", "Authorization/Access Control", "Information Disclosure",
    "Open Redirect", "Server-Side Template Injection (SSTI)", "Business Logic Flaw",
    "Race Condition", "Subdomain Takeover", "DNS Misconfiguration",
    "SSL/TLS Misconfiguration", "Insecure Data Storage", "Insecure Communication",
    "Command Injection", "Path Traversal", "File Upload",
]

REQUIRED_SECTIONS = [
    "## Summary", "## Steps to Reproduce", "## Impact"
]

CVSS_V31 = r"CVSS:3\.\d+/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]"
CVSS_V40 = r"CVSS:4\.0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/VC:[NLH]/VI:[NLH]/VA:[NLH]/SC:[NLH]/SI:[NLH]/SA:[NLH]"


def validate_report(report_path: str) -> Tuple[bool, str]:
    """
    Validate an Intigriti report.

    Returns:
        Tuple of (is_valid, message)
    """
    path = Path(report_path)
    if not path.exists():
        return False, f"Report not found: {report_path}"

    content = path.read_text(encoding="utf-8")
    errors: List[str] = []
    warnings: List[str] = []

    # Check required sections
    for section in REQUIRED_SECTIONS:
        if section not in content:
            errors.append(f"Missing: {section}")

    # Check CVSS score
    has_cvss = re.search(CVSS_V31, content) or re.search(CVSS_V40, content)
    if not has_cvss:
        if "CVSS" in content:
            warnings.append("CVSS vector format may be invalid")
        else:
            errors.append("Missing CVSS vector string")

    # Check title (no URL)
    title_match = re.search(r'^# (.+)$', content, re.MULTILINE)
    if title_match:
        title = title_match.group(1)
        if re.search(r'https?://', title):
            warnings.append("Title should not contain URLs (Intigriti convention)")
    else:
        warnings.append("No title found (# heading)")

    # Check domain field
    if "**Domain**" not in content and "Domain:" not in content:
        errors.append("Missing domain field")

    # Check vulnerability type
    if "**Vulnerability Type**" not in content and "Vulnerability Type:" not in content:
        warnings.append("Missing vulnerability type field")

    # Check steps are numbered
    steps_match = re.search(r'## Steps to Reproduce(.+?)(?=##|\Z)', content, re.DOTALL)
    if steps_match and not re.search(r'^\d+\.', steps_match.group(1), re.MULTILINE):
        warnings.append("Steps should be numbered")

    # Check for sensitive data
    sensitive = [
        (r'-----BEGIN [A-Z]+ KEY-----', "private keys"),
        (r'bearer\s+[A-Za-z0-9._-]{20,}', "bearer tokens"),
    ]
    for pattern, desc in sensitive:
        if re.search(pattern, content, re.IGNORECASE):
            errors.append(f"Potential sensitive data: {desc}")

    # Build result
    if errors:
        msg = "FAILED:\n" + "\n".join(f"  - {e}" for e in errors)
    else:
        msg = "PASSED"

    if warnings:
        msg += "\nWarnings:\n" + "\n".join(f"  - {w}" for w in warnings)

    return len(errors) == 0, msg


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python report_validator.py <report.md>")
        sys.exit(1)

    valid, message = validate_report(sys.argv[1])
    print(message)
    sys.exit(0 if valid else 1)
