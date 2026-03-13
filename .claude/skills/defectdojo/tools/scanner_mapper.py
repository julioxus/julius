"""
DefectDojo Scanner Mapper

Identifies scanner output format and maps to DefectDojo import scan_type.
Used for automated scan imports via /api/v2/import-scan/ endpoint.
Supports IAP authentication via browser login cookies.
"""

import json
import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Tuple

# Import IAP auth module (same directory)
sys.path.insert(0, str(Path(__file__).parent))
from iap_browser_auth import get_iap_cookies  # noqa: E402

# File extension + content patterns → scan_type
SCANNER_SIGNATURES = {
    "nuclei": {
        "scan_type": "Nuclei Scan",
        "extensions": [".json", ".jsonl"],
        "markers": ["template-id", "matcher-name", "extracted-results"],
    },
    "nmap": {
        "scan_type": "Nmap XML Scan",
        "extensions": [".xml"],
        "markers": ["<nmaprun", "scanner=\"nmap\""],
    },
    "zap": {
        "scan_type": "ZAP Scan",
        "extensions": [".xml", ".json"],
        "markers": ["<OWASPZAPReport", "\"@programName\": \"ZAP\""],
    },
    "burp": {
        "scan_type": "Burp REST API",
        "extensions": [".xml", ".json"],
        "markers": ["<issues burpVersion", "\"issue_type\""],
    },
    "trivy": {
        "scan_type": "Trivy Scan",
        "extensions": [".json"],
        "markers": ["\"SchemaVersion\"", "\"Vulnerabilities\"", "\"Target\""],
    },
    "semgrep": {
        "scan_type": "Semgrep JSON Report",
        "extensions": [".json"],
        "markers": ["\"results\"", "\"check_id\"", "semgrep"],
    },
    "prowler": {
        "scan_type": "Prowler",
        "extensions": [".json", ".csv"],
        "markers": ["StatusExtended", "ResourceArn", "Prowler"],
    },
    "nikto": {
        "scan_type": "Nikto Scan",
        "extensions": [".xml", ".json"],
        "markers": ["<niktoscan", "\"host\"", "\"ip\""],
    },
    "sslyze": {
        "scan_type": "SSLyze 3 Scan (JSON)",
        "extensions": [".json"],
        "markers": ["\"server_scan_results\"", "sslyze"],
    },
    "generic_csv": {
        "scan_type": "Generic Findings Import",
        "extensions": [".csv"],
        "markers": ["Date", "Title", "Severity"],
    },
}


def detect_scanner(file_path: str) -> Optional[Tuple[str, str]]:
    """
    Detect scanner type from file content.

    Returns:
        Tuple of (scanner_name, scan_type) or None if unrecognized.
    """
    path = Path(file_path)
    if not path.exists():
        return None

    ext = path.suffix.lower()
    content = path.read_text(encoding="utf-8", errors="ignore")[:5000]

    for scanner, sig in SCANNER_SIGNATURES.items():
        if ext not in sig["extensions"]:
            continue
        matches = sum(1 for m in sig["markers"] if m.lower() in content.lower())
        if matches >= 2 or (matches >= 1 and len(sig["markers"]) <= 2):
            return (scanner, sig["scan_type"])

    return None


def generate_import_command(file_path: str, scan_type: str,
                            engagement_id: int) -> str:
    """Generate curl command for DefectDojo scan import.

    Includes IAP cookie file if available.
    """
    iap_cookie_arg = ""
    cookie_file = get_iap_cookies()
    if cookie_file:
        iap_cookie_arg = f'  -b "{cookie_file}" \\\n'
    return (
        f'curl -X POST "$DEFECTDOJO_URL/api/v2/import-scan/" \\\n'
        f'  -H "Authorization: Token $DEFECTDOJO_TOKEN" \\\n'
        f'{iap_cookie_arg}'
        f'  -F "scan_type={scan_type}" \\\n'
        f'  -F "file=@{file_path}" \\\n'
        f'  -F "engagement={engagement_id}" \\\n'
        f'  -F "active=true" \\\n'
        f'  -F "verified=false"'
    )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner_mapper.py <scan_output_file> [engagement_id]")
        print("\nSupported formats:")
        for name, sig in SCANNER_SIGNATURES.items():
            print(f"  {name}: {sig['scan_type']} ({', '.join(sig['extensions'])})")
        sys.exit(1)

    file_path = sys.argv[1]
    engagement_id = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    result = detect_scanner(file_path)
    if result:
        scanner, scan_type = result
        print(f"Detected: {scanner}")
        print(f"DefectDojo scan_type: {scan_type}")
        if engagement_id:
            print(f"\nImport command:")
            print(generate_import_command(file_path, scan_type, engagement_id))
    else:
        print(f"Could not identify scanner format for: {file_path}")
        print("Use 'Generic Findings Import' for manual CSV/JSON import.")
        sys.exit(1)
