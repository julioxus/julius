"""
DefectDojo Finding Importer

Imports validated pentest findings into DefectDojo via API v2.
Requires DEFECTDOJO_URL and DEFECTDOJO_TOKEN environment variables.
Supports Google Cloud IAP authentication via browser login (cookie-based).
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

# Import IAP auth module (same directory)
sys.path.insert(0, str(Path(__file__).parent))
from iap_browser_auth import get_iap_cookies  # noqa: E402

# Severity → numerical_severity mapping
SEVERITY_MAP = {
    "Critical": "S0",
    "High": "S1",
    "Medium": "S2",
    "Low": "S3",
    "Info": "S4",
}


def get_config() -> tuple:
    """Get DefectDojo URL and token from environment."""
    url = os.environ.get("DEFECTDOJO_URL", "").strip().rstrip("/")
    token = os.environ.get("DEFECTDOJO_TOKEN", "").strip()
    if not url or not token:
        print("ERROR: DEFECTDOJO_URL and DEFECTDOJO_TOKEN must be set.")
        print("  export DEFECTDOJO_URL=https://defectdojo.example.com")
        print("  export DEFECTDOJO_TOKEN=<your_api_key>")
        print("\nFor IAP-protected instances, also set:")
        print("  export IAP_CLIENT_ID=<oauth2_client_id>")
        sys.exit(1)
    return url, token


def _build_auth_headers(token: str) -> list:
    """Build curl auth headers including IAP cookies if available."""
    headers = ["-H", f"Authorization: Token {token}"]
    cookie_file = get_iap_cookies()
    if cookie_file:
        headers.extend(["-b", cookie_file])
    return headers


def api_request(method: str, endpoint: str, data: Optional[dict] = None,
                url: Optional[str] = None, token: Optional[str] = None) -> dict:
    """Make authenticated request to DefectDojo API v2."""
    if url is None or token is None:
        url, token = get_config()

    full_url = f"{url}/api/v2/{endpoint.lstrip('/')}"
    cmd = ["curl", "-s", "-w", "\n%{http_code}", "-X", method]
    cmd.extend(_build_auth_headers(token))
    cmd.extend(["-H", "Content-Type: application/json"])

    if data:
        cmd.extend(["-d", json.dumps(data)])
    cmd.append(full_url)

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    lines = result.stdout.strip().rsplit("\n", 1)

    if len(lines) != 2:
        print(f"ERROR: Unexpected response from {full_url}")
        sys.exit(1)

    body, status = lines[0], lines[1]

    if status in ("401", "403"):
        has_cookies = bool(get_iap_cookies())
        if has_cookies:
            print(f"ERROR: Auth failed (HTTP {status}). IAP cookies may be expired — run: python tools/iap_browser_auth.py --clear")
        else:
            print(f"ERROR: Auth failed (HTTP {status}). Check DEFECTDOJO_TOKEN. If behind IAP, run: python tools/iap_browser_auth.py")
        sys.exit(1)

    if not status.startswith("2"):
        print(f"ERROR: API {method} {endpoint} failed (HTTP {status}): {body[:300]}")
        return {"error": True, "status": status, "body": body}

    return json.loads(body) if body else {}


def upload_file(finding_id: int, file_path: str, title: str,
                url: Optional[str] = None, token: Optional[str] = None) -> dict:
    """Upload file to a finding."""
    if url is None or token is None:
        url, token = get_config()

    full_url = f"{url}/api/v2/findings/{finding_id}/files/"
    cmd = ["curl", "-s", "-w", "\n%{http_code}", "-X", "POST"]
    cmd.extend(_build_auth_headers(token))
    cmd.extend(["-F", f"file=@{file_path}", "-F", f"title={title}", full_url])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    lines = result.stdout.strip().rsplit("\n", 1)
    if len(lines) == 2:
        body, status = lines[0], lines[1]
        if status.startswith("2"):
            return {"success": True, "file": file_path}
    return {"success": False, "file": file_path}


def parse_finding_dir(finding_path: str) -> Optional[Dict]:
    """Parse a finding directory into DefectDojo fields."""
    path = Path(finding_path)
    desc_file = path / "description.md"

    if not desc_file.exists():
        print(f"WARNING: No description.md in {finding_path}, skipping")
        return None

    content = desc_file.read_text(encoding="utf-8")

    # Extract fields from description.md
    finding = {
        "title": "",
        "severity": "Medium",
        "description": content,
        "mitigation": "",
        "impact": "",
        "steps_to_reproduce": "",
        "cwe": 0,
        "cvssv3": "",
        "active": True,
        "verified": (path / "poc.py").exists() and (path / "poc_output.txt").exists(),
        "evidence_files": [],
    }

    # Parse title from first heading
    for line in content.split("\n"):
        if line.startswith("# "):
            finding["title"] = line[2:].strip()
            break

    # Parse severity
    for line in content.split("\n"):
        if "**Severity**" in line:
            for sev in ["Critical", "High", "Medium", "Low", "Info"]:
                if sev in line:
                    finding["severity"] = sev
                    break
            break

    # Parse CVSS
    for line in content.split("\n"):
        if "**CVSS**" in line or "CVSS:3.1" in line:
            import re
            match = re.search(r"CVSS:3\.1/[^\s)]+", line)
            if match:
                finding["cvssv3"] = match.group(0)
            score_match = re.search(r"(\d+\.\d+)", line)
            if score_match:
                finding["cvssv3_score"] = float(score_match.group(1))
            break

    # Parse sections
    current_section = ""
    section_content = []
    for line in content.split("\n"):
        if line.startswith("## "):
            if current_section == "Remediation":
                finding["mitigation"] = "\n".join(section_content).strip()
            elif current_section == "Business Impact" or current_section == "Impact":
                finding["impact"] = "\n".join(section_content).strip()
            elif current_section == "Steps to Reproduce":
                finding["steps_to_reproduce"] = "\n".join(section_content).strip()
            current_section = line[3:].strip()
            section_content = []
        else:
            section_content.append(line)

    # Handle last section
    if current_section == "Remediation":
        finding["mitigation"] = "\n".join(section_content).strip()
    elif current_section in ("Business Impact", "Impact"):
        finding["impact"] = "\n".join(section_content).strip()

    # Set numerical_severity
    finding["numerical_severity"] = SEVERITY_MAP.get(finding["severity"], "S2")

    # Collect evidence files
    for f in ["poc.py", "poc_output.txt", "workflow.md"]:
        if (path / f).exists():
            finding["evidence_files"].append(str(path / f))
    evidence_dir = path / "evidence"
    if evidence_dir.exists():
        for f in evidence_dir.iterdir():
            if f.is_file():
                finding["evidence_files"].append(str(f))

    return finding


def import_finding(finding: Dict, test_id: int,
                   url: Optional[str] = None, token: Optional[str] = None) -> dict:
    """Import a single finding to DefectDojo."""
    payload = {
        "title": finding["title"],
        "severity": finding["severity"],
        "description": finding["description"],
        "mitigation": finding.get("mitigation", ""),
        "impact": finding.get("impact", ""),
        "steps_to_reproduce": finding.get("steps_to_reproduce", ""),
        "cwe": finding.get("cwe", 0),
        "cvssv3": finding.get("cvssv3", ""),
        "test": test_id,
        "active": True,
        "verified": finding.get("verified", False),
        "numerical_severity": finding.get("numerical_severity", "S2"),
    }

    if "cvssv3_score" in finding:
        payload["cvssv3_score"] = finding["cvssv3_score"]

    result = api_request("POST", "findings/", payload, url, token)

    if "error" not in result and "id" in result:
        dd_id = result["id"]
        # Upload evidence files
        for file_path in finding.get("evidence_files", []):
            title = Path(file_path).name
            upload_file(dd_id, file_path, title, url, token)
        return {"success": True, "id": dd_id, "title": finding["title"]}

    return {"success": False, "title": finding["title"], "error": result}


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python finding_importer.py <findings_dir> <test_id>")
        print("  findings_dir: path containing finding-NNN/ directories")
        print("  test_id: DefectDojo test ID to import into")
        sys.exit(1)

    findings_dir = Path(sys.argv[1])
    test_id = int(sys.argv[2])

    if not findings_dir.exists():
        print(f"ERROR: Directory not found: {findings_dir}")
        sys.exit(1)

    # Find all finding directories
    finding_dirs = sorted(findings_dir.glob("finding-*/"))
    if not finding_dirs:
        print(f"No finding-NNN/ directories found in {findings_dir}")
        sys.exit(1)

    print(f"Found {len(finding_dirs)} findings to import into test {test_id}")

    results = []
    for fdir in finding_dirs:
        finding = parse_finding_dir(str(fdir))
        if finding:
            print(f"Importing: {finding['title']} ({finding['severity']})")
            result = import_finding(finding, test_id)
            results.append(result)
            status = "OK" if result["success"] else "FAILED"
            print(f"  → {status} (DD ID: {result.get('id', 'N/A')})")

    # Summary
    success = sum(1 for r in results if r["success"])
    print(f"\nImport complete: {success}/{len(results)} findings imported")
