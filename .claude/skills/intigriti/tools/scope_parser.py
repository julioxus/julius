"""
Intigriti Scope Parser

Fetches and parses Intigriti domain-based scope from the API.
Always uses the Intigriti API for scope retrieval - never hardcoded data.

Requires INTIGRITI_TOKEN environment variable to be set.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Optional

API_BASE = "https://api.intigriti.com/external/researcher/v1"


def get_token() -> str:
    """
    Get the Intigriti API token from environment.

    Raises:
        SystemExit: If INTIGRITI_TOKEN is not set.
    """
    token = os.environ.get("INTIGRITI_TOKEN", "").strip()
    if not token:
        print("ERROR: INTIGRITI_TOKEN environment variable is not set.")
        print("Set it with: export INTIGRITI_TOKEN=<your_bearer_token>")
        print("Generate a token at: https://app.intigriti.com/researcher/settings/api")
        sys.exit(1)
    return token


def api_request(endpoint: str, token: Optional[str] = None) -> dict:
    """
    Make an authenticated GET request to the Intigriti API using curl.

    Args:
        endpoint: API path (appended to base URL)
        token: Bearer token (reads from env if not provided)

    Returns:
        Parsed JSON response

    Raises:
        SystemExit: If token is missing or request fails.
    """
    if token is None:
        token = get_token()

    url = f"{API_BASE}/{endpoint.lstrip('/')}"
    result = subprocess.run(
        ["curl", "-s", "-w", "\n%{http_code}", "-H", f"Authorization: Bearer {token}", "-H", "Content-Type: application/json", url],
        capture_output=True, text=True, timeout=30
    )

    lines = result.stdout.strip().rsplit("\n", 1)
    if len(lines) != 2:
        print(f"ERROR: Unexpected API response from {url}")
        sys.exit(1)

    body, status_code = lines[0], lines[1]

    if status_code == "401" or status_code == "403":
        print(f"ERROR: Authentication failed (HTTP {status_code}). Token may be invalid or expired.")
        print("Generate a new token at: https://app.intigriti.com/researcher/settings/api")
        sys.exit(1)

    if not status_code.startswith("2"):
        print(f"ERROR: API request failed with HTTP {status_code}: {body[:200]}")
        sys.exit(1)

    return json.loads(body)


def fetch_program_scope(program_id: str, token: Optional[str] = None) -> List[Dict[str, any]]:
    """
    Fetch and parse program scope directly from the Intigriti API.

    Args:
        program_id: Intigriti program UUID
        token: Bearer token (reads from env if not provided)

    Returns:
        List of in-scope domain dicts sorted by tier
    """
    data = api_request(f"program/{program_id}/domain", token)
    return parse_scope(data)


def fetch_program_details(program_id: str, token: Optional[str] = None) -> dict:
    """
    Fetch program details (rules, bounty table, etc.) from the API.

    Args:
        program_id: Intigriti program UUID
        token: Bearer token (reads from env if not provided)

    Returns:
        Program details dict
    """
    return api_request(f"program/{program_id}", token)


def parse_scope(data: dict) -> List[Dict[str, any]]:
    """
    Parse Intigriti program scope from API response.

    Args:
        data: JSON response from GET /core/researcher/program/{id}/domain

    Returns:
        List of in-scope domain dicts sorted by tier (1=highest priority)
    """
    domains = data.get("domains", [])
    in_scope = []

    for domain in domains:
        if not domain.get("inScope", False):
            continue

        asset = {
            "id": domain.get("id", ""),
            "domain": domain.get("domain", "").strip(),
            "type": domain.get("type", "web_application").strip(),
            "tier": domain.get("tier", 5),
            "description": domain.get("description", "").strip(),
        }

        if not asset["domain"]:
            continue

        in_scope.append(asset)

    # Sort by tier (1 = highest priority)
    in_scope.sort(key=lambda d: d["tier"])
    return in_scope


def parse_scope_file(json_path: str) -> List[Dict[str, any]]:
    """
    Parse scope from a saved JSON file.

    Args:
        json_path: Path to JSON file with API response
    """
    path = Path(json_path)
    if not path.exists():
        raise FileNotFoundError(f"Scope file not found: {json_path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return parse_scope(data)


def generate_summary(assets: List[Dict[str, any]]) -> str:
    """Generate summary of parsed scope."""
    total = len(assets)
    by_tier = {}
    by_type = {}

    for asset in assets:
        tier = asset["tier"]
        by_tier[tier] = by_tier.get(tier, 0) + 1
        atype = asset["type"]
        by_type[atype] = by_type.get(atype, 0) + 1

    summary = f"Total in-scope domains: {total}\n\nBy tier:\n"
    for tier in sorted(by_tier.keys()):
        summary += f"  Tier {tier}: {by_tier[tier]}\n"

    summary += "\nBy type:\n"
    for atype, count in sorted(by_type.items()):
        summary += f"  {atype}: {count}\n"

    return summary


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python scope_parser.py --api <program_id>   # Fetch from API (recommended)")
        print("  python scope_parser.py <scope.json>          # Parse local file")
        sys.exit(1)

    try:
        if sys.argv[1] == "--api":
            if len(sys.argv) < 3:
                print("ERROR: Program ID required. Usage: python scope_parser.py --api <program_id>")
                sys.exit(1)
            program_id = sys.argv[2]
            print(f"Fetching scope from Intigriti API for program: {program_id}")
            assets = fetch_program_scope(program_id)
        else:
            assets = parse_scope_file(sys.argv[1])

        print(generate_summary(assets))
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
