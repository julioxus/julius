"""
Intigriti Scope Parser

Parses Intigriti program scope from structured data (JSON files, dicts).
Scope is extracted from program pages (PDF, URL, manual input) - Intigriti
does not provide a public researcher API.

Usage:
    python scope_parser.py <scope.json>
"""

import json
import sys
from pathlib import Path
from typing import List, Dict, Optional


def parse_scope(assets: List[Dict[str, any]]) -> List[Dict[str, any]]:
    """
    Parse and normalize Intigriti program scope from a list of assets.

    Args:
        assets: List of asset dicts with keys: name, type, tier, description (optional)

    Returns:
        List of normalized asset dicts sorted by tier (1=highest priority)
    """
    parsed = []

    for asset in assets:
        entry = {
            "name": asset.get("name", asset.get("domain", "")).strip(),
            "type": asset.get("type", "web_application").strip().lower(),
            "tier": int(asset.get("tier", 5)),
            "description": asset.get("description", "").strip(),
        }

        if not entry["name"]:
            continue

        parsed.append(entry)

    # Sort by tier (1 = highest priority)
    parsed.sort(key=lambda d: d["tier"])
    return parsed


def parse_scope_file(json_path: str) -> List[Dict[str, any]]:
    """
    Parse scope from a saved JSON file.

    Expected format:
    [
        {"name": "*.example.com", "type": "web_application", "tier": 1, "description": "Main app"},
        {"name": "com.example.app", "type": "android", "tier": 2, "description": "Mobile app"}
    ]

    Args:
        json_path: Path to JSON file with scope data
    """
    path = Path(json_path)
    if not path.exists():
        raise FileNotFoundError(f"Scope file not found: {json_path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Support both list format and dict with "assets" key
    if isinstance(data, dict):
        assets = data.get("assets", data.get("domains", data.get("scope", [])))
    else:
        assets = data

    return parse_scope(assets)


def is_mobile_asset(asset: Dict[str, any]) -> bool:
    """Check if an asset is a mobile app (iOS or Android)."""
    asset_type = asset.get("type", "").lower()
    return asset_type in ("ios", "android", "mobile")


def get_mobile_assets(assets: List[Dict[str, any]]) -> List[Dict[str, any]]:
    """Filter and return only mobile assets from scope."""
    return [a for a in assets if is_mobile_asset(a)]


def get_web_assets(assets: List[Dict[str, any]]) -> List[Dict[str, any]]:
    """Filter and return non-mobile assets from scope."""
    return [a for a in assets if not is_mobile_asset(a)]


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

    summary = f"Total in-scope assets: {total}\n\nBy tier:\n"
    for tier in sorted(by_tier.keys()):
        summary += f"  Tier {tier}: {by_tier[tier]}\n"

    summary += "\nBy type:\n"
    for atype, count in sorted(by_type.items()):
        summary += f"  {atype}: {count}\n"

    mobile = get_mobile_assets(assets)
    if mobile:
        summary += f"\nMobile apps ({len(mobile)}):\n"
        for app in mobile:
            summary += f"  [{app['type'].upper()}] {app['name']} (Tier {app['tier']})\n"

    return summary


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python scope_parser.py <scope.json>   # Parse scope from JSON file")
        print()
        print("JSON format: list of {name, type, tier, description}")
        sys.exit(1)

    try:
        assets = parse_scope_file(sys.argv[1])
        print(generate_summary(assets))
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
