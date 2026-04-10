"""Unified interface for querying bug bounty platforms (Intigriti & HackerOne)."""

from __future__ import annotations

import base64
import json
import urllib.request
import urllib.error
from typing import Any

from bounty_intel.config import settings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_INTIGRITI_BASE = "https://api.intigriti.com/external/researcher/v1"
_HACKERONE_BASE = "https://api.hackerone.com/v1"
_BUGCROWD_BASE = "https://api.bugcrowd.com"


def _api_get(url: str, headers: dict[str, str]) -> dict[str, Any] | None:
    """Perform a GET request and return parsed JSON, or None on failure."""
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError) as exc:
        print(f"[platforms] request failed for {url}: {exc}")
        return None


def _intigriti_headers() -> dict[str, str]:
    pat = settings.intigriti_pat
    return {
        "Authorization": f"Bearer {pat}",
        "Accept": "application/json",
    }


def _hackerone_headers() -> dict[str, str]:
    creds = base64.b64encode(
        f"{settings.hackerone_username}:{settings.hackerone_api_token}".encode()
    ).decode()
    return {
        "Authorization": f"Basic {creds}",
        "Accept": "application/json",
    }


def _bugcrowd_headers() -> dict[str, str]:
    return {
        "Authorization": f"Token {settings.bugcrowd_token}",
        "Accept": "application/vnd.bugcrowd+json",
        "User-Agent": "BountyIntel/1.0",
    }


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

def _safe_dict_value(d: Any, key: str = "value", default: str = "") -> str:
    """Extract a value from a dict field that may be None or missing."""
    if isinstance(d, dict):
        return str(d.get(key, default))
    return default


def _normalize_intigriti_program(raw: dict[str, Any]) -> dict[str, Any]:
    status_val = _safe_dict_value(raw.get("status"), "value").lower()
    if status_val in ("open",):
        status = "open"
    elif status_val in ("suspended",):
        status = "suspended"
    else:
        status = status_val or "unknown"

    prog_type_id = raw.get("type", {}).get("id") if isinstance(raw.get("type"), dict) else None
    program_type = "bounty" if prog_type_id == 1 else "vdp"

    conf_raw = raw.get("confidentialityLevel", "")
    if isinstance(conf_raw, dict):
        conf_raw = _safe_dict_value(conf_raw, "value")
    conf = str(conf_raw).lower()
    if "public" in conf:
        confidentiality = "public"
    elif "invite" in conf:
        confidentiality = "invite_only"
    else:
        confidentiality = "private"

    min_bounty_raw = raw.get("minBounty")
    max_bounty_raw = raw.get("maxBounty")
    min_bounty = float(min_bounty_raw.get("value", 0)) if isinstance(min_bounty_raw, dict) else 0.0
    max_bounty = float(max_bounty_raw.get("value", 0)) if isinstance(max_bounty_raw, dict) else 0.0
    currency = _safe_dict_value(min_bounty_raw, "currency", "EUR") if isinstance(min_bounty_raw, dict) else "EUR"

    web_links = raw.get("webLinks") or {}
    url = web_links.get("detail", "") if isinstance(web_links, dict) else ""

    return {
        "platform": "intigriti",
        "platform_id": raw.get("id", ""),
        "handle": raw.get("handle", ""),
        "name": raw.get("name", ""),
        "status": status,
        "program_type": program_type,
        "confidentiality": confidentiality,
        "min_bounty": min_bounty,
        "max_bounty": max_bounty,
        "currency": currency,
        "industry": raw.get("industry", ""),
        "url": url,
    }


def _normalize_hackerone_program(raw: dict[str, Any]) -> dict[str, Any]:
    attrs = raw.get("attributes", {})
    handle = attrs.get("handle", "")
    state = attrs.get("state", "").lower()
    if state in ("public_mode", "soft_launched"):
        status = "open"
    elif state == "paused":
        status = "paused"
    else:
        status = state or "unknown"

    offers_bounties = attrs.get("offers_bounties", False)
    program_type = "bounty" if offers_bounties else "vdp"

    submission_state = attrs.get("submission_state", "")
    if submission_state == "open":
        status = "open"
    elif submission_state == "paused":
        status = "paused"

    return {
        "platform": "hackerone",
        "platform_id": handle,
        "handle": handle,
        "name": attrs.get("name", ""),
        "status": status,
        "program_type": program_type,
        "confidentiality": "public",
        "min_bounty": 0.0,
        "max_bounty": 0.0,
        "currency": attrs.get("currency", "USD"),
        "industry": "",
        "url": f"https://hackerone.com/{handle}" if handle else "",
    }


def _normalize_intigriti_scope(domain: dict[str, Any]) -> dict[str, Any]:
    type_val = _safe_dict_value(domain.get("type"), "value").lower()
    if "url" in type_val or "web" in type_val:
        asset_type = "url"
    elif "mobile" in type_val or "android" in type_val or "ios" in type_val:
        asset_type = "mobile"
    elif "api" in type_val:
        asset_type = "api"
    else:
        asset_type = type_val or "other"

    tier = _safe_dict_value(domain.get("tier"), "value", "")

    return {
        "asset_type": asset_type,
        "endpoint": domain.get("endpoint", ""),
        "tier": tier,
        "eligible_for_bounty": True,
        "description": domain.get("description", "") or "",
    }


def _normalize_hackerone_scope(raw: dict[str, Any]) -> dict[str, Any]:
    attrs = raw.get("attributes", {})
    asset_type_raw = attrs.get("asset_type", "").lower()
    if "url" in asset_type_raw:
        asset_type = "url"
    elif "mobile" in asset_type_raw or "android" in asset_type_raw or "ios" in asset_type_raw:
        asset_type = "mobile"
    elif "api" in asset_type_raw:
        asset_type = "api"
    elif asset_type_raw:
        asset_type = asset_type_raw
    else:
        asset_type = "other"

    return {
        "asset_type": asset_type,
        "endpoint": attrs.get("asset_identifier", ""),
        "tier": attrs.get("max_severity", ""),
        "eligible_for_bounty": bool(attrs.get("eligible_for_bounty", False)),
        "description": attrs.get("instruction", "") or "",
    }


# ---------------------------------------------------------------------------
# Public API — Intigriti
# ---------------------------------------------------------------------------

def search_intigriti_programs(*, status: str = "", limit: int = 50) -> list[dict]:
    """List Intigriti programs via PAT. Returns normalized dicts."""
    if not settings.intigriti_pat:
        print("[platforms] INTIGRITI_PAT not configured, skipping Intigriti search")
        return []

    url = f"{_INTIGRITI_BASE}/programs?limit={limit}&offset=0"
    data = _api_get(url, _intigriti_headers())
    if data is None:
        return []

    records = data.get("records", data) if isinstance(data, dict) else data
    if not isinstance(records, list):
        print(f"[platforms] unexpected Intigriti response format")
        return []

    programs = [_normalize_intigriti_program(r) for r in records]

    if status:
        status_lower = status.lower()
        programs = [p for p in programs if p["status"] == status_lower]

    return programs


def get_intigriti_program_detail(program_id: str) -> dict | None:
    """Get full Intigriti program detail including scope and rules."""
    if not settings.intigriti_pat:
        print("[platforms] INTIGRITI_PAT not configured")
        return None

    url = f"{_INTIGRITI_BASE}/programs/{program_id}"
    data = _api_get(url, _intigriti_headers())
    if data is None:
        return None

    program = _normalize_intigriti_program(data)

    domains_raw = data.get("domains", {})
    if isinstance(domains_raw, dict):
        domain_list = domains_raw.get("content", [])
    elif isinstance(domains_raw, list):
        domain_list = domains_raw
    else:
        domain_list = []
    program["scope"] = [_normalize_intigriti_scope(d) for d in domain_list]

    roe_raw = data.get("rulesOfEngagement", {})
    if isinstance(roe_raw, dict):
        roe_content = roe_raw.get("content", {})
        program["rules"] = roe_content.get("description", "") if isinstance(roe_content, dict) else ""
    else:
        program["rules"] = str(roe_raw) if roe_raw else ""

    return program


# ---------------------------------------------------------------------------
# Public API — HackerOne
# ---------------------------------------------------------------------------

def search_hackerone_programs(*, limit: int = 50) -> list[dict]:
    """List H1 programs the researcher has access to. Returns normalized dicts."""
    if not settings.hackerone_username or not settings.hackerone_api_token:
        print("[platforms] HackerOne credentials not configured, skipping H1 search")
        return []

    url = f"{_HACKERONE_BASE}/hackers/programs?page[size]={limit}"
    data = _api_get(url, _hackerone_headers())
    if data is None:
        return []

    raw_programs = data.get("data", [])
    if not isinstance(raw_programs, list):
        print(f"[platforms] unexpected HackerOne response format")
        return []

    return [_normalize_hackerone_program(r) for r in raw_programs]


def get_hackerone_program_scope(handle: str) -> list[dict]:
    """Get H1 structured scopes for a program."""
    if not settings.hackerone_username or not settings.hackerone_api_token:
        print("[platforms] HackerOne credentials not configured")
        return []

    url = f"{_HACKERONE_BASE}/hackers/programs/{handle}/structured_scopes?page[size]=100"
    data = _api_get(url, _hackerone_headers())
    if data is None:
        return []

    raw_scopes = data.get("data", [])
    if not isinstance(raw_scopes, list):
        print(f"[platforms] unexpected HackerOne scope response format")
        return []

    return [_normalize_hackerone_scope(s) for s in raw_scopes]


def _normalize_bugcrowd_program(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize Bugcrowd program data to unified format."""
    # Bugcrowd program status mapping
    state = raw.get("state", "").lower()
    if state in ("running", "active"):
        status = "open"
    elif state in ("paused", "suspended"):
        status = "paused"
    else:
        status = state or "unknown"

    # Determine program type
    program_type = "bounty" if raw.get("bounty_enabled", False) else "vdp"

    # Extract bounty information
    min_bounty = float(raw.get("min_payout", {}).get("cents", 0)) / 100 if raw.get("min_payout") else 0.0
    max_bounty = float(raw.get("max_payout", {}).get("cents", 0)) / 100 if raw.get("max_payout") else 0.0
    currency = raw.get("min_payout", {}).get("currency", "USD") if raw.get("min_payout") else "USD"

    # Determine visibility
    visibility = raw.get("visibility", "").lower()
    if "public" in visibility:
        confidentiality = "public"
    elif "private" in visibility or "invite" in visibility:
        confidentiality = "invite_only"
    else:
        confidentiality = "private"

    return {
        "platform": "bugcrowd",
        "platform_id": raw.get("code", ""),
        "handle": raw.get("code", ""),
        "name": raw.get("name", ""),
        "status": status,
        "program_type": program_type,
        "confidentiality": confidentiality,
        "min_bounty": min_bounty,
        "max_bounty": max_bounty,
        "currency": currency,
        "industry": raw.get("industry", ""),
        "url": raw.get("program_url", ""),
    }


def _normalize_bugcrowd_scope(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize Bugcrowd target/scope data to unified format."""
    category = raw.get("category", "").lower()
    if "website" in category or "web" in category or "url" in category:
        asset_type = "url"
    elif "mobile" in category or "android" in category or "ios" in category:
        asset_type = "mobile"
    elif "api" in category:
        asset_type = "api"
    else:
        asset_type = category or "other"

    # Bugcrowd uses priority levels
    priority = raw.get("priority", "")
    tier = str(priority).lower() if priority else ""

    return {
        "asset_type": asset_type,
        "endpoint": raw.get("name", ""),
        "tier": tier,
        "eligible_for_bounty": bool(raw.get("bounty_eligible", True)),
        "description": raw.get("description", "") or "",
    }


# ---------------------------------------------------------------------------
# Public API — Bugcrowd
# ---------------------------------------------------------------------------

def search_bugcrowd_programs(*, status: str = "", limit: int = 50, comprehensive: bool = True) -> list[dict]:
    """List Bugcrowd programs via engagements.json API. Fast, paginated, real bounty data."""
    # Primary method: JSON API (no Playwright needed, works with session cookies)
    programs = _fetch_bugcrowd_engagements_json(limit=limit)
    if programs:
        if status:
            status_lower = status.lower()
            programs = [p for p in programs if p.get("status", "").lower() == status_lower]
        print(f"[platforms] Found {len(programs)} Bugcrowd programs via JSON API")
        return programs

    # Fallback: official API (if credentials configured)
    if settings.bugcrowd_email and settings.bugcrowd_token:
        url = f"{_BUGCROWD_BASE}/programs?limit={limit}"
        data = _api_get(url, _bugcrowd_headers())
        if data is not None:
            programs_raw = data.get("programs", data) if isinstance(data, dict) else data
            if isinstance(programs_raw, list):
                programs = [_normalize_bugcrowd_program(p) for p in programs_raw]
                if status:
                    programs = [p for p in programs if p["status"] == status.lower()]
                print(f"[platforms] Found {len(programs)} programs via Bugcrowd credentials API")
                return programs

    print("[platforms] No Bugcrowd data source available")
    return _fallback_bugcrowd_programs()


def _fetch_bugcrowd_engagements_json(limit: int = 300) -> list[dict]:
    """Fetch programs from Bugcrowd's engagements.json API with pagination."""
    import json as _json
    from pathlib import Path

    # Load session cookies
    cookie_file = Path.home() / ".bugcrowd" / "session_cookies.json"
    meta_file = Path.home() / ".bugcrowd" / "session_meta.json"
    cookies = {}
    if cookie_file.exists():
        try:
            import time
            if meta_file.exists():
                meta = _json.loads(meta_file.read_text())
                if meta.get("expires_at", 0) > time.time():
                    cookies = _json.loads(cookie_file.read_text())
            else:
                cookies = _json.loads(cookie_file.read_text())
        except (_json.JSONDecodeError, KeyError):
            pass

    cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items()) if cookies else ""

    all_programs: list[dict] = []
    page = 1

    while len(all_programs) < limit:
        import urllib.request as _req
        url = (f"https://bugcrowd.com/engagements.json"
               f"?category=bug_bounty&page={page}&sort_by=promoted&sort_direction=desc")
        req = _req.Request(url)
        if cookie_header:
            req.add_header("Cookie", cookie_header)
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")

        try:
            with _req.urlopen(req, timeout=15) as resp:
                data = _json.loads(resp.read().decode())
        except Exception as e:
            print(f"[platforms] Bugcrowd JSON API error on page {page}: {e}")
            break

        engagements = data.get("engagements", [])
        if not engagements:
            break

        for eng in engagements:
            rs = eng.get("rewardSummary") or {}
            handle = (eng.get("briefUrl") or "").replace("/engagements/", "")
            if not handle:
                continue

            def _parse_amt(s):
                if not s: return 0.0
                import re
                m = re.search(r"[\d,]+", s.replace("$", ""))
                return float(m.group().replace(",", "")) if m else 0.0

            all_programs.append({
                "platform": "bugcrowd",
                "platform_id": handle,
                "handle": handle,
                "name": eng.get("name") or handle,
                "status": "open" if eng.get("accessStatus") == "open" else "closed",
                "program_type": "bounty",
                "confidentiality": "private" if eng.get("isPrivate") else "public",
                "min_bounty": _parse_amt(rs.get("minReward", "")),
                "max_bounty": _parse_amt(rs.get("maxReward", "")),
                "reward_summary": rs.get("summary", ""),
                "currency": "USD",
                "industry": eng.get("industryName") or "Unknown",
                "service_level": eng.get("serviceLevel") or "",
                "url": f"https://bugcrowd.com/engagements/{handle}",
            })

        total = data.get("paginationMeta", {}).get("totalCount", 0)
        if len(all_programs) >= total:
            break
        page += 1

    return all_programs[:limit]


def _fallback_bugcrowd_programs() -> list[dict]:
    """Fallback method for Bugcrowd program discovery when API is unavailable."""
    # Return known public programs or ask for manual input
    known_programs = [
        {
            "platform": "bugcrowd",
            "platform_id": "manual-entry",
            "handle": "manual-entry",
            "name": "Manual Program Entry",
            "status": "open",
            "program_type": "manual",
            "confidentiality": "public",
            "min_bounty": 0.0,
            "max_bounty": 0.0,
            "currency": "USD",
            "industry": "manual",
            "url": "https://bugcrowd.com/programs",
        }
    ]

    print("[platforms] Returned fallback option for manual program entry")
    print("[platforms] Use /bugcrowd manual-mode for guided setup")

    return known_programs


def get_bugcrowd_program_detail(program_code: str) -> dict | None:
    """Get full Bugcrowd program detail including scope and rules."""
    # Try engagements.json listing for basic info (fast, no Playwright)
    programs = _fetch_bugcrowd_engagements_json(limit=300)
    for p in programs:
        if p.get("handle") == program_code:
            print(f"[platforms] Got program info for {program_code} via JSON API")
            return p

    # Try official API (if credentials configured)
    if settings.bugcrowd_email and settings.bugcrowd_token:
        url = f"{_BUGCROWD_BASE}/programs/{program_code}"
        data = _api_get(url, _bugcrowd_headers())
        if data is not None:
            program = _normalize_bugcrowd_program(data)
            targets_url = f"{_BUGCROWD_BASE}/programs/{program_code}/targets"
            targets_data = _api_get(targets_url, _bugcrowd_headers())
            if targets_data:
                program["scope"] = [_normalize_bugcrowd_scope(t) for t in targets_data.get("targets", [])]
            else:
                program["scope"] = []
            program["rules"] = data.get("brief", "") or data.get("description", "")
            print(f"[platforms] Got program details for {program_code} via credentials API")
            return program

    # Fallback: scraper with Playwright for scope/rules
    try:
        import sys
        from pathlib import Path
        skill_tools = Path(__file__).parent.parent / ".claude" / "skills" / "bugcrowd" / "tools"
        if str(skill_tools) not in sys.path:
            sys.path.insert(0, str(skill_tools))
        from bugcrowd_scraper import BugcrowdScraper
        scraper = BugcrowdScraper(headless=True, authenticated=True)
        program = scraper.get_program_detail(program_code)
        if program and not program.get("manual_entry_required"):
            print(f"[platforms] Got program details for {program_code} via scraper")
            return program
    except (ImportError, Exception) as e:
        print(f"[platforms] Scraper fallback failed for {program_code}: {e}")

    print(f"[platforms] Creating manual template for {program_code}")
    return _create_manual_program_template(program_code)


def _create_manual_program_template(program_code: str) -> dict:
    """Create a manual program template for user input."""
    return {
        "platform": "bugcrowd",
        "platform_id": program_code,
        "handle": program_code,
        "name": f"Bugcrowd Program ({program_code})",
        "status": "open",
        "program_type": "bounty",
        "confidentiality": "public",
        "min_bounty": 0.0,
        "max_bounty": 0.0,
        "currency": "USD",
        "industry": "unknown",
        "url": f"https://bugcrowd.com/{program_code}",
        "scope": [],
        "rules": "Manual program entry - please provide scope and rules",
        "manual_entry_required": True,
    }


def get_bugcrowd_program_scope(program_code: str) -> list[dict]:
    """Get Bugcrowd targets/scope for a program."""
    if not settings.bugcrowd_email or not settings.bugcrowd_token:
        print("[platforms] Bugcrowd credentials not configured")
        return []

    url = f"{_BUGCROWD_BASE}/programs/{program_code}/targets"
    data = _api_get(url, _bugcrowd_headers())
    if data is None:
        return []

    raw_targets = data.get("targets", [])
    if not isinstance(raw_targets, list):
        print(f"[platforms] unexpected Bugcrowd targets response format")
        return []

    return [_normalize_bugcrowd_scope(t) for t in raw_targets]
