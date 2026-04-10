#!/usr/bin/env python3
"""
Bugcrowd Program Discovery & Detail Extraction

Primary: JSON API (engagements.json) — fast, paginated, returns bounty data.
Fallback: Playwright browser automation — for program detail/scope extraction.
"""

import json
import re
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Optional

CACHE_DIR = Path.home() / ".bugcrowd"
COOKIE_CACHE_FILE = CACHE_DIR / "session_cookies.json"

ENGAGEMENTS_API = "https://bugcrowd.com/engagements.json"
BRIEF_API = "https://bugcrowd.com/{handle}/brief.json"
BASE_URL = "https://bugcrowd.com"

# Lazy Playwright import (only needed for get_program_detail fallback)
_playwright_available = None


def _check_playwright():
    global _playwright_available
    if _playwright_available is None:
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
            _playwright_available = True
        except ImportError:
            _playwright_available = False
    return _playwright_available


def _load_cookies() -> Dict[str, str]:
    """Read cached session cookies from disk."""
    if not COOKIE_CACHE_FILE.exists():
        return {}
    try:
        import time
        meta_file = CACHE_DIR / "session_meta.json"
        if meta_file.exists():
            meta = json.loads(meta_file.read_text())
            if meta.get("expires_at", 0) < time.time():
                return {}
        return json.loads(COOKIE_CACHE_FILE.read_text())
    except (json.JSONDecodeError, KeyError):
        return {}


def _cookie_header(cookies: Dict[str, str]) -> str:
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def _api_get(url: str, cookies: Dict[str, str], timeout: int = 15) -> Optional[dict]:
    """GET a JSON endpoint with session cookies."""
    req = urllib.request.Request(url)
    if cookies:
        req.add_header("Cookie", _cookie_header(cookies))
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as e:
        print(f"[scraper] API error for {url}: {e}")
        return None


def _parse_amount(s: str) -> float:
    if not s:
        return 0.0
    m = re.search(r"[\d,]+", s.replace("$", ""))
    return float(m.group().replace(",", "")) if m else 0.0


class BugcrowdScraper:
    """Bugcrowd program discovery via JSON API + optional Playwright detail extraction."""

    def __init__(self, headless: bool = True, authenticated: bool = False):
        self.headless = headless
        self.authenticated = authenticated
        self.cookies: Dict[str, str] = {}

        if self.authenticated:
            self.cookies = _load_cookies()
            if self.cookies:
                print(f"[scraper] Loaded {len(self.cookies)} session cookies")
            else:
                print("[scraper] No valid session cookies — using public access")
                self.authenticated = False

    # ── Program listing (JSON API) ────────────────────────────

    def discover_programs(self, limit: int = 50, category: str = "bug_bounty",
                          sort_by: str = "promoted") -> List[Dict]:
        """Discover programs via engagements.json API with pagination."""
        all_engagements: List[Dict] = []
        page = 1

        while len(all_engagements) < limit:
            url = (f"{ENGAGEMENTS_API}?category={category}&page={page}"
                   f"&sort_by={sort_by}&sort_direction=desc")
            data = _api_get(url, self.cookies)
            if not data:
                break

            engagements = data.get("engagements", [])
            if not engagements:
                break

            all_engagements.extend(engagements)
            total = data.get("paginationMeta", {}).get("totalCount", 0)
            print(f"[scraper] Page {page}: {len(engagements)} programs "
                  f"({len(all_engagements)}/{total})")

            if len(all_engagements) >= total:
                break
            page += 1

        programs = [self._normalize(e) for e in all_engagements[:limit]]
        print(f"[scraper] Discovered {len(programs)} programs via JSON API")
        return programs

    def comprehensive_discovery(self, limit: int = 300) -> List[Dict]:
        """Alias for discover_programs with high limit — replaces old Playwright scan."""
        return self.discover_programs(limit=limit)

    def _normalize(self, eng: dict) -> Dict:
        """Normalize a raw engagements.json item to standard program dict."""
        rs = eng.get("rewardSummary") or {}
        handle = (eng.get("briefUrl") or "").replace("/engagements/", "")
        return {
            "platform": "bugcrowd",
            "platform_id": handle,
            "handle": handle,
            "name": eng.get("name") or handle,
            "tagline": (eng.get("tagline") or "")[:200],
            "status": "open" if eng.get("accessStatus") == "open" else "closed",
            "program_type": (eng.get("productEngagementType") or {}).get("label", "Bug Bounty"),
            "confidentiality": "private" if eng.get("isPrivate") else "public",
            "min_bounty": _parse_amount(rs.get("minReward", "")),
            "max_bounty": _parse_amount(rs.get("maxReward", "")),
            "reward_summary": rs.get("summary", ""),
            "currency": "USD",
            "industry": eng.get("industryName") or "Unknown",
            "service_level": eng.get("serviceLevel") or "",
            "logo_url": eng.get("logoUrl") or "",
            "url": f"{BASE_URL}/engagements/{handle}",
            "ends_at": eng.get("endsAt"),
            "is_following": eng.get("isFollowing", False),
            "discovery_method": "json_api",
        }

    # ── Program detail (JSON brief + Playwright fallback) ─────

    def get_program_detail(self, handle: str) -> Optional[Dict]:
        """Get program detail: try brief.json first, then Playwright."""
        # Try the brief JSON endpoint
        detail = self._fetch_brief_json(handle)
        if detail:
            return detail

        # Fallback to Playwright for full page extraction
        if _check_playwright():
            return self._fetch_detail_playwright(handle)

        return self._fallback_template(handle)

    def _fetch_brief_json(self, handle: str) -> Optional[Dict]:
        """Try fetching program brief via JSON endpoint."""
        # Try multiple URL patterns
        urls = [
            f"{BASE_URL}/{handle}/brief.json",
            f"{BASE_URL}/engagements/{handle}/brief.json",
        ]
        for url in urls:
            data = _api_get(url, self.cookies)
            if data and isinstance(data, dict):
                return self._normalize_brief(handle, data)
        return None

    def _normalize_brief(self, handle: str, brief: dict) -> Dict:
        """Normalize brief.json response."""
        # Extract scope targets
        scope = []
        targets = brief.get("targets") or brief.get("scope") or []
        if isinstance(targets, list):
            for t in targets:
                scope.append({
                    "asset_type": t.get("type", "url"),
                    "endpoint": t.get("name") or t.get("uri", ""),
                    "tier": t.get("priority", "p3"),
                    "eligible_for_bounty": True,
                    "description": t.get("description", ""),
                })

        # Extract reward ranges
        reward_ranges = brief.get("rewardRange") or brief.get("rewards") or {}
        min_bounty = 0.0
        max_bounty = 0.0
        if isinstance(reward_ranges, dict):
            min_bounty = float(reward_ranges.get("min", 0) or 0)
            max_bounty = float(reward_ranges.get("max", 0) or 0)
        elif isinstance(reward_ranges, list):
            amounts = []
            for r in reward_ranges:
                if isinstance(r, dict):
                    amounts.append(float(r.get("amount", 0) or 0))
            if amounts:
                min_bounty = min(amounts)
                max_bounty = max(amounts)

        return {
            "platform": "bugcrowd",
            "platform_id": handle,
            "handle": handle,
            "name": brief.get("name") or brief.get("title") or handle,
            "status": "open",
            "program_type": "bounty",
            "confidentiality": "public",
            "description": brief.get("description") or brief.get("tagline", ""),
            "min_bounty": min_bounty,
            "max_bounty": max_bounty,
            "currency": "USD",
            "url": f"{BASE_URL}/engagements/{handle}",
            "scope": scope,
            "rules": brief.get("rules") or brief.get("brief", ""),
            "oos_rules": brief.get("outOfScope", ""),
            "tech_stack": self._detect_tech(brief.get("description", "")),
            "discovery_method": "brief_json",
        }

    def _fetch_detail_playwright(self, handle: str) -> Optional[Dict]:
        """Fallback: extract program detail via Playwright browser."""
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context()

            if self.cookies:
                for name, value in self.cookies.items():
                    context.add_cookies([{
                        "name": name, "value": value,
                        "domain": ".bugcrowd.com", "path": "/",
                        "httpOnly": True, "secure": True,
                    }])

            page = context.new_page()
            try:
                url = f"{BASE_URL}/engagements/{handle}"
                resp = page.goto(url)
                if resp and resp.status == 404:
                    return None
                page.wait_for_load_state("networkidle")

                # Extract title
                title_el = page.query_selector("h1, .program-title, [data-testid='program-title']")
                name = title_el.inner_text().strip() if title_el else handle

                # Extract scope from page
                scope = self._extract_scope_from_page(page)

                # Extract bounty table
                bounties = self._extract_bounties_from_page(page)

                # Extract description
                desc = ""
                for sel in [".program-brief", ".program-description", "[data-testid='program-description']"]:
                    el = page.query_selector(sel)
                    if el:
                        desc = el.inner_text().strip()
                        break

                return {
                    "platform": "bugcrowd",
                    "platform_id": handle,
                    "handle": handle,
                    "name": name,
                    "status": "open",
                    "program_type": "bounty",
                    "confidentiality": "public",
                    "description": desc,
                    "min_bounty": bounties.get("min_bounty", 0.0),
                    "max_bounty": bounties.get("max_bounty", 0.0),
                    "currency": "USD",
                    "url": url,
                    "scope": scope,
                    "tech_stack": self._detect_tech(desc),
                    "discovery_method": "playwright",
                }
            except Exception as e:
                print(f"[scraper] Playwright detail error for {handle}: {e}")
                return self._fallback_template(handle)
            finally:
                browser.close()

    def _extract_scope_from_page(self, page) -> List[Dict]:
        """Extract scope items from a Playwright page."""
        scope = []
        for selector in [".scope-table tbody tr", ".in-scope-list li",
                         "[data-testid='scope-item']", ".target-list .target-item"]:
            elements = page.query_selector_all(selector)
            if elements:
                for el in elements:
                    text = el.inner_text().strip()
                    if text and len(text) > 2:
                        scope.append({
                            "asset_type": "url",
                            "endpoint": text,
                            "tier": "p3",
                            "eligible_for_bounty": True,
                        })
                break
        return scope

    def _extract_bounties_from_page(self, page) -> Dict:
        """Extract bounty amounts from a Playwright page."""
        amounts = []
        for selector in [".bounty-table tr", ".rewards-table tr", "[data-testid='bounty-row']"]:
            elements = page.query_selector_all(selector)
            for el in elements:
                text = el.inner_text()
                for m in re.findall(r"\$[\d,]+", text):
                    try:
                        amounts.append(float(m.replace("$", "").replace(",", "")))
                    except ValueError:
                        pass
            if amounts:
                break
        return {
            "min_bounty": min(amounts) if amounts else 0.0,
            "max_bounty": max(amounts) if amounts else 0.0,
        }

    # ── Helpers ────────────────────────────────────────────────

    def _detect_tech(self, text: str) -> List[str]:
        if not text:
            return []
        text_lower = text.lower()
        tech_map = {
            "react": ["react"], "angular": ["angular"], "vue": ["vue.js", "vuejs"],
            "nodejs": ["node.js", "nodejs"], "python": ["python", "django", "flask"],
            "php": ["php", "laravel"], "java": ["java", "spring"],
            "api": ["rest api", "graphql", "api"],
            "mobile": ["ios", "android", "mobile app"],
            "web": ["web app", "website"],
        }
        return [tech for tech, patterns in tech_map.items()
                if any(p in text_lower for p in patterns)]

    def _fallback_template(self, handle: str) -> Dict:
        return {
            "platform": "bugcrowd",
            "platform_id": handle,
            "handle": handle,
            "name": f"Bugcrowd Program ({handle})",
            "status": "open",
            "program_type": "bounty",
            "confidentiality": "public",
            "min_bounty": 0.0,
            "max_bounty": 0.0,
            "currency": "USD",
            "url": f"{BASE_URL}/engagements/{handle}",
            "scope": [],
            "tech_stack": [],
            "manual_entry_required": True,
            "discovery_method": "fallback_template",
        }


# ── CLI ───────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Bugcrowd Program Discovery")
    parser.add_argument("--discover", action="store_true", help="List programs via JSON API")
    parser.add_argument("--detail", type=str, help="Get detail for a specific program handle")
    parser.add_argument("--limit", type=int, default=50, help="Max programs to return")
    parser.add_argument("--sort", default="promoted", help="Sort: promoted, name, reward")
    parser.add_argument("--headless", action="store_true", default=True)
    parser.add_argument("--json", action="store_true", help="Output raw JSON")

    args = parser.parse_args()
    scraper = BugcrowdScraper(headless=args.headless, authenticated=True)

    if args.detail:
        result = scraper.get_program_detail(args.detail)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if result:
                print(f"Name:    {result.get('name')}")
                print(f"Bounty:  ${result.get('min_bounty', 0):,.0f} - ${result.get('max_bounty', 0):,.0f}")
                print(f"Scope:   {len(result.get('scope', []))} targets")
                print(f"Method:  {result.get('discovery_method')}")
            else:
                print(f"Program {args.detail} not found")
    else:
        programs = scraper.discover_programs(limit=args.limit, sort_by=args.sort)
        if args.json:
            print(json.dumps(programs, indent=2))
        else:
            print(f"\n{'#':>3} {'Program':40} {'Bounty Range':>20} {'Industry':20} {'Status'}")
            print("-" * 95)
            for i, p in enumerate(programs, 1):
                summary = p.get("reward_summary") or "N/A"
                print(f"{i:3} {p['name'][:39]:40} {summary:>20} "
                      f"{p['industry'][:19]:20} {p['status']}")


if __name__ == "__main__":
    main()
