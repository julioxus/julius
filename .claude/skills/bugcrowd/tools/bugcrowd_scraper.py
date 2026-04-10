#!/usr/bin/env python3
"""
Bugcrowd Program Scraper using Playwright
Automatically discovers and extracts program information from Bugcrowd's public pages.
"""

import json
import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    print("Playwright not installed. Run: pip install playwright && playwright install")


class BugcrowdScraper:
    """Automated Bugcrowd program discovery and data extraction."""

    def __init__(self, headless: bool = True, authenticated: bool = False):
        self.headless = headless
        self.authenticated = authenticated
        self.base_url = "https://bugcrowd.com"
        self.cookies = None

        # Load session cookies if authenticated mode requested
        if self.authenticated:
            self._load_session_cookies()

    def _load_session_cookies(self):
        """Load session cookies for authenticated access."""
        try:
            # Try to import the auth module
            from pathlib import Path
            import sys

            auth_path = Path(__file__).parent
            if str(auth_path) not in sys.path:
                sys.path.insert(0, str(auth_path))

            from bugcrowd_auth import get_session_cookies

            self.cookies = get_session_cookies()
            if self.cookies:
                print(f"[scraper] Loaded {len(self.cookies)} session cookies for authenticated access")
            else:
                print("[scraper] Failed to load session cookies - falling back to public access")
                self.authenticated = False

        except ImportError:
            print("[scraper] Authentication module not available - using public access only")
            self.authenticated = False
        except Exception as e:
            print(f"[scraper] Error loading session cookies: {e}")
            self.authenticated = False

    def discover_programs(self, limit: int = 50) -> List[Dict]:
        """Discover available Bugcrowd programs from public directory or authenticated dashboard."""
        if not PLAYWRIGHT_AVAILABLE:
            return self._fallback_known_programs()

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context()

            # Set authentication cookies if available
            if self.authenticated and self.cookies:
                self._set_browser_cookies(context)

            page = context.new_page()

            # Set user agent to avoid detection
            page.set_extra_http_headers({
                "User-Agent": "BountyIntel/1.0 (Security Research)"
            })

            programs = []

            try:
                if self.authenticated and self.cookies:
                    # Comprehensive scan of all possible dashboard URLs and views
                    dashboard_urls = [
                        f"{self.base_url}/dashboard",
                        f"{self.base_url}/dashboard/programs",
                        f"{self.base_url}/dashboard/engagements",
                        f"{self.base_url}/engagements",
                        f"{self.base_url}/engagements?filter=all",
                        f"{self.base_url}/engagements?filter=active",
                        f"{self.base_url}/engagements?filter=upcoming",
                        f"{self.base_url}/engagements?filter=completed",
                        f"{self.base_url}/engagements?filter=invited",
                        f"{self.base_url}/programs",
                        f"{self.base_url}/programs?filter=all",
                        f"{self.base_url}/programs?filter=active",
                        f"{self.base_url}/programs?filter=upcoming",
                        f"{self.base_url}/programs?category=web",
                        f"{self.base_url}/programs?category=mobile",
                        f"{self.base_url}/programs?category=api",
                        f"{self.base_url}/researcher/programs",
                        f"{self.base_url}/researcher/engagements",
                        f"{self.base_url}/researcher/dashboard",
                        f"{self.base_url}/user/programs",
                        f"{self.base_url}/user/engagements",
                        f"{self.base_url}/my/programs",
                        f"{self.base_url}/my/engagements"
                    ]

                    print(f"[scraper] Comprehensive scan of {len(dashboard_urls)} dashboard URLs for program discovery")
                    for url in dashboard_urls:
                        print(f"\n[scraper] Checking: {url}")
                        try:
                            response = page.goto(url)
                            if response and response.status >= 400:
                                print(f"[scraper] Skipping {url}: HTTP {response.status}")
                                continue

                            page.wait_for_load_state("networkidle", timeout=15000)

                            # Extract programs from this page
                            page_programs = self._extract_programs_from_page(page, limit - len(programs))
                            print(f"[scraper] Found {len(page_programs)} programs on {url}")

                            # Add unique programs (avoid duplicates)
                            for program in page_programs:
                                handle = program.get("handle")
                                if handle and not any(p.get("handle") == handle for p in programs):
                                    programs.append(program)
                                    print(f"[scraper] Added new program: {program.get('name')} ({handle})")

                            # Check for pagination - look for next page links
                            pagination_links = page.query_selector_all("a[aria-label*='Next'], a[href*='page='], .pagination a, .next-page")
                            if pagination_links and len(programs) < limit:
                                print(f"[scraper] Found pagination, exploring next pages...")
                                for page_num in range(2, 6):  # Check up to 5 pages
                                    try:
                                        next_url = f"{url}{'&' if '?' in url else '?'}page={page_num}"
                                        print(f"[scraper] Checking page {page_num}: {next_url}")
                                        page.goto(next_url)
                                        page.wait_for_load_state("networkidle", timeout=10000)

                                        page_programs = self._extract_programs_from_page(page, limit - len(programs))
                                        if not page_programs:
                                            break

                                        for program in page_programs:
                                            handle = program.get("handle")
                                            if handle and not any(p.get("handle") == handle for p in programs):
                                                programs.append(program)
                                                print(f"[scraper] Added from page {page_num}: {program.get('name')} ({handle})")
                                    except:
                                        break

                            if len(programs) >= limit:
                                print(f"[scraper] Reached limit of {limit} programs")
                                break

                        except Exception as e:
                            print(f"[scraper] Error scanning {url}: {e}")
                            continue
                else:
                    # Use public programs directory
                    url = f"{self.base_url}/programs"
                    print("[scraper] Using public directory for program discovery")
                    page.goto(url)
                    page.wait_for_load_state("networkidle")
                    programs = self._extract_programs_from_page(page, limit)

                discovery_type = "authenticated dashboard" if self.authenticated else "public scraping"
                print(f"Discovered {len(programs)} Bugcrowd programs via {discovery_type}")
                return programs

            except Exception as e:
                print(f"Error discovering programs: {e}")
                return self._fallback_known_programs()
            finally:
                browser.close()

            discovery_type = "authenticated dashboard" if self.authenticated else "public scraping"
            print(f"Discovered {len(programs)} Bugcrowd programs via {discovery_type}")
            return programs

    def _extract_programs_from_page(self, page, limit: int = 50) -> List[Dict]:
        """Extract program information from a single page."""
        programs = []

        try:
            # Comprehensive list of selectors to find ALL possible program links
            selectors = [
                "a[href*='/programs/']",  # Direct program links
                "a[href*='/engagements/']",  # Engagement links
                ".program-card a",  # Program card links
                ".engagement-card a",  # Engagement card links
                "[data-cy*='program'] a",  # Cypress test selectors
                "[data-testid*='program'] a",  # Test ID selectors
                "[data-testid*='engagement'] a",  # Engagement test selectors
                ".dashboard-program-link",  # Dashboard specific
                ".program-list a",  # Program list
                ".engagement-list a",  # Engagement list
                "a[class*='program']",  # Any class containing 'program'
                "a[class*='engagement']",  # Any class containing 'engagement'
                "a[class*='card']",  # Card-style links
                ".card a",  # Generic card links
                ".tile a",  # Tile-style links
                "[role='link'][href*='/']",  # ARIA role links
                "a[href*='/projects/']",  # Projects links
                "a[href*='/bugs/']",  # Bug links
                "a[href*='/bounty/']",  # Bounty links
                "a[href*='/security/']",  # Security links
                "h3 a",  # Header links
                "h2 a",  # Header links
                ".title a",  # Title links
                ".name a",  # Name links
            ]

            program_elements = []

            # Try each selector and collect ALL potential links
            for selector in selectors:
                elements = page.query_selector_all(selector)
                for element in elements:
                    href = element.get_attribute("href")
                    if href and ("/programs/" in href or "/engagements/" in href):
                        program_elements.append(element)

            # If still no program links found, be more aggressive
            if not program_elements:
                print("[scraper] No specific selectors worked, scanning ALL links...")
                all_links = page.query_selector_all("a[href]")
                print(f"[scraper] Found {len(all_links)} total links to examine")

                for link in all_links:
                    href = link.get_attribute("href")
                    if href and (
                        "/programs/" in href or
                        "/engagements/" in href or
                        "/projects/" in href or
                        ("/bug" in href and "bugcrowd.com" in href) or
                        ("/bounty" in href and "bugcrowd.com" in href) or
                        (self.base_url in href and any(keyword in href.lower() for keyword in ["program", "engagement", "bug", "bounty", "project", "security"]))
                    ):
                        program_elements.append(link)
                print(f"[scraper] Filtered to {len(program_elements)} potential program links")

            print(f"[scraper] Total program elements found: {len(program_elements)}")

            for i, element in enumerate(program_elements[:limit]):
                try:
                    href = element.get_attribute("href")
                    if not href:
                        continue

                    print(f"[scraper] Processing link {i+1}/{len(program_elements)}: {href}")

                    # Extract program handle from URL
                    handle = self._extract_handle_from_url(href)
                    if not handle:
                        print(f"[scraper] Could not extract handle from: {href}")
                        continue

                    # Get program name from link text
                    name = element.inner_text()
                    name = name.strip()

                    # If name is empty or too short, try to get from parent or nearby elements
                    if not name or len(name) < 2:
                        try:
                            # Try different ways to get a better name
                            parent = element.locator("..")
                            if parent:
                                name = parent.inner_text().strip()
                                # Take first meaningful line
                                lines = [line.strip() for line in name.split('\n') if line.strip()]
                                if lines:
                                    name = lines[0]
                        except:
                            pass

                    # Final fallback to handle
                    if not name or len(name) < 2:
                        name = handle.replace('-', ' ').title()

                    print(f"[scraper] Found: '{name}' ({handle})")

                    if handle and name:
                        program_data = {
                            "platform": "bugcrowd",
                            "platform_id": handle,
                            "handle": handle,
                            "name": name,
                            "status": "open",
                            "program_type": "bounty",
                            "confidentiality": "private" if self.authenticated else "public",
                            "url": urljoin(self.base_url, href),
                            "discovery_method": "authenticated_dashboard" if self.authenticated else "public_browser_automation"
                        }
                        programs.append(program_data)

                except Exception as e:
                    print(f"[scraper] Error processing element {i}: {e}")
                    continue

        except Exception as e:
            print(f"[scraper] Error extracting programs from page: {e}")

        print(f"[scraper] Returning {len(programs)} programs from this page")
        return programs

    def comprehensive_discovery(self, limit: int = 100) -> List[Dict]:
        """Comprehensive program discovery with detailed inspection."""
        if not PLAYWRIGHT_AVAILABLE:
            return self._fallback_known_programs()

        # Use headless browser for MCP integration (visible only when called directly from CLI)
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)  # Respect headless setting
            context = browser.new_context()

            # Set authentication cookies
            if self.authenticated and self.cookies:
                self._set_browser_cookies(context)

            page = context.new_page()
            page.set_extra_http_headers({
                "User-Agent": "BountyIntel/1.0 (Security Research)"
            })

            programs = []

            try:
                print("[scraper] Starting comprehensive discovery...")

                # Start with the main dashboard
                page.goto(f"{self.base_url}/dashboard")
                page.wait_for_load_state("networkidle")

                # Wait a moment for dynamic content to load
                page.wait_for_timeout(2000)

                # Try to find all navigation links and sections
                nav_links = page.query_selector_all("nav a, .navigation a, [role='navigation'] a")
                dashboard_sections = []

                for link in nav_links:
                    href = link.get_attribute("href")
                    text = link.inner_text().lower()
                    if href and any(keyword in text for keyword in ["program", "engagement", "bug", "bounty", "submission"]):
                        dashboard_sections.append(href)

                # Add common URLs
                dashboard_sections.extend([
                    "/dashboard",
                    "/dashboard/programs",
                    "/dashboard/engagements",
                    "/engagements",
                    "/programs"
                ])

                # Remove duplicates and ensure full URLs
                unique_sections = []
                for section in dashboard_sections:
                    if section.startswith("/"):
                        full_url = f"{self.base_url}{section}"
                    else:
                        full_url = section

                    if full_url not in unique_sections:
                        unique_sections.append(full_url)

                print(f"[scraper] Found {len(unique_sections)} sections to explore")

                for url in unique_sections:
                    if len(programs) >= limit:
                        break

                    print(f"[scraper] Exploring: {url}")
                    try:
                        page.goto(url)
                        page.wait_for_load_state("networkidle", timeout=15000)
                        page.wait_for_timeout(1000)  # Brief wait for dynamic content

                        # Extract programs from this page
                        page_programs = self._extract_programs_from_page(page, limit - len(programs))

                        # Add unique programs
                        for program in page_programs:
                            handle = program.get("handle")
                            if handle and not any(p.get("handle") == handle for p in programs):
                                programs.append(program)
                                print(f"[scraper] Added: {program.get('name')} ({handle})")

                    except Exception as e:
                        print(f"[scraper] Error exploring {url}: {e}")

                print(f"[scraper] Comprehensive discovery complete!")

            except Exception as e:
                print(f"[scraper] Error in comprehensive discovery: {e}")
            finally:
                browser.close()

            print(f"Discovered {len(programs)} total Bugcrowd programs via comprehensive scan")
            return programs

    def _set_browser_cookies(self, context):
        """Set authentication cookies in browser context."""
        if not self.cookies:
            return

        try:
            cookies_for_browser = []
            for name, value in self.cookies.items():
                cookie = {
                    'name': name,
                    'value': value,
                    'domain': '.bugcrowd.com',
                    'path': '/',
                    'httpOnly': True,
                    'secure': True
                }
                cookies_for_browser.append(cookie)

            context.add_cookies(cookies_for_browser)
            print(f"[scraper] Set {len(cookies_for_browser)} authentication cookies")

        except Exception as e:
            print(f"[scraper] Error setting cookies: {e}")

    def get_program_detail(self, handle: str) -> Optional[Dict]:
        """Extract detailed program information including scope and bounties."""
        if not PLAYWRIGHT_AVAILABLE:
            return self._fallback_program_template(handle)

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context()

            # Set authentication cookies if available
            if self.authenticated and self.cookies:
                self._set_browser_cookies(context)

            page = context.new_page()

            page.set_extra_http_headers({
                "User-Agent": "BountyIntel/1.0 (Security Research)"
            })

            try:
                # Navigate to program page
                url = f"{self.base_url}/{handle}"
                response = page.goto(url)

                if response and response.status == 404:
                    print(f"Program {handle} not found (404)")
                    return None

                page.wait_for_load_state("networkidle")

                # Extract program information
                program_info = self._extract_program_info(page, handle)

                # Mark if extracted with authentication
                program_info["authenticated_access"] = self.authenticated

                # Extract scope (more details available when authenticated)
                scope = self._extract_scope(page)
                program_info["scope"] = scope

                # Extract bounty table
                bounties = self._extract_bounty_table(page)
                program_info.update(bounties)

                # Extract out-of-scope rules
                oos_rules = self._extract_oos_rules(page)
                program_info["oos_rules"] = oos_rules

                # Extract tech stack hints
                tech_stack = self._extract_tech_stack(page)
                program_info["tech_stack"] = tech_stack

                return program_info

            except Exception as e:
                print(f"Error extracting program details for {handle}: {e}")
                return self._fallback_program_template(handle)
            finally:
                browser.close()

    def _extract_program_info(self, page, handle: str) -> Dict:
        """Extract basic program information."""
        try:
            # Try to get program title
            title_element = page.query_selector("h1, .program-title, [data-testid='program-title']")
            name = title_element.inner_text() if title_element else f"Bugcrowd Program ({handle})"

            # Try to get program description
            desc_selectors = [".program-brief", ".program-description", "[data-testid='program-description']"]
            description = ""
            for selector in desc_selectors:
                desc_element = page.query_selector(selector)
                if desc_element:
                    description = desc_element.inner_text()
                    break

            return {
                "platform": "bugcrowd",
                "platform_id": handle,
                "handle": handle,
                "name": name.strip(),
                "status": "open",
                "program_type": "bounty",
                "confidentiality": "public",
                "description": description.strip(),
                "url": f"{self.base_url}/{handle}",
                "discovery_method": "browser_automation"
            }

        except Exception as e:
            print(f"Error extracting program info: {e}")
            return self._fallback_program_template(handle)

    def _extract_scope(self, page) -> List[Dict]:
        """Extract in-scope assets."""
        scope = []

        try:
            # Look for scope tables or lists
            scope_selectors = [
                ".scope-table tbody tr",
                ".in-scope-list li",
                "[data-testid='scope-item']",
                ".target-list .target-item"
            ]

            for selector in scope_selectors:
                elements = page.query_selector_all(selector)
                if elements:
                    for element in elements:
                        try:
                            text = element.inner_text()
                            scope_item = self._parse_scope_item(text)
                            if scope_item:
                                scope.append(scope_item)
                        except:
                            continue
                    break

        except Exception as e:
            print(f"Error extracting scope: {e}")

        return scope

    def _extract_bounty_table(self, page) -> Dict:
        """Extract bounty amounts by priority level."""
        bounties = {
            "min_bounty": 0.0,
            "max_bounty": 0.0,
            "currency": "USD",
            "bounty_notes": ""
        }

        try:
            # Look for bounty tables
            bounty_selectors = [
                ".bounty-table tr",
                ".rewards-table tr",
                "[data-testid='bounty-row']"
            ]

            bounty_text = []
            for selector in bounty_selectors:
                elements = page.query_selector_all(selector)
                if elements:
                    for element in elements:
                        try:
                            text = element.inner_text()
                            if any(priority in text.lower() for priority in ["p1", "p2", "p3", "p4", "p5", "critical", "high", "medium", "low"]):
                                bounty_text.append(text)
                        except:
                            continue
                    break

            if bounty_text:
                bounty_info = self._parse_bounty_table(bounty_text)
                bounties.update(bounty_info)

        except Exception as e:
            print(f"Error extracting bounty table: {e}")

        return bounties

    def _extract_oos_rules(self, page) -> str:
        """Extract out-of-scope rules."""
        try:
            oos_selectors = [
                ".out-of-scope",
                ".oos-rules",
                "[data-testid='out-of-scope']",
                ".exclusions"
            ]

            for selector in oos_selectors:
                element = page.query_selector(selector)
                if element:
                    return element.inner_text()

        except Exception as e:
            print(f"Error extracting OOS rules: {e}")

        return ""

    def _extract_tech_stack(self, page) -> List[str]:
        """Extract technology stack hints from program page."""
        tech_stack = set()

        try:
            # Get all text content
            body = page.query_selector("body")
            if body:
                text = body.inner_text()
                text = text.lower()

                # Common technology patterns
                tech_patterns = {
                    "react": ["react", "reactjs"],
                    "angular": ["angular", "angularjs"],
                    "vue": ["vue.js", "vuejs"],
                    "nodejs": ["node.js", "nodejs", "express"],
                    "python": ["python", "django", "flask"],
                    "php": ["php", "laravel", "wordpress"],
                    "ruby": ["ruby", "rails"],
                    "java": ["java", "spring"],
                    "dotnet": [".net", "asp.net", "c#"],
                    "aws": ["aws", "amazon web services"],
                    "gcp": ["google cloud", "gcp"],
                    "azure": ["azure", "microsoft cloud"],
                    "api": ["rest api", "graphql", "api"],
                    "mobile": ["ios", "android", "mobile app"],
                    "web": ["web app", "website", "browser"]
                }

                for tech, patterns in tech_patterns.items():
                    if any(pattern in text for pattern in patterns):
                        tech_stack.add(tech)

        except Exception as e:
            print(f"Error extracting tech stack: {e}")

        return list(tech_stack)

    def _extract_handle_from_url(self, url: str) -> Optional[str]:
        """Extract program handle from URL."""
        try:
            parsed = urlparse(url)
            path_parts = parsed.path.strip("/").split("/")

            # Handle different URL patterns:
            # /programs/handle
            # /engagements/handle
            # /handle (direct program access)
            # bugcrowd.com/handle

            if "programs" in path_parts and len(path_parts) > 1:
                idx = path_parts.index("programs")
                if idx + 1 < len(path_parts):
                    return path_parts[idx + 1]
            elif "engagements" in path_parts and len(path_parts) > 1:
                idx = path_parts.index("engagements")
                if idx + 1 < len(path_parts):
                    return path_parts[idx + 1]
            elif len(path_parts) == 1 and path_parts[0]:
                # Direct program handle (e.g., bugcrowd.com/tesla)
                handle = path_parts[0]
                # Exclude common non-program paths
                if handle not in ['dashboard', 'submissions', 'programs', 'profile', 'settings', 'help', 'about']:
                    return handle
            elif len(path_parts) >= 2:
                # Try last part if it looks like a handle
                last_part = path_parts[-1]
                if last_part and '-' in last_part or last_part.islower():
                    return last_part

        except Exception as e:
            print(f"[scraper] Error extracting handle from {url}: {e}")
        return None

    def _parse_scope_item(self, text: str) -> Optional[Dict]:
        """Parse a scope item text into structured data."""
        if not text or len(text.strip()) < 3:
            return None

        text = text.strip()

        # Detect asset type
        asset_type = "url"
        if any(mobile in text.lower() for mobile in ["ios", "android", "mobile", "app store", "google play"]):
            asset_type = "mobile"
        elif "api" in text.lower():
            asset_type = "api"

        # Extract priority level
        tier = "p3"  # default medium
        priority_match = re.search(r'\b(p[1-5]|critical|high|medium|low|info)\b', text.lower())
        if priority_match:
            priority = priority_match.group(1)
            if priority in ["p1", "critical"]:
                tier = "p1"
            elif priority in ["p2", "high"]:
                tier = "p2"
            elif priority in ["p3", "medium"]:
                tier = "p3"
            elif priority in ["p4", "low"]:
                tier = "p4"
            elif priority in ["p5", "info"]:
                tier = "p5"

        # Clean up endpoint
        endpoint = re.sub(r'\s*\([^)]*\)\s*', '', text).strip()

        return {
            "asset_type": asset_type,
            "endpoint": endpoint,
            "tier": tier,
            "eligible_for_bounty": True,
            "description": text
        }

    def _parse_bounty_table(self, bounty_texts: List[str]) -> Dict:
        """Parse bounty table into structured data."""
        bounty_amounts = []
        notes = []

        for text in bounty_texts:
            # Extract dollar amounts
            amounts = re.findall(r'\$[\d,]+', text)
            bounty_amounts.extend(amounts)
            notes.append(text.strip())

        # Convert to numbers and find min/max
        numeric_amounts = []
        for amount in bounty_amounts:
            try:
                numeric = int(amount.replace('$', '').replace(',', ''))
                numeric_amounts.append(numeric)
            except:
                continue

        return {
            "min_bounty": float(min(numeric_amounts)) if numeric_amounts else 0.0,
            "max_bounty": float(max(numeric_amounts)) if numeric_amounts else 0.0,
            "currency": "USD",
            "bounty_notes": " | ".join(notes)
        }

    def _fallback_known_programs(self) -> List[Dict]:
        """Return known public Bugcrowd programs when scraping fails."""
        known_programs = [
            {
                "platform": "bugcrowd",
                "platform_id": "tesla",
                "handle": "tesla",
                "name": "Tesla",
                "status": "open",
                "program_type": "bounty",
                "confidentiality": "public",
                "url": "https://bugcrowd.com/tesla",
                "discovery_method": "known_programs"
            },
            {
                "platform": "bugcrowd",
                "platform_id": "crowdstrike",
                "handle": "crowdstrike",
                "name": "CrowdStrike",
                "status": "open",
                "program_type": "bounty",
                "confidentiality": "public",
                "url": "https://bugcrowd.com/crowdstrike",
                "discovery_method": "known_programs"
            }
        ]

        print(f"Using fallback known programs: {len(known_programs)} programs")
        return known_programs

    def _fallback_program_template(self, handle: str) -> Dict:
        """Create fallback program template."""
        return {
            "platform": "bugcrowd",
            "platform_id": handle,
            "handle": handle,
            "name": f"Bugcrowd Program ({handle})",
            "status": "open",
            "program_type": "bounty",
            "confidentiality": "public",
            "url": f"https://bugcrowd.com/{handle}",
            "scope": [],
            "oos_rules": "",
            "tech_stack": [],
            "bounty_notes": "Manual bounty extraction required",
            "min_bounty": 0.0,
            "max_bounty": 0.0,
            "currency": "USD",
            "manual_entry_required": True,
            "discovery_method": "fallback_template"
        }


# CLI interface
def main():
    """Command line interface for Bugcrowd scraper."""
    import argparse

    parser = argparse.ArgumentParser(description="Bugcrowd Program Scraper")
    parser.add_argument("--discover", action="store_true", help="Discover programs")
    parser.add_argument("--comprehensive", action="store_true", help="Comprehensive discovery with visible browser")
    parser.add_argument("--program", type=str, help="Get specific program details")
    parser.add_argument("--limit", type=int, default=20, help="Limit results")
    parser.add_argument("--headless", action="store_true", help="Run browser in headless mode")
    parser.add_argument("--authenticated", action="store_true", help="Use authenticated access")

    args = parser.parse_args()

    scraper = BugcrowdScraper(headless=args.headless, authenticated=args.authenticated)

    if args.comprehensive:
        programs = scraper.comprehensive_discovery(limit=args.limit)
        print(json.dumps(programs, indent=2))
    elif args.discover:
        programs = scraper.discover_programs(limit=args.limit)
        print(json.dumps(programs, indent=2))
    elif args.program:
        program = scraper.get_program_detail(args.program)
        print(json.dumps(program, indent=2))
    else:
        print("Use --discover to find programs, --comprehensive for detailed scan, or --program <handle> for details")


if __name__ == "__main__":
    main()