#!/usr/bin/env python3
"""
HackerOne Disclosed Report Writeup Scraper

Scrapes full writeups from publicly disclosed HackerOne reports using Playwright.
Reads the program index, ranks reports by impact score, and extracts writeup content.

Usage:
    python3 tools/hackerone-writeup-scraper.py --limit 10
    python3 tools/hackerone-writeup-scraper.py --dry-run
    python3 tools/hackerone-writeup-scraper.py --limit 50 --output /tmp/writeups.json
"""

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
INTEL_INDEX_PATH = REPO_ROOT / ".claude" / "skills" / "pentest" / "hackerone-intel-index.json"
DEFAULT_OUTPUT_DIR = REPO_ROOT / ".claude" / "skills" / "pentest" / "hackerone-writeups"
DEFAULT_OUTPUT_FILE = DEFAULT_OUTPUT_DIR / "top-writeups.json"

HACKERONE_BASE_URL = "https://hackerone.com/reports"

# Scraping parameters
REQUEST_DELAY_SECONDS = 2.0
PAGE_LOAD_TIMEOUT_MS = 15_000
NAVIGATION_TIMEOUT_MS = 30_000
DEFAULT_LIMIT = 100

# Impact score weights
BOUNTY_WEIGHT = 0.4
UPVOTES_WEIGHT = 0.6

# Selectors to wait for (tried in order, first match wins)
CONTENT_WAIT_SELECTORS = [
    ".report-heading",
    ".timeline-container",
    "[data-testid='report-section']",
    ".report__content",
    "#report-body",
    "article",
]

# Selectors for extracting writeup text (tried in order)
WRITEUP_SELECTORS = [
    ".report-heading ~ .markdown-content",
    "[data-testid='report-section'] .markdown-content",
    ".report__content .markdown-content",
    ".timeline-container .markdown-content",
    ".report-body",
    "article .markdown-content",
    ".markdown-content",
]

# Selectors for severity/CVSS extraction
SEVERITY_SELECTORS = [
    "[data-testid='severity-rating']",
    ".spec-severity-rating",
    ".report-severity",
    ".severity-rating",
]

CVSS_SELECTORS = [
    "[data-testid='cvss-score']",
    ".spec-cvss-score",
    ".cvss-score",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("hackerone-scraper")


# ---------------------------------------------------------------------------
# Data loading and ranking
# ---------------------------------------------------------------------------

def load_intel_index(path: Path) -> dict:
    """Load the HackerOne intel index JSON file."""
    if not path.exists():
        logger.error("Intel index not found at %s", path)
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_report_id(link: str) -> str | None:
    """Extract numeric report ID from a link like 'hackerone.com/reports/1234567'."""
    match = re.search(r"/reports/(\d+)", link)
    return match.group(1) if match else None


def compute_impact_score(bounty: float, upvotes: int) -> float:
    """Weighted impact score: bounty * 0.4 + upvotes * 0.6."""
    return (bounty or 0) * BOUNTY_WEIGHT + (upvotes or 0) * UPVOTES_WEIGHT


def rank_reports(intel_index: dict, limit: int) -> list[dict]:
    """
    Collect all reports across programs, compute impact scores,
    and return the top N sorted by descending impact score.
    """
    all_reports = []
    seen_ids = set()

    for program_name, program_data in intel_index.items():
        if not isinstance(program_data, dict):
            continue
        top_reports = program_data.get("top_reports", [])
        for report in top_reports:
            link = report.get("link", "")
            report_id = extract_report_id(link)
            if not report_id or report_id in seen_ids:
                continue
            seen_ids.add(report_id)

            bounty = report.get("bounty") or 0
            upvotes = report.get("upvotes") or 0
            score = compute_impact_score(bounty, upvotes)

            all_reports.append({
                "report_id": report_id,
                "title": report.get("title", ""),
                "program": program_name,
                "bounty": bounty,
                "upvotes": upvotes,
                "impact_score": round(score, 2),
                "vuln_type": report.get("vuln_type", ""),
                "url": f"{HACKERONE_BASE_URL}/{report_id}",
            })

    all_reports.sort(key=lambda r: r["impact_score"], reverse=True)
    logger.info(
        "Found %d unique reports across %d programs, selecting top %d",
        len(all_reports), len(intel_index), limit,
    )
    return all_reports[:limit]


# ---------------------------------------------------------------------------
# Playwright scraping
# ---------------------------------------------------------------------------

async def wait_for_content(page) -> bool:
    """Wait for any of the known content selectors to appear on the page."""
    for selector in CONTENT_WAIT_SELECTORS:
        try:
            await page.wait_for_selector(selector, timeout=PAGE_LOAD_TIMEOUT_MS)
            return True
        except Exception:
            continue
    return False


async def extract_writeup(page) -> str:
    """Extract the writeup/description text from the loaded report page."""
    for selector in WRITEUP_SELECTORS:
        try:
            elements = await page.query_selector_all(selector)
            if elements:
                # Take the first substantial block (the vulnerability description)
                texts = []
                for el in elements:
                    text = (await el.inner_text()).strip()
                    if text:
                        texts.append(text)
                if texts:
                    return "\n\n".join(texts)
        except Exception:
            continue

    # Fallback: grab all text from the page body
    try:
        body_text = await page.inner_text("body")
        return body_text.strip()[:5000] if body_text else ""
    except Exception:
        return ""


async def extract_severity(page) -> str:
    """Extract severity rating text if visible."""
    for selector in SEVERITY_SELECTORS:
        try:
            el = await page.query_selector(selector)
            if el:
                text = (await el.inner_text()).strip()
                if text:
                    return text
        except Exception:
            continue
    return ""


async def extract_cvss(page) -> str:
    """Extract CVSS score text if visible."""
    for selector in CVSS_SELECTORS:
        try:
            el = await page.query_selector(selector)
            if el:
                text = (await el.inner_text()).strip()
                if text:
                    return text
        except Exception:
            continue
    return ""


async def scrape_report(page, report: dict) -> dict | None:
    """
    Navigate to a single report URL and extract writeup data.
    Returns enriched report dict or None on failure.
    """
    url = report["url"]
    report_id = report["report_id"]
    logger.info("Scraping report %s: %s", report_id, report["title"][:80])

    try:
        response = await page.goto(url, timeout=NAVIGATION_TIMEOUT_MS, wait_until="domcontentloaded")

        if response and response.status == 429:
            logger.warning("Rate limited on report %s, skipping", report_id)
            return None

        if response and response.status != 200:
            logger.warning("HTTP %d for report %s, skipping", response.status, report_id)
            return None

        content_loaded = await wait_for_content(page)
        if not content_loaded:
            logger.warning("Content selectors not found for report %s, attempting extraction anyway", report_id)

        writeup_text = await extract_writeup(page)
        severity = await extract_severity(page)
        cvss = await extract_cvss(page)

        if not writeup_text:
            logger.warning("No writeup text extracted for report %s", report_id)
            return None

        return {
            **report,
            "writeup": writeup_text,
            "severity": severity,
            "cvss": cvss,
            "scraped_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    except Exception as exc:
        logger.error("Failed to scrape report %s: %s", report_id, str(exc)[:200])
        return None


async def scrape_all(reports: list[dict], output_path: Path) -> list[dict]:
    """Scrape all reports sequentially with rate-limit delays."""
    from playwright.async_api import async_playwright

    results = []
    failed = 0

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1280, "height": 900},
        )
        page = await context.new_page()

        for i, report in enumerate(reports):
            if i > 0:
                await asyncio.sleep(REQUEST_DELAY_SECONDS)

            result = await scrape_report(page, report)
            if result:
                results.append(result)
                logger.info(
                    "  [%d/%d] Extracted %d chars from report %s",
                    i + 1, len(reports), len(result["writeup"]), report["report_id"],
                )
            else:
                failed += 1
                logger.info("  [%d/%d] Skipped report %s", i + 1, len(reports), report["report_id"])

            # Incremental save every 10 reports
            if len(results) % 10 == 0 and results:
                save_results(results, output_path)

        await browser.close()

    logger.info("Scraping complete: %d succeeded, %d failed out of %d total", len(results), failed, len(reports))
    return results


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def save_results(results: list[dict], output_path: Path) -> None:
    """Write results to JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "metadata": {
                    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "total_reports": len(results),
                    "source": str(INTEL_INDEX_PATH),
                },
                "reports": results,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )
    logger.info("Saved %d reports to %s", len(results), output_path)


def print_dry_run(reports: list[dict]) -> None:
    """Print URLs and metadata without scraping."""
    print(f"\n{'='*80}")
    print(f"DRY RUN: Would scrape {len(reports)} reports")
    print(f"{'='*80}\n")
    for i, r in enumerate(reports, 1):
        print(f"  {i:3d}. [{r['impact_score']:>10.2f}] {r['url']}")
        print(f"       {r['title'][:70]}")
        print(f"       Program: {r['program']} | Bounty: ${r['bounty']:,.0f} | Upvotes: {r['upvotes']}")
        print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scrape writeups from disclosed HackerOne reports.",
    )
    parser.add_argument(
        "--limit", type=int, default=DEFAULT_LIMIT,
        help=f"Number of top reports to scrape (default: {DEFAULT_LIMIT})",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print URLs that would be scraped without actually scraping",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help=f"Output JSON path (default: {DEFAULT_OUTPUT_FILE})",
    )
    parser.add_argument(
        "--index", type=str, default=None,
        help=f"Path to intel index JSON (default: {INTEL_INDEX_PATH})",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args()


async def main() -> None:
    args = parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    index_path = Path(args.index) if args.index else INTEL_INDEX_PATH
    output_path = Path(args.output) if args.output else DEFAULT_OUTPUT_FILE

    intel_index = load_intel_index(index_path)
    ranked = rank_reports(intel_index, args.limit)

    if not ranked:
        logger.error("No reports found in the intel index")
        sys.exit(1)

    if args.dry_run:
        print_dry_run(ranked)
        sys.exit(0)

    results = await scrape_all(ranked, output_path)
    save_results(results, output_path)

    print(f"\nDone. {len(results)} writeups saved to {output_path}")


if __name__ == "__main__":
    asyncio.run(main())
