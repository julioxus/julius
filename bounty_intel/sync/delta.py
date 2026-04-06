"""Delta sync coordinator — manages watermarks and orchestrates source syncs."""

from __future__ import annotations

from datetime import datetime, timezone

from bounty_intel import service
from bounty_intel.sync import hackerone, intigriti


def sync_all(sources: list[str] | None = None) -> dict:
    """Run delta sync for specified sources (or all).

    Returns per-source stats dict.
    """
    if sources is None:
        sources = ["hackerone", "intigriti"]

    results = {}

    for source in sources:
        print(f"\n--- Syncing {source} ---")
        state = service.get_sync_state(source)
        since = state.last_submission_updated if state else None

        if since:
            print(f"  Watermark: {since.isoformat()}")
        else:
            print(f"  First sync (no watermark)")

        if source == "hackerone":
            stats = hackerone.sync(since=since)
        elif source == "intigriti":
            stats = intigriti.sync(since=since)
        else:
            print(f"  [!] Unknown source: {source}")
            continue

        # Check for auth errors
        if stats.get("error") == "no_cookie":
            print(f"  [!] Skipped — Intigriti login failed or unavailable.")
            results[source] = stats
            continue

        # Update watermark
        max_updated = stats.get("max_updated")
        if max_updated:
            service.update_sync_state(source, max_updated)
            print(f"  Watermark updated to: {max_updated.isoformat()}")

        results[source] = stats
        print(f"  Result: {stats.get('upserted', 0)} upserted, {stats.get('skipped', 0)} skipped")

    return results
