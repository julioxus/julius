"""CLI entrypoint for the Bounty Intelligence System.

Usage:
    python -m bounty_intel migrate [--import]
    python -m bounty_intel sync [--source intigriti|hackerone|all]
    python -m bounty_intel forecast
    python -m bounty_intel serve [--port 8000]
    python -m bounty_intel stats
    python -m bounty_intel mcp
    python -m bounty_intel report create --program HANDLE --file PATH
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def cmd_migrate(args):
    from bounty_intel.migration.schema import create_schema
    create_schema()

    if getattr(args, "do_import", False):
        from bounty_intel.migration.import_existing import run_full_import
        base_dir = Path(args.base_dir) if args.base_dir else None
        run_full_import(base_dir)

    if getattr(args, "dedup", False):
        from bounty_intel.migration.import_existing import deduplicate_programs
        deduplicate_programs()


def cmd_sync(args):
    from bounty_intel.sync.delta import sync_all

    source = args.source or "all"
    sources = None if source == "all" else [source]
    results = sync_all(sources=sources)

    print("\n=== Sync Summary ===")
    for src, stats in results.items():
        if stats.get("error"):
            print(f"  {src}: SKIPPED ({stats['error']})")
        else:
            print(f"  {src}: {stats.get('upserted', 0)} upserted, {stats.get('skipped', 0)} skipped")


def cmd_forecast(args):
    from bounty_intel.forecast.engine import compute_forecast, print_forecast

    print("Computing forecast from DB...")
    fc = compute_forecast()
    print_forecast(fc)

    if getattr(args, "output", None):
        import json
        Path(args.output).write_text(json.dumps(fc, indent=2, default=str))
        print(f"\nForecast saved to {args.output}")


def cmd_serve(args):
    import uvicorn
    port = args.port or 8000
    print(f"Starting web dashboard on port {port}...")
    uvicorn.run("bounty_intel.web.app:app", host="0.0.0.0", port=port, reload=True)


def cmd_stats(args):
    from bounty_intel.client import BountyIntelClient
    client = BountyIntelClient()
    stats = client.get_stats()
    for k, v in stats.items():
        print(f"  {k}: {v}")


def cmd_mcp(args):
    from bounty_intel.mcp_server import main as mcp_main
    mcp_main()


def cmd_report(args):
    if args.action == "create":
        from bounty_intel.client import BountyIntelClient
        client = BountyIntelClient()

        content = Path(args.file).read_text()
        import re
        title_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
        title = title_match.group(1).strip() if title_match else Path(args.file).stem

        program = client.get_program(args.platform or "hackerone", args.program)
        if not program:
            print(f"Program not found: {args.program}")
            sys.exit(1)

        report_id = client.create_report(
            program_id=program.id,
            platform=args.platform or "hackerone",
            report_slug=Path(args.file).stem,
            title=title,
            markdown_body=content,
        )
        print(f"Report created: id={report_id}, title={title}")


def main():
    parser = argparse.ArgumentParser(prog="bounty-intel", description="Bounty Intelligence System")
    subparsers = parser.add_subparsers(dest="command")

    # migrate
    p_migrate = subparsers.add_parser("migrate", help="Create DB schema and optionally import data")
    p_migrate.add_argument("--import", dest="do_import", action="store_true", help="Import existing data")
    p_migrate.add_argument("--dedup", action="store_true", help="Deduplicate programs with same name")
    p_migrate.add_argument("--base-dir", help="Path to julius repo root")

    # sync
    p_sync = subparsers.add_parser("sync", help="Delta sync from platform APIs")
    p_sync.add_argument("--source", choices=["intigriti", "hackerone", "all"], default="all")

    # forecast
    subparsers.add_parser("forecast", help="Compute earnings forecast")

    # serve
    p_serve = subparsers.add_parser("serve", help="Start web dashboard")
    p_serve.add_argument("--port", type=int, default=8000)

    # stats
    subparsers.add_parser("stats", help="Show DB statistics")

    # mcp
    subparsers.add_parser("mcp", help="Start MCP server (stdio transport)")

    # report
    p_report = subparsers.add_parser("report", help="Manage submission reports")
    p_report.add_argument("action", choices=["create", "list"])
    p_report.add_argument("--program", help="Program handle")
    p_report.add_argument("--platform", default="hackerone")
    p_report.add_argument("--file", help="Markdown file to import")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    {
        "migrate": cmd_migrate,
        "sync": cmd_sync,
        "forecast": cmd_forecast,
        "serve": cmd_serve,
        "stats": cmd_stats,
        "mcp": cmd_mcp,
        "report": cmd_report,
    }[args.command](args)


if __name__ == "__main__":
    main()
