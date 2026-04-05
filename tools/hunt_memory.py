#!/usr/bin/env python3
"""JSONL-backed persistent cross-target pattern database for bug bounty hunting."""

import argparse
import fcntl
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone


class HuntMemory:
    def __init__(self, path="outputs/hunt_memory.jsonl"):
        self.path = path
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        if not os.path.exists(self.path):
            open(self.path, "a").close()

    def _load(self):
        records = []
        if not os.path.getsize(self.path):
            return records
        with open(self.path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def record(self, entry: dict):
        entry.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        entry.setdefault("chain", None)
        with open(self.path, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(json.dumps(entry) + "\n")
            fcntl.flock(f, fcntl.LOCK_UN)

    def query_by_tech(self, tech_stack: list, success_only=True) -> list:
        tech_set = {t.lower() for t in tech_stack}
        results = []
        for r in self._load():
            r_tech = {t.lower() for t in r.get("tech_stack", [])}
            if r_tech & tech_set:
                if not success_only or r.get("success"):
                    results.append(r)
        return sorted(results, key=lambda x: x.get("payout", 0), reverse=True)

    def query_by_vuln_class(self, vuln_class: str) -> list:
        vc = vuln_class.lower()
        results = [r for r in self._load() if r.get("vuln_class", "").lower() == vc]
        return sorted(results, key=lambda x: x.get("payout", 0), reverse=True)

    def suggest_attacks(self, tech_stack: list) -> list:
        tech_set = {t.lower() for t in tech_stack}
        by_class = defaultdict(lambda: {"success": 0, "total": 0, "payouts": [], "hints": set()})
        for r in self._load():
            r_tech = {t.lower() for t in r.get("tech_stack", [])}
            if not (r_tech & tech_set):
                continue
            vc = r.get("vuln_class", "unknown")
            bucket = by_class[vc]
            bucket["total"] += 1
            if r.get("success"):
                bucket["success"] += 1
                bucket["payouts"].append(r.get("payout", 0))
                if r.get("technique_summary"):
                    bucket["hints"].add(r["technique_summary"])
        suggestions = []
        for vc, b in by_class.items():
            avg_payout = sum(b["payouts"]) / len(b["payouts"]) if b["payouts"] else 0.0
            suggestions.append({
                "vuln_class": vc,
                "success_count": b["success"],
                "total_count": b["total"],
                "success_rate": b["success"] / b["total"] if b["total"] else 0.0,
                "avg_payout": avg_payout,
                "technique_hints": sorted(b["hints"]),
            })
        return sorted(suggestions, key=lambda x: x["success_count"] * x["avg_payout"], reverse=True)

    def get_acceptance_stats(self, vuln_class=None, platform=None) -> dict:
        records = self._load()
        if vuln_class:
            records = [r for r in records if r.get("vuln_class", "").lower() == vuln_class.lower()]
        if platform:
            records = [r for r in records if r.get("platform", "").lower() == platform.lower()]
        total = len(records)
        accepted = sum(1 for r in records if r.get("success"))
        rejected = total - accepted
        return {
            "total": total,
            "accepted": accepted,
            "rejected": rejected,
            "acceptance_rate": accepted / total if total else 0.0,
        }

    def get_stats(self) -> dict:
        records = self._load()
        by_class = defaultdict(lambda: {"total": 0, "success": 0})
        top_payouts = []
        for r in records:
            vc = r.get("vuln_class", "unknown")
            by_class[vc]["total"] += 1
            if r.get("success"):
                by_class[vc]["success"] += 1
            if r.get("payout", 0) > 0:
                top_payouts.append({"target": r.get("target"), "vuln_class": vc,
                                    "payout": r["payout"], "severity": r.get("severity")})
        top_payouts.sort(key=lambda x: x["payout"], reverse=True)
        success_rates = {vc: {"total": d["total"], "success": d["success"],
                              "rate": d["success"] / d["total"] if d["total"] else 0.0}
                         for vc, d in sorted(by_class.items())}
        return {"total_records": len(records), "success_rate_by_class": success_rates,
                "top_payouts": top_payouts[:10]}


def main():
    parser = argparse.ArgumentParser(description="Hunt Memory - cross-target pattern database")
    sub = parser.add_subparsers(dest="command")

    rec = sub.add_parser("record", help="Record a finding")
    rec.add_argument("--target", required=True)
    rec.add_argument("--domain", default=None)
    rec.add_argument("--vuln-class", required=True)
    rec.add_argument("--tech", default="", help="Comma-separated tech stack")
    rec.add_argument("--success", action="store_true")
    rec.add_argument("--payout", type=float, default=0)
    rec.add_argument("--severity", default="medium")
    rec.add_argument("--technique", default="")
    rec.add_argument("--chain", default=None)
    rec.add_argument("--platform", default=None)

    sug = sub.add_parser("suggest", help="Suggest attacks for a tech stack")
    sug.add_argument("--tech", required=True, help="Comma-separated tech stack")

    sub.add_parser("stats", help="Print summary statistics")

    acc = sub.add_parser("acceptance-stats", help="Acceptance statistics")
    acc.add_argument("--vuln-class", default=None)
    acc.add_argument("--platform", default=None)

    args = parser.parse_args()
    hm = HuntMemory()

    if args.command == "record":
        tech = [t.strip() for t in args.tech.split(",") if t.strip()]
        hm.record({"target": args.target, "domain": args.domain, "vuln_class": args.vuln_class,
                    "tech_stack": tech, "success": args.success, "payout": args.payout,
                    "severity": args.severity, "technique_summary": args.technique,
                    "chain": args.chain, "platform": args.platform})
        print("Recorded.")
    elif args.command == "suggest":
        tech = [t.strip() for t in args.tech.split(",") if t.strip()]
        print(json.dumps(hm.suggest_attacks(tech), indent=2))
    elif args.command == "stats":
        print(json.dumps(hm.get_stats(), indent=2))
    elif args.command == "acceptance-stats":
        print(json.dumps(hm.get_acceptance_stats(args.vuln_class, args.platform), indent=2))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
