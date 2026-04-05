#!/usr/bin/env python3
"""Deterministic scope validation tool for bug bounty and pentesting engagements."""

import argparse
import ipaddress
import json
import sys
from pathlib import Path


class ScopeChecker:
    def __init__(self, domains=None, ips=None, oos=None):
        self.domains = domains or []
        self.ips = ips or []
        self.oos = oos or []

    @classmethod
    def from_file(cls, path):
        data = json.loads(Path(path).read_text())
        return cls(
            domains=data.get("domains", []),
            ips=data.get("ips", []),
            oos=data.get("oos", []),
        )

    def to_file(self, path):
        Path(path).write_text(json.dumps(
            {"domains": self.domains, "ips": self.ips, "oos": self.oos},
            indent=2,
        ) + "\n")

    def _match_domain(self, target, pattern):
        """Anchored suffix match: *.x.com matches sub.x.com but not evil-x.com."""
        target = target.lower().rstrip(".")
        pattern = pattern.lower().rstrip(".")
        if pattern.startswith("*."):
            suffix = pattern[1:]  # e.g. ".target.com"
            return target == suffix[1:] or target.endswith(suffix)
        return target == pattern

    def _match_ip(self, target, spec):
        """Match IP against exact IP or CIDR range."""
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            return False
        try:
            network = ipaddress.ip_network(spec, strict=False)
            return addr in network
        except ValueError:
            return False

    def _matches_any(self, target, domains, ips):
        for pattern in domains:
            if self._match_domain(target, pattern):
                return True
        for spec in ips:
            if self._match_ip(target, spec):
                return True
        return False

    def is_in_scope(self, target):
        """Returns (bool, str) — deny-first: OOS checked before in-scope."""
        target = target.strip().lower()
        oos_domains = [e for e in self.oos if not _is_ip(e)]
        oos_ips = [e for e in self.oos if _is_ip(e)]

        # OOS deny-first
        if self._matches_any(target, oos_domains, oos_ips):
            return False, f"DENIED: {target} matches out-of-scope rule"

        # In-scope check
        if self._matches_any(target, self.domains, self.ips):
            return True, f"ALLOWED: {target} is in scope"

        return False, f"DENIED: {target} does not match any in-scope rule"


def _is_ip(s):
    """Quick check if string looks like an IP or CIDR."""
    try:
        ipaddress.ip_address(s.split("/")[0])
        return True
    except ValueError:
        return False


def cmd_check(args):
    checker = ScopeChecker.from_file(args.scope)
    allowed, reason = checker.is_in_scope(args.target)
    print(reason)
    sys.exit(0 if allowed else 1)


def cmd_generate(args):
    domains = [d.strip() for d in args.domains.split(",")] if args.domains else []
    ips = [i.strip() for i in args.ips.split(",")] if args.ips else []
    oos = [o.strip() for o in args.oos.split(",")] if args.oos else []
    checker = ScopeChecker(domains=domains, ips=ips, oos=oos)
    checker.to_file(args.output)
    print(f"Scope written to {args.output}")


def main():
    parser = argparse.ArgumentParser(description="Scope validation tool")
    sub = parser.add_subparsers(dest="command", required=True)

    check_p = sub.add_parser("check", help="Check if target is in scope")
    check_p.add_argument("target", help="Domain or IP to check")
    check_p.add_argument("--scope", required=True, help="Path to scope.json")

    gen_p = sub.add_parser("generate", help="Generate scope.json")
    gen_p.add_argument("--domains", default="", help="Comma-separated domains")
    gen_p.add_argument("--ips", default="", help="Comma-separated IPs/CIDRs")
    gen_p.add_argument("--oos", default="", help="Comma-separated out-of-scope entries")
    gen_p.add_argument("--output", default="scope.json", help="Output path")

    args = parser.parse_args()
    if args.command == "check":
        cmd_check(args)
    elif args.command == "generate":
        cmd_generate(args)


if __name__ == "__main__":
    main()
