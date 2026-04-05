#!/usr/bin/env python3
"""Unified safety tool: circuit breaker, rate limiter, and safe method policy."""

import argparse
import fcntl
import json
import os
import time
from urllib.parse import urlparse

CB_FILE, RL_FILE = "/tmp/julius_circuit_breaker.json", "/tmp/julius_rate_limiter.json"
CB_THRESHOLD, CB_COOLDOWN = 5, 300
RATE_LIMITS = {"recon": 10, "active": 2}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
BLOCKED_METHODS = {"PUT", "DELETE", "PATCH"}


def _load_json(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        fcntl.flock(f, fcntl.LOCK_SH)
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def _save_json(path, data):
    with open(path, "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        json.dump(data, f, indent=2)
        fcntl.flock(f, fcntl.LOCK_UN)


def _extract_host(url):
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.hostname or url


class CircuitBreaker:
    def __init__(self):
        self.state = _load_json(CB_FILE)

    def _save(self):
        _save_json(CB_FILE, self.state)

    def is_open(self, host):
        entry = self.state.get(host, {})
        if entry.get("failures", 0) >= CB_THRESHOLD:
            if time.time() - entry.get("last_failure", 0) < CB_COOLDOWN:
                return True
            # Cooldown expired, auto-reset
            self.reset(host)
        return False

    def record_failure(self, host):
        entry = self.state.setdefault(host, {"failures": 0})
        entry["failures"] = entry.get("failures", 0) + 1
        entry["last_failure"] = time.time()
        self._save()

    def record_success(self, host):
        if host in self.state:
            self.state[host] = {"failures": 0}
            self._save()

    def reset(self, host):
        self.state.pop(host, None)
        self._save()

    def status(self):
        return {h: {**v, "tripped": v.get("failures", 0) >= CB_THRESHOLD} for h, v in self.state.items()}


class RateLimiter:
    def __init__(self):
        self.state = _load_json(RL_FILE)

    def _save(self):
        _save_json(RL_FILE, self.state)

    def check(self, host, mode="active"):
        now = time.time()
        limit = RATE_LIMITS.get(mode, RATE_LIMITS["active"])
        window = 1.0  # 1-second sliding window
        timestamps = self.state.get(host, [])
        timestamps = [t for t in timestamps if now - t < window]
        self.state[host] = timestamps
        if len(timestamps) >= limit:
            wait = window - (now - timestamps[0])
            return False, max(0.0, wait)
        return True, 0.0

    def record(self, host):
        now = time.time()
        timestamps = self.state.get(host, [])
        timestamps = [t for t in timestamps if now - t < 1.0]
        timestamps.append(now)
        self.state[host] = timestamps
        self._save()

    def status(self):
        now = time.time()
        return {h: len([t for t in ts if now - t < 1.0]) for h, ts in self.state.items()}


class SafeMethodPolicy:
    @staticmethod
    def check(method):
        m = method.upper()
        if m in BLOCKED_METHODS:
            return False, f"{m} requires-confirmation: destructive method blocked by safety policy"
        return True, None


class SafetyRails:
    def __init__(self):
        self.cb = CircuitBreaker()
        self.rl = RateLimiter()
        self.policy = SafeMethodPolicy()

    def preflight(self, method, url, mode="active"):
        host = _extract_host(url)
        method_ok, method_msg = self.policy.check(method)
        cb_open = self.cb.is_open(host)
        rl_ok, wait = self.rl.check(host, mode)

        allowed = method_ok and not cb_open and rl_ok
        reasons = []
        if not method_ok:
            reasons.append(method_msg)
        if cb_open:
            reasons.append(f"circuit breaker tripped for {host}")
        if not rl_ok:
            reasons.append(f"rate limit exceeded for {host} ({mode}: {RATE_LIMITS.get(mode)}req/s)")

        if allowed:
            self.rl.record(host)

        return {
            "allowed": allowed,
            "checks": {"method_policy": method_ok, "circuit_breaker": not cb_open, "rate_limiter": rl_ok},
            "wait_seconds": round(wait, 3),
            "reason": "; ".join(reasons) if reasons else "all checks passed",
        }


def main():
    parser = argparse.ArgumentParser(description="Julius Safety Rails")
    sub = parser.add_subparsers(dest="command", required=True)

    pf = sub.add_parser("preflight", help="Run preflight checks")
    pf.add_argument("method")
    pf.add_argument("url")
    pf.add_argument("--mode", choices=["recon", "active"], default="active")

    rs = sub.add_parser("record-success", help="Record successful request")
    rs.add_argument("host")

    rf = sub.add_parser("record-failure", help="Record failed request")
    rf.add_argument("host")

    sub.add_parser("status", help="Show all state")

    rt = sub.add_parser("reset", help="Reset circuit breaker for host")
    rt.add_argument("host")

    args = parser.parse_args()
    rails = SafetyRails()

    if args.command == "preflight":
        result = rails.preflight(args.method, args.url, args.mode)
        print(json.dumps(result, indent=2))
    elif args.command == "record-success":
        rails.cb.record_success(args.host)
        print(f"Recorded success for {args.host}")
    elif args.command == "record-failure":
        rails.cb.record_failure(args.host)
        print(f"Recorded failure for {args.host}")
    elif args.command == "status":
        print(json.dumps({"circuit_breaker": rails.cb.status(), "rate_limiter": rails.rl.status()}, indent=2))
    elif args.command == "reset":
        rails.cb.reset(args.host)
        print(f"Reset circuit breaker for {args.host}")


if __name__ == "__main__":
    main()
