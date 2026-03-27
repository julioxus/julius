#!/usr/bin/env python3
"""Read environment variables from .env files reliably.

Usage: python3 .claude/tools/env-reader.py VAR1 VAR2 VAR3

Searches for .env in current directory and parent directories.
Prints VAR=value for found variables, VAR=NOT_SET for missing ones.
"""

import os
import sys
from pathlib import Path


def find_env_file():
    """Walk up from cwd to find .env file."""
    current = Path.cwd()
    while current != current.parent:
        env_path = current / ".env"
        if env_path.is_file():
            return env_path
        current = current.parent
    return None


def parse_env_file(path):
    """Parse .env file into dict, handling quotes and comments."""
    env = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            # Strip surrounding quotes
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            env[key] = value
    return env


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 .claude/tools/env-reader.py VAR1 [VAR2 ...]", file=sys.stderr)
        sys.exit(1)

    requested = sys.argv[1:]
    env_file = find_env_file()

    file_env = parse_env_file(env_file) if env_file else {}

    for var in requested:
        # Check .env file first, then OS environment
        value = file_env.get(var) or os.environ.get(var)
        if value:
            print(f"{var}={value}")
        else:
            print(f"{var}=NOT_SET")


if __name__ == "__main__":
    main()
