#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)"
VENV_PYTHON="$REPO_ROOT/.venv/bin/python"
SERVER="$REPO_ROOT/bounty_intel/mcp_server.py"

if [ -x "$VENV_PYTHON" ]; then
  exec "$VENV_PYTHON" "$SERVER"
fi

exec python3 "$SERVER"
