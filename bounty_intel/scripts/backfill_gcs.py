#!/usr/bin/env python3
"""Backfill local evidence files to GCS via API + gsutil.

Usage: .venv/bin/python bounty_intel/scripts/backfill_gcs.py
Requires: BOUNTY_INTEL_API_URL and BOUNTY_INTEL_API_KEY in .env
"""

import json
import os
import subprocess
import sys
from pathlib import Path

# Load .env
env_path = Path(__file__).resolve().parents[2] / ".env"
if env_path.exists():
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

API_URL = os.environ.get("BOUNTY_INTEL_API_URL", "").rstrip("/")
API_KEY = os.environ.get("BOUNTY_INTEL_API_KEY", "")
GCS_BUCKET = "julius-bounty-evidence"

if not API_URL or not API_KEY:
    print("ERROR: Set BOUNTY_INTEL_API_URL and BOUNTY_INTEL_API_KEY in .env")
    sys.exit(1)

import urllib.request


def api_get(path):
    req = urllib.request.Request(f"{API_URL}/api/v1{path}", headers={"X-API-Key": API_KEY})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def api_patch(path, data):
    body = json.dumps(data).encode()
    req = urllib.request.Request(
        f"{API_URL}/api/v1{path}", data=body, method="PATCH",
        headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def gsutil_cp(local_path, gcs_path):
    result = subprocess.run(
        ["gsutil", "-q", "cp", str(local_path), gcs_path],
        capture_output=True, text=True, timeout=60,
    )
    return result.returncode == 0


def main():
    uploaded = 0
    skipped = 0
    errors = 0
    offset = 0
    batch_size = 500

    while True:
        files = api_get(f"/evidence/needs-backfill?limit={batch_size}&offset={offset}")
        if not files:
            break

        print(f"Batch: {len(files)} files (offset={offset})")
        for ef in files:
            local = Path(ef["local_path"])
            if not local.exists():
                skipped += 1
                continue

            prefix = f"findings/{ef['finding_id']}" if ef.get("finding_id") else f"reports/{ef.get('report_id')}"
            gcs_path = f"gs://{GCS_BUCKET}/{prefix}/{local.name}"

            if gsutil_cp(local, gcs_path):
                try:
                    api_patch(f"/evidence/{ef['id']}/gcs", {"gcs_path": gcs_path})
                    uploaded += 1
                except Exception as exc:
                    errors += 1
                    print(f"  ERROR updating DB for {ef['id']}: {exc}")
            else:
                errors += 1
                print(f"  ERROR uploading {local}")

            if (uploaded + skipped + errors) % 100 == 0:
                print(f"  Progress: uploaded={uploaded}, skipped={skipped}, errors={errors}")

        # Don't increment offset — successfully backfilled records disappear from the query
        if len(files) < batch_size:
            break

    print(f"\nDone! uploaded={uploaded}, skipped={skipped}, errors={errors}")


if __name__ == "__main__":
    main()
