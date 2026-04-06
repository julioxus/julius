"""HTTP client for the Bounty Intel API.

All operations go through the REST API served by the Cloud Run dashboard.
No direct database access — the API server handles all DB interaction.

Usage:
    from bounty_intel.client import BountyIntelClient
    db = BountyIntelClient()  # reads API URL + key from .env
    programs = db.list_programs()
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import requests

from bounty_intel.config import settings

DEFAULT_API_URL = "https://bounty-dashboard-887002731862.europe-west1.run.app"


class BountyIntelClient:
    """HTTP client for the Bounty Intel REST API."""

    def __init__(self, api_url: str | None = None, api_key: str | None = None):
        self.api_url = (api_url or settings.bounty_intel_api_url or DEFAULT_API_URL).rstrip("/")
        self.api_key = api_key or settings.bounty_intel_api_key
        if not self.api_key:
            raise ValueError(
                "BOUNTY_INTEL_API_KEY not set. Add it to .env:\n"
                "  BOUNTY_INTEL_API_KEY=<your-api-key>"
            )

    def _headers(self) -> dict[str, str]:
        return {"X-API-Key": self.api_key, "Content-Type": "application/json"}

    def _get(self, path: str, params: dict | None = None) -> Any:
        resp = requests.get(f"{self.api_url}{path}", headers=self._headers(), params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, data: dict | None = None) -> Any:
        resp = requests.post(f"{self.api_url}{path}", headers=self._headers(), json=data or {}, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def _patch(self, path: str, data: dict) -> Any:
        resp = requests.patch(f"{self.api_url}{path}", headers=self._headers(), json=data, timeout=30)
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Programs
    # ------------------------------------------------------------------
    def list_programs(self, platform: str | None = None, status: str | None = None) -> list[dict]:
        params = {}
        if platform:
            params["platform"] = platform
        if status:
            params["status"] = status
        return self._get("/api/v1/programs", params)

    def upsert_program(self, *, platform: str, handle: str, company_name: str, **kwargs) -> int:
        data = {"platform": platform, "handle": handle, "company_name": company_name, **kwargs}
        return self._post("/api/v1/programs", data)["id"]

    # ------------------------------------------------------------------
    # Engagements
    # ------------------------------------------------------------------
    def get_engagement(self, platform: str, handle: str) -> dict | None:
        try:
            return self._get(f"/api/v1/engagements/{platform}/{handle}")
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                return None
            raise

    def create_engagement(self, program_id: int, **kwargs) -> int:
        data = {"program_id": program_id, **kwargs}
        return self._post("/api/v1/engagements", data)["id"]

    def update_engagement(self, engagement_id: int, **kwargs) -> None:
        self._patch(f"/api/v1/engagements/{engagement_id}", kwargs)

    # ------------------------------------------------------------------
    # Recon & Attack Surface
    # ------------------------------------------------------------------
    def get_program_recon(self, program_id: int) -> dict:
        """Get structured recon data for a program."""
        try:
            return self._get(f"/api/v1/programs/{program_id}/recon")
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                return {}
            raise

    def get_attack_surface(self, program_id: int) -> dict:
        """Get attack surface summary for a program."""
        try:
            return self._get(f"/api/v1/programs/{program_id}/attack-surface")
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                return {}
            raise

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------
    def get_findings(self, *, program_id: int | None = None, status: str | None = None,
                     vuln_class: str | None = None, is_building_block: bool | None = None) -> list[dict]:
        params = {}
        if program_id:
            params["program_id"] = program_id
        if status:
            params["status"] = status
        if vuln_class:
            params["vuln_class"] = vuln_class
        if is_building_block is not None:
            params["is_building_block"] = "1" if is_building_block else "0"
        return self._get("/api/v1/findings", params)

    def save_finding(self, *, program_id: int, **kwargs) -> int:
        data = {"program_id": program_id, **kwargs}
        return self._post("/api/v1/findings", data)["id"]

    def update_finding(self, finding_id: int, **kwargs) -> None:
        self._patch(f"/api/v1/findings/{finding_id}", kwargs)

    def get_finding_evidence(self, finding_id: int) -> list[dict]:
        """Get evidence files associated with a finding."""
        return self._get(f"/api/v1/findings/{finding_id}/evidence")

    def delete_finding(self, finding_id: int) -> None:
        resp = requests.delete(f"{self.api_url}/api/v1/findings/{finding_id}",
                               headers=self._headers(), timeout=30)
        resp.raise_for_status()

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------
    def list_reports(self, status: str | None = None, program_id: int | None = None) -> list[dict]:
        params = {}
        if status:
            params["status"] = status
        if program_id:
            params["program_id"] = program_id
        return self._get("/api/v1/reports", params)

    def create_report(self, *, program_id: int, platform: str, title: str,
                      markdown_body: str, **kwargs) -> int:
        data = {"program_id": program_id, "platform": platform, "title": title,
                "markdown_body": markdown_body, **kwargs}
        return self._post("/api/v1/reports", data)["id"]

    def update_report(self, report_id: int, **kwargs) -> None:
        self._patch(f"/api/v1/reports/{report_id}", kwargs)

    def delete_report(self, report_id: int) -> None:
        resp = requests.delete(f"{self.api_url}/api/v1/reports/{report_id}",
                               headers=self._headers(), timeout=30)
        resp.raise_for_status()

    def mark_report_submitted(self, report_id: int, platform_submission_id: str) -> None:
        self._post(f"/api/v1/reports/{report_id}/submit",
                   {"platform_submission_id": platform_submission_id})

    # ------------------------------------------------------------------
    # Submissions
    # ------------------------------------------------------------------
    def get_submissions(self, *, platform: str | None = None, disposition: str | None = None,
                        program_id: int | None = None) -> list[dict]:
        params = {}
        if platform:
            params["platform"] = platform
        if disposition:
            params["disposition"] = disposition
        if program_id:
            params["program_id"] = program_id
        return self._get("/api/v1/submissions", params)

    # ------------------------------------------------------------------
    # Hunt Memory
    # ------------------------------------------------------------------
    def record_hunt(self, *, target: str, vuln_class: str, **kwargs) -> int:
        data = {"target": target, "vuln_class": vuln_class, **kwargs}
        return self._post("/api/v1/hunt", data)["id"]

    def suggest_attacks(self, tech_stack: list[str]) -> list[dict]:
        return self._get("/api/v1/hunt/suggest", {"tech_stack": ",".join(tech_stack)})

    def get_hunt_memory(self, target: str | None = None, vuln_class: str | None = None) -> list[dict]:
        params = {}
        if target:
            params["target"] = target
        if vuln_class:
            params["vuln_class"] = vuln_class
        return self._get("/api/v1/hunt", params)

    # ------------------------------------------------------------------
    # Activity
    # ------------------------------------------------------------------
    def log_activity(self, engagement_id: int | None, action: str, details: dict | None = None) -> int:
        data = {"engagement_id": engagement_id, "action": action, "details": details or {}}
        return self._post("/api/v1/activity", data)["id"]

    # ------------------------------------------------------------------
    # AI Evaluations
    # ------------------------------------------------------------------
    def save_ai_evaluation(self, submission_id: int, **kwargs) -> int:
        data = {"submission_id": submission_id, **kwargs}
        return self._post("/api/v1/evaluations", data)["id"]

    # ------------------------------------------------------------------
    # Sync
    # ------------------------------------------------------------------
    def sync(self, source: str = "all") -> dict:
        return self._post("/api/v1/sync", {"source": source})

    # ------------------------------------------------------------------
    # Forecast
    # ------------------------------------------------------------------
    def forecast(self) -> dict:
        return self._get("/api/v1/forecast")

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------
    def get_stats(self) -> dict:
        return self._get("/api/v1/stats")
