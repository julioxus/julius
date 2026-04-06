"""Bounty Intel MCP Server — exposes all Bounty Intel API operations as MCP tools.

Run directly:  python -m bounty_intel.mcp_server
Or via CLI:    bounty-intel mcp
"""

from __future__ import annotations

import logging
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("bounty-intel-mcp")
logger.addHandler(logging.StreamHandler(sys.stderr))
logger.setLevel(logging.INFO)

mcp = FastMCP("bounty-intel")

# Lazy singleton — avoids crash at startup if env vars are missing
_client = None


def _get_client():
    global _client
    if _client is None:
        from bounty_intel.client import BountyIntelClient
        _client = BountyIntelClient()
    return _client


def _safe_call(fn, *args, **kwargs) -> Any:
    """Wrap client calls — return error dict instead of raising."""
    try:
        result = fn(*args, **kwargs)
        return result if result is not None else {"status": "ok"}
    except Exception as e:
        status = getattr(getattr(e, "response", None), "status_code", None)
        err = {"error": str(e)}
        if status:
            err["status_code"] = status
        return err


# ── Programs (3) ────────────────────────────────────────────


@mcp.tool()
def bounty_list_programs(platform: str = "", status: str = "") -> list[dict]:
    """List all bug bounty programs.

    Use to see available programs, filter by platform (hackerone, intigriti)
    or status (open, closed, paused). Returns id, company name, platform, and handle.
    """
    c = _get_client()
    return _safe_call(c.list_programs, platform=platform or None, status=status or None)


@mcp.tool()
def bounty_get_program(program_id: int) -> dict:
    """Get full details of a specific program including scope and out-of-scope rules.

    Use when you need the program's scope (domains, endpoints), OOS rules,
    tech stack, or other details not included in the list view.
    """
    c = _get_client()
    return _safe_call(c.get_program, program_id)


@mcp.tool()
def bounty_upsert_program(
    platform: str,
    handle: str,
    company_name: str,
    status: str = "open",
    bounty_type: str = "bounty",
    tech_stack: list[str] | None = None,
    notes: str = "",
) -> dict:
    """Create or update a bug bounty program.

    Use when onboarding a new program or updating program metadata.
    Platform is 'hackerone' or 'intigriti'. Handle is the program's slug on that platform.
    """
    c = _get_client()
    kwargs: dict[str, Any] = {"status": status, "bounty_type": bounty_type, "notes": notes}
    if tech_stack:
        kwargs["tech_stack"] = tech_stack
    pid = _safe_call(c.upsert_program, platform=platform, handle=handle,
                     company_name=company_name, **kwargs)
    if isinstance(pid, int):
        return {"id": pid}
    return pid


# ── Engagements (4) ─────────────────────────────────────────


@mcp.tool()
def bounty_list_engagements(status: str = "", program_id: int = 0) -> list[dict]:
    """List all engagements across programs.

    Use to see which engagements are active, paused, or completed.
    Filter by status or program_id. Returns engagement id, program, status, and start date.
    """
    c = _get_client()
    return _safe_call(c.list_engagements, status=status or None,
                      program_id=program_id or None)


@mcp.tool()
def bounty_get_engagement(platform: str, handle: str) -> dict:
    """Get the most recent engagement for a program by platform and handle.

    Use when you know the platform (hackerone/intigriti) and program handle.
    Returns engagement details including recon data and attack surface.
    """
    c = _get_client()
    return _safe_call(c.get_engagement, platform, handle)


@mcp.tool()
def bounty_create_engagement(program_id: int, status: str = "active", notes: str = "") -> dict:
    """Start a new engagement for a program.

    Use when beginning work on a program. Links findings and activity to this engagement.
    """
    c = _get_client()
    eid = _safe_call(c.create_engagement, program_id, status=status, notes=notes)
    if isinstance(eid, int):
        return {"id": eid}
    return eid


@mcp.tool()
def bounty_update_engagement(
    engagement_id: int,
    status: str = "",
    notes: str = "",
    recon_data: dict | None = None,
    attack_surface: dict | None = None,
) -> dict:
    """Update an engagement's status, notes, recon data, or attack surface.

    Use to store recon results (subdomains, endpoints) or update engagement status.
    Only provided fields are updated.
    """
    c = _get_client()
    kwargs: dict[str, Any] = {}
    if status:
        kwargs["status"] = status
    if notes:
        kwargs["notes"] = notes
    if recon_data is not None:
        kwargs["recon_data"] = recon_data
    if attack_surface is not None:
        kwargs["attack_surface"] = attack_surface
    return _safe_call(c.update_engagement, engagement_id, **kwargs)


# ── Recon (2) ────────────────────────────────────────────────


@mcp.tool()
def bounty_get_recon(program_id: int) -> dict:
    """Get reconnaissance data for a program.

    Returns structured recon: subdomains, endpoints, API specs, technologies discovered.
    Use before testing to understand the attack surface.
    """
    c = _get_client()
    return _safe_call(c.get_program_recon, program_id)


@mcp.tool()
def bounty_get_attack_surface(program_id: int) -> dict:
    """Get the attack surface summary for a program.

    Returns scope coverage, tested/untested areas, and surface statistics.
    Use to identify gaps in testing coverage.
    """
    c = _get_client()
    return _safe_call(c.get_attack_surface, program_id)


# ── Findings (7) ────────────────────────────────────────────


@mcp.tool()
def bounty_get_findings(
    program_id: int = 0,
    status: str = "",
    vuln_class: str = "",
    is_building_block: bool | None = None,
) -> list[dict]:
    """List vulnerability findings with optional filters.

    Filter by program, status (discovered/reported/accepted/rejected/duplicate),
    vuln_class (xss, sqli, ssrf, idor, etc.), or building block flag.
    Returns summary view (description truncated to 500 chars).
    Use bounty_get_finding for full details of a specific finding.
    """
    c = _get_client()
    return _safe_call(c.get_findings, program_id=program_id or None,
                      status=status or None, vuln_class=vuln_class or None,
                      is_building_block=is_building_block)


@mcp.tool()
def bounty_get_finding(finding_id: int) -> dict:
    """Get full details of a specific finding.

    Returns all fields: description, steps to reproduce, impact, PoC code/output,
    CVSS vector, chain information, and building block notes.
    Use this when you need the complete finding content (not the truncated list view).
    """
    c = _get_client()
    return _safe_call(c.get_finding, finding_id)


@mcp.tool()
def bounty_search_findings(query: str, program_id: int = 0) -> list[dict]:
    """Search findings by text across titles and descriptions.

    Use to find existing findings about a specific vulnerability type or target.
    Example: bounty_search_findings("SSRF") or bounty_search_findings("admin panel", program_id=5)
    Returns up to 50 results.
    """
    c = _get_client()
    return _safe_call(c.search_findings, query, program_id=program_id or None)


@mcp.tool()
def bounty_save_finding(
    program_id: int,
    title: str,
    vuln_class: str = "",
    severity: str = "",
    cvss_vector: str = "",
    status: str = "discovered",
    description: str = "",
    steps_to_reproduce: str = "",
    impact: str = "",
    poc_code: str = "",
    poc_output: str = "",
    is_building_block: bool = False,
    building_block_notes: str = "",
    engagement_id: int | None = None,
    chain_with: list[int] | None = None,
) -> dict:
    """Save a new vulnerability finding.

    Use after discovering a vulnerability. Severity: critical/high/medium/low/info.
    Set is_building_block=True for findings that are part of an attack chain but not
    independently submittable. Link to other findings via chain_with (list of finding IDs).
    """
    c = _get_client()
    kwargs: dict[str, Any] = {
        "title": title, "vuln_class": vuln_class, "severity": severity,
        "cvss_vector": cvss_vector, "status": status, "description": description,
        "steps_to_reproduce": steps_to_reproduce, "impact": impact,
        "poc_code": poc_code, "poc_output": poc_output,
        "is_building_block": is_building_block, "building_block_notes": building_block_notes,
    }
    if engagement_id is not None:
        kwargs["engagement_id"] = engagement_id
    if chain_with:
        kwargs["chain_with"] = chain_with
    fid = _safe_call(c.save_finding, program_id=program_id, **kwargs)
    if isinstance(fid, int):
        return {"id": fid}
    return fid


@mcp.tool()
def bounty_update_finding(
    finding_id: int,
    status: str = "",
    severity: str = "",
    cvss_vector: str = "",
    vuln_class: str = "",
    description: str = "",
    impact: str = "",
    steps_to_reproduce: str = "",
    is_building_block: bool | None = None,
    building_block_notes: str = "",
) -> dict:
    """Update an existing finding's fields. Only provided non-empty fields are updated.

    Use to change status, upgrade severity, add description/impact, or toggle building block.
    """
    c = _get_client()
    kwargs: dict[str, Any] = {}
    if status:
        kwargs["status"] = status
    if severity:
        kwargs["severity"] = severity
    if cvss_vector:
        kwargs["cvss_vector"] = cvss_vector
    if vuln_class:
        kwargs["vuln_class"] = vuln_class
    if description:
        kwargs["description"] = description
    if impact:
        kwargs["impact"] = impact
    if steps_to_reproduce:
        kwargs["steps_to_reproduce"] = steps_to_reproduce
    if is_building_block is not None:
        kwargs["is_building_block"] = is_building_block
    if building_block_notes:
        kwargs["building_block_notes"] = building_block_notes
    return _safe_call(c.update_finding, finding_id, **kwargs)


@mcp.tool()
def bounty_get_finding_evidence(finding_id: int) -> list[dict]:
    """Get evidence files attached to a finding (screenshots, PoC videos, HTTP logs).

    Returns file metadata: id, filename, content type, size, paths.
    Use bounty_get_evidence_url to get a download link for a specific file.
    """
    c = _get_client()
    return _safe_call(c.get_finding_evidence, finding_id)


@mcp.tool()
def bounty_delete_finding(finding_id: int) -> dict:
    """Delete a finding. Fails if the finding is linked to a submitted report.

    Use with caution — only for findings that were created in error.
    """
    c = _get_client()
    return _safe_call(c.delete_finding, finding_id)


# ── Reports (7) ─────────────────────────────────────────────


@mcp.tool()
def bounty_list_reports(status: str = "", program_id: int = 0) -> list[dict]:
    """List submission reports. Filter by status (draft/submitted/accepted/rejected) or program.

    Returns summary without markdown body. Use bounty_get_report for full content.
    """
    c = _get_client()
    return _safe_call(c.list_reports, status=status or None,
                      program_id=program_id or None)


@mcp.tool()
def bounty_get_report(report_id: int) -> dict:
    """Get full report including markdown body, validation result, and timestamps.

    Use to review or edit a report before submission.
    """
    c = _get_client()
    return _safe_call(c.get_report, report_id)


@mcp.tool()
def bounty_create_report(
    program_id: int,
    platform: str,
    title: str,
    markdown_body: str,
    finding_id: int | None = None,
    severity: str = "",
    cvss_vector: str = "",
    report_slug: str = "",
) -> dict:
    """Create a new submission report (draft).

    Reports document a vulnerability for platform submission. Platform is 'hackerone' or 'intigriti'.
    Optionally link to a finding. The report starts in 'draft' status.
    """
    c = _get_client()
    kwargs: dict[str, Any] = {}
    if finding_id:
        kwargs["finding_id"] = finding_id
    if severity:
        kwargs["severity"] = severity
    if cvss_vector:
        kwargs["cvss_vector"] = cvss_vector
    if report_slug:
        kwargs["report_slug"] = report_slug
    rid = _safe_call(c.create_report, program_id=program_id, platform=platform,
                     title=title, markdown_body=markdown_body, **kwargs)
    if isinstance(rid, int):
        return {"id": rid}
    return rid


@mcp.tool()
def bounty_update_report(
    report_id: int,
    markdown_body: str = "",
    status: str = "",
) -> dict:
    """Update a report's markdown body or status.

    Use to refine the report content or change its status.
    """
    c = _get_client()
    kwargs: dict[str, Any] = {}
    if markdown_body:
        kwargs["markdown_body"] = markdown_body
    if status:
        kwargs["status"] = status
    return _safe_call(c.update_report, report_id, **kwargs)


@mcp.tool()
def bounty_delete_report(report_id: int) -> dict:
    """Delete a report. Fails if the report has been submitted or accepted.

    Use only for draft reports that are no longer needed.
    """
    c = _get_client()
    return _safe_call(c.delete_report, report_id)


@mcp.tool()
def bounty_mark_report_submitted(report_id: int, platform_submission_id: str) -> dict:
    """Mark a report as submitted to the platform.

    Call after actually submitting on HackerOne/Intigriti. Provide the platform's
    submission/report ID for cross-reference.
    """
    c = _get_client()
    return _safe_call(c.mark_report_submitted, report_id, platform_submission_id)


@mcp.tool()
def bounty_get_report_evidence(report_id: int) -> list[dict]:
    """Get evidence files linked to a report.

    Similar to bounty_get_finding_evidence but for report-level attachments.
    """
    c = _get_client()
    return _safe_call(c.get_report_evidence, report_id)


# ── Submissions (1) ─────────────────────────────────────────


@mcp.tool()
def bounty_get_submissions(
    platform: str = "",
    disposition: str = "",
    program_id: int = 0,
) -> list[dict]:
    """List submissions synced from HackerOne/Intigriti platforms.

    Submissions are auto-synced from platform APIs. Filter by platform,
    disposition (new/triaged/resolved/duplicate/informative/not_applicable),
    or program. Returns bounty amounts and company names.
    """
    c = _get_client()
    return _safe_call(c.get_submissions, platform=platform or None,
                      disposition=disposition or None,
                      program_id=program_id or None)


# ── Payouts (1) ─────────────────────────────────────────────


@mcp.tool()
def bounty_get_payouts(submission_id: int = 0, program_id: int = 0) -> list[dict]:
    """List bounty payouts. Filter by submission or program.

    Returns amount, currency, EUR equivalent, payout type, status, and paid date.
    Use to check earnings or find unpaid bounties.
    """
    c = _get_client()
    return _safe_call(c.get_payouts, submission_id=submission_id or None,
                      program_id=program_id or None)


# ── Hunt Memory (3) ─────────────────────────────────────────


@mcp.tool()
def bounty_record_hunt(
    target: str,
    vuln_class: str,
    success: bool = False,
    payout: float = 0,
    severity: str = "",
    technique: str = "",
    chain: str = "",
    platform: str = "",
    tech_stack: list[str] | None = None,
    domain: str = "",
) -> dict:
    """Record a hunt attempt in memory for cross-engagement learning.

    Records what was tested, whether it worked, and the technique used.
    This builds up pattern data used by bounty_suggest_attacks.
    """
    c = _get_client()
    kwargs: dict[str, Any] = {
        "success": success, "payout": payout, "severity": severity,
        "technique": technique, "chain": chain, "platform": platform, "domain": domain,
    }
    if tech_stack:
        kwargs["tech_stack"] = tech_stack
    hid = _safe_call(c.record_hunt, target=target, vuln_class=vuln_class, **kwargs)
    if isinstance(hid, int):
        return {"id": hid}
    return hid


@mcp.tool()
def bounty_suggest_attacks(tech_stack: list[str]) -> list[dict]:
    """Get attack suggestions based on technology stack.

    Analyzes past hunt memory to suggest which vulnerability classes are most likely
    to succeed for the given tech stack. Returns success rates and average payouts.
    Example: bounty_suggest_attacks(["react", "graphql", "node"])
    """
    c = _get_client()
    return _safe_call(c.suggest_attacks, tech_stack)


@mcp.tool()
def bounty_get_hunt_memory(target: str = "", vuln_class: str = "") -> list[dict]:
    """Query past hunt attempts. Filter by target or vulnerability class.

    Use to check what has already been tested against a target or which techniques
    were used for a given vulnerability class.
    """
    c = _get_client()
    return _safe_call(c.get_hunt_memory, target=target or None,
                      vuln_class=vuln_class or None)


# ── Evidence (2) ─────────────────────────────────────────────


@mcp.tool()
def bounty_upload_evidence(
    finding_id: int,
    filename: str,
    local_path: str = "",
    content_type: str = "",
    size_bytes: int = 0,
    report_id: int | None = None,
) -> dict:
    """Upload evidence for a finding (screenshot, video, HTTP log).

    Registers the file metadata in the database. If local_path points to an existing file,
    it will be uploaded to Google Cloud Storage automatically.
    Optionally link to a report via report_id.
    """
    c = _get_client()
    return _safe_call(c.upload_evidence, finding_id, filename,
                      local_path=local_path, content_type=content_type,
                      size_bytes=size_bytes, report_id=report_id)


@mcp.tool()
def bounty_get_evidence_url(evidence_id: int) -> dict:
    """Get a signed download URL for an evidence file stored in GCS.

    Returns a time-limited URL to view/download the evidence. Fails if the file
    is local-only (no GCS path).
    """
    c = _get_client()
    return _safe_call(c.get_evidence_url, evidence_id)


# ── Activity (2) ─────────────────────────────────────────────


@mcp.tool()
def bounty_log_activity(
    action: str,
    engagement_id: int | None = None,
    details: dict | None = None,
) -> dict:
    """Log an activity event (testing action, discovery, status change).

    Use to maintain an audit trail of what was done during an engagement.
    """
    c = _get_client()
    aid = _safe_call(c.log_activity, engagement_id, action, details)
    if isinstance(aid, int):
        return {"id": aid}
    return aid


@mcp.tool()
def bounty_get_activity(engagement_id: int = 0, limit: int = 100) -> list[dict]:
    """List recent activity logs. Filter by engagement. Max 500 entries.

    Use to review what has been done during an engagement.
    """
    c = _get_client()
    return _safe_call(c.get_activity, engagement_id=engagement_id or None,
                      limit=min(limit, 500))


# ── AI Evaluation (1) ───────────────────────────────────────


@mcp.tool()
def bounty_save_ai_evaluation(
    submission_id: int,
    acceptance_probability: float,
    confidence: float = 0,
    likely_outcome: str = "",
    severity_assessment: str = "",
    strengths: list[str] | None = None,
    weaknesses: list[str] | None = None,
    triager_reasoning: str = "",
    suggested_improvements: list[str] | None = None,
) -> dict:
    """Save an AI evaluation of a submission's acceptance probability.

    Records the AI's assessment of whether a submission will be accepted,
    including confidence, reasoning, and suggestions for improvement.
    """
    c = _get_client()
    kwargs: dict[str, Any] = {
        "acceptance_probability": acceptance_probability,
        "confidence": confidence, "likely_outcome": likely_outcome,
        "severity_assessment": severity_assessment,
        "triager_reasoning": triager_reasoning,
    }
    if strengths:
        kwargs["strengths"] = strengths
    if weaknesses:
        kwargs["weaknesses"] = weaknesses
    if suggested_improvements:
        kwargs["suggested_improvements"] = suggested_improvements
    eid = _safe_call(c.save_ai_evaluation, submission_id, **kwargs)
    if isinstance(eid, int):
        return {"id": eid}
    return eid


# ── Ops (3) ──────────────────────────────────────────────────


@mcp.tool()
def bounty_sync(source: str = "all") -> dict:
    """Sync submissions from bug bounty platforms.

    Source can be 'all', 'hackerone', or 'intigriti'. Performs delta sync
    to pull new/updated submissions from the platform APIs.
    """
    c = _get_client()
    return _safe_call(c.sync, source)


@mcp.tool()
def bounty_forecast() -> dict:
    """Get earnings forecast based on current submissions and historical data.

    Returns projected earnings, acceptance rates, and confidence intervals.
    """
    c = _get_client()
    return _safe_call(c.forecast)


@mcp.tool()
def bounty_get_stats() -> dict:
    """Get overall Bounty Intel statistics.

    Returns counts of programs, engagements, findings, submissions, reports,
    evidence files, and hunt memory entries. Quick health check.
    """
    c = _get_client()
    return _safe_call(c.get_stats)


# ── Entry point ──────────────────────────────────────────────


def main():
    logger.info("Starting Bounty Intel MCP server")
    mcp.run()


if __name__ == "__main__":
    main()
