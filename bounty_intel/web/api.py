"""REST API endpoints for programmatic access from skills.

All endpoints under /api/v1/ require X-API-Key header.
Skills running locally use these instead of direct DB access.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, UploadFile, File, Form
from pydantic import BaseModel

from bounty_intel.config import settings

router = APIRouter(prefix="/api/v1")


# ── Auth ─────────────────────────────────────────────────────
async def verify_api_key(x_api_key: str = Header()):
    if not settings.api_key:
        raise HTTPException(503, "API key not configured on server")
    if not _constant_time_compare(x_api_key, settings.api_key):
        raise HTTPException(401, "Invalid API key")


def _constant_time_compare(a: str, b: str) -> bool:
    """Prevent timing attacks on API key comparison."""
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())


# ── Schemas ──────────────────────────────────────────────────
class ProgramIn(BaseModel):
    platform: str
    handle: str
    company_name: str
    status: str = "open"
    bounty_type: str = "bounty"
    scope: dict = {}
    oos_rules: dict = {}
    tech_stack: list[str] = []
    notes: str = ""

class EngagementIn(BaseModel):
    program_id: int
    status: str = "active"
    notes: str = ""
    recon_data: dict = {}
    attack_surface: dict = {}

class FindingIn(BaseModel):
    engagement_id: int | None = None
    program_id: int
    title: str
    vuln_class: str = ""
    severity: str = ""
    cvss_vector: str = ""
    status: str = "discovered"
    description: str = ""
    steps_to_reproduce: str = ""
    impact: str = ""
    poc_code: str = ""
    poc_output: str = ""
    chain_with: list[int] = []
    is_building_block: bool = False
    building_block_notes: str = ""

class FindingUpdate(BaseModel):
    status: str | None = None
    severity: str | None = None
    cvss_vector: str | None = None
    vuln_class: str | None = None
    description: str | None = None
    impact: str | None = None
    steps_to_reproduce: str | None = None
    is_building_block: bool | None = None
    building_block_notes: str | None = None

class ReportIn(BaseModel):
    finding_id: int | None = None
    program_id: int
    platform: str
    report_slug: str = ""
    title: str
    severity: str = ""
    cvss_vector: str = ""
    markdown_body: str

class ReportUpdate(BaseModel):
    markdown_body: str | None = None
    status: str | None = None
    validation_result: dict | None = None

class HuntIn(BaseModel):
    target: str
    vuln_class: str
    success: bool = False
    payout: float = 0
    severity: str = ""
    technique: str = ""
    chain: str = ""
    platform: str = ""
    tech_stack: list[str] = []
    domain: str = ""

class ActivityIn(BaseModel):
    engagement_id: int | None = None
    action: str
    details: dict = {}

class AIEvalIn(BaseModel):
    submission_id: int
    acceptance_probability: float
    confidence: float = 0
    likely_outcome: str = ""
    severity_assessment: str = ""
    strengths: list[str] = []
    weaknesses: list[str] = []
    triager_reasoning: str = ""
    suggested_improvements: list[str] = []


# ── Programs ─────────────────────────────────────────────────
@router.get("/programs", dependencies=[Depends(verify_api_key)])
async def list_programs(platform: str = "", status: str = ""):
    from bounty_intel import service
    
    programs = service.list_programs(platform=platform or None, status=status or None)
    return [{"id": p.id, "platform": p.platform, "handle": p.platform_handle,
             "company_name": p.company_name, "status": p.status, "bounty_type": p.bounty_type,
             "tech_stack": p.tech_stack or [], "notes": p.notes or "",
             "logo_url": p.logo_url or ""} for p in programs]


@router.post("/programs", dependencies=[Depends(verify_api_key)])
async def upsert_program(data: ProgramIn):
    from bounty_intel import service
    
    pid = service.upsert_program(
        platform=data.platform, handle=data.handle, company_name=data.company_name,
        status=data.status, bounty_type=data.bounty_type, scope=data.scope,
        oos_rules=data.oos_rules, tech_stack=data.tech_stack, notes=data.notes,
    )
    return {"id": pid}


# ── Engagements ──────────────────────────────────────────────
@router.get("/engagements/{platform}/{handle}", dependencies=[Depends(verify_api_key)])
async def get_engagement(platform: str, handle: str):
    from bounty_intel import service
    
    eng = service.get_engagement(platform, handle)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    return {"id": eng.id, "program_id": eng.program_id, "status": eng.status,
            "notes": eng.notes, "recon_data": eng.recon_data, "attack_surface": eng.attack_surface}


@router.post("/engagements", dependencies=[Depends(verify_api_key)])
async def create_engagement(data: EngagementIn):
    from bounty_intel import service
    
    eid = service.create_engagement(
        data.program_id, status=data.status, notes=data.notes,
        recon_data=data.recon_data, attack_surface=data.attack_surface,
    )
    return {"id": eid}


class EngagementUpdate(BaseModel):
    status: str | None = None
    notes: str | None = None
    recon_data: dict | None = None
    attack_surface: dict | None = None


@router.patch("/engagements/{engagement_id}", dependencies=[Depends(verify_api_key)])
async def update_engagement(engagement_id: int, data: EngagementUpdate):
    from bounty_intel import service

    updates = {k: v for k, v in data.model_dump().items() if v is not None}
    service.update_engagement(engagement_id, **updates)
    return {"ok": True}


# ── Findings ─────────────────────────────────────────────────
@router.get("/findings", dependencies=[Depends(verify_api_key)])
async def list_findings(program_id: int = 0, status: str = "", vuln_class: str = "",
                        is_building_block: str = ""):
    from bounty_intel import service
    
    findings = service.get_findings(
        program_id=program_id or None, status=status or None,
        vuln_class=vuln_class or None,
        is_building_block=True if is_building_block == "1" else None,
    )
    return [{"id": f.id, "program_id": f.program_id, "engagement_id": f.engagement_id,
             "title": f.title, "vuln_class": f.vuln_class, "severity": f.severity,
             "status": f.status, "is_building_block": f.is_building_block,
             "building_block_notes": f.building_block_notes or "",
             "description": f.description[:500] if f.description else "",
             "created_at": f.created_at.isoformat() if f.created_at else None} for f in findings]


@router.post("/findings", dependencies=[Depends(verify_api_key)])
async def create_finding(data: FindingIn):
    from bounty_intel import service
    
    fid = service.save_finding(**data.model_dump())
    return {"id": fid}


@router.patch("/findings/{finding_id}", dependencies=[Depends(verify_api_key)])
async def update_finding(finding_id: int, data: FindingUpdate):
    from bounty_intel import service

    updates = {k: v for k, v in data.model_dump().items() if v is not None}
    service.update_finding(finding_id, **updates)
    return {"ok": True}


@router.delete("/findings/{finding_id}", dependencies=[Depends(verify_api_key)])
async def delete_finding(finding_id: int):
    from bounty_intel.db import Finding, SubmissionReport, get_session
    from sqlalchemy import select

    session = get_session()
    finding = session.get(Finding, finding_id)
    if not finding:
        session.close()
        raise HTTPException(404, "Finding not found")
    # Block if linked to a submitted report
    linked = session.scalar(
        select(SubmissionReport).where(
            SubmissionReport.finding_id == finding_id,
            SubmissionReport.status.in_(["submitted", "accepted"]),
        )
    )
    if linked:
        session.close()
        raise HTTPException(409, "Cannot delete: finding is linked to a submitted report")
    session.delete(finding)
    session.commit()
    session.close()
    return {"ok": True}


# ── Reports ──────────────────────────────────────────────────
@router.get("/reports", dependencies=[Depends(verify_api_key)])
async def list_reports(status: str = "", program_id: int = 0):
    from bounty_intel import service
    
    reports = service.list_reports(status=status or None, program_id=program_id or None)
    return [{"id": r.id, "program_id": r.program_id, "platform": r.platform,
             "report_slug": r.report_slug, "title": r.title, "severity": r.severity,
             "status": r.status, "created_at": r.created_at.isoformat() if r.created_at else None,
             "submitted_at": r.submitted_at.isoformat() if r.submitted_at else None}
            for r in reports]


@router.post("/reports", dependencies=[Depends(verify_api_key)])
async def create_report(data: ReportIn):
    from bounty_intel import service
    
    rid = service.create_report(**data.model_dump())
    return {"id": rid}


@router.patch("/reports/{report_id}", dependencies=[Depends(verify_api_key)])
async def api_update_report(report_id: int, data: ReportUpdate):
    from bounty_intel import service
    
    updates = {k: v for k, v in data.model_dump().items() if v is not None}
    service.update_report(report_id, **updates)
    return {"ok": True}


@router.delete("/reports/{report_id}", dependencies=[Depends(verify_api_key)])
async def delete_report(report_id: int):
    from bounty_intel.db import SubmissionReport, get_session

    session = get_session()
    report = session.get(SubmissionReport, report_id)
    if not report:
        session.close()
        raise HTTPException(404, "Report not found")
    if report.status in ("submitted", "accepted"):
        session.close()
        raise HTTPException(409, "Cannot delete a submitted/accepted report")
    session.delete(report)
    session.commit()
    session.close()
    return {"ok": True}


@router.post("/reports/{report_id}/submit", dependencies=[Depends(verify_api_key)])
async def api_submit_report(report_id: int, platform_submission_id: str = ""):
    from bounty_intel import service
    
    service.mark_report_submitted(report_id, platform_submission_id)
    return {"ok": True}


# ── Submissions ─────────────────────────────────────────────
@router.get("/submissions", dependencies=[Depends(verify_api_key)])
async def list_submissions(platform: str = "", disposition: str = "", program_id: int = 0):
    from bounty_intel import service

    subs = service.get_submissions(
        platform=platform or None, disposition=disposition or None,
        program_id=program_id or None,
    )
    return [{"id": sub.id, "platform_id": sub.platform_id, "platform": sub.platform,
             "program_id": sub.program_id, "report_id": sub.report_id,
             "title": sub.title, "severity": sub.severity, "disposition": sub.disposition,
             "listed_bounty": float(sub.listed_bounty or 0),
             "listed_currency": sub.listed_currency,
             "company_name": sub.program.company_name if sub.program else None,
             "created_at": sub.created_at.isoformat() if sub.created_at else None}
            for sub in subs]


# ── Hunt Memory ──────────────────────────────────────────────
@router.get("/hunt", dependencies=[Depends(verify_api_key)])
async def list_hunt(target: str = "", vuln_class: str = ""):
    from bounty_intel import service
    
    entries = service.get_hunt_memory(target=target or None, vuln_class=vuln_class or None)
    return [{"id": e.id, "target": e.target, "vuln_class": e.vuln_class,
             "tech_stack": e.tech_stack or [], "success": e.success,
             "payout": float(e.payout or 0), "technique": e.technique_summary or "",
             "platform": e.platform or ""} for e in entries]


@router.post("/hunt", dependencies=[Depends(verify_api_key)])
async def record_hunt(data: HuntIn):
    from bounty_intel import service
    
    hid = service.record_hunt(**data.model_dump())
    return {"id": hid}


@router.get("/hunt/suggest", dependencies=[Depends(verify_api_key)])
async def suggest_attacks(tech_stack: str = ""):
    from bounty_intel import service
    
    stack = [t.strip() for t in tech_stack.split(",") if t.strip()]
    return service.suggest_attacks(stack)


# ── Activity ─────────────────────────────────────────────────
@router.post("/activity", dependencies=[Depends(verify_api_key)])
async def log_activity(data: ActivityIn):
    from bounty_intel import service
    
    aid = service.log_activity(data.engagement_id, data.action, data.details)
    return {"id": aid}


# ── AI Evaluations ───────────────────────────────────────────
@router.post("/evaluations", dependencies=[Depends(verify_api_key)])
async def save_evaluation(data: AIEvalIn):
    from bounty_intel import service
    
    eid = service.save_ai_evaluation(**data.model_dump())
    return {"id": eid}


class SyncRequest(BaseModel):
    source: str = "all"
    cookie: str = ""  # Intigriti session cookie (optional)
    force: bool = False  # ignore watermark, full re-sync


# ── Sync ─────────────────────────────────────────────────────
@router.post("/sync", dependencies=[Depends(verify_api_key)])
async def api_sync(data: SyncRequest):
    # If Intigriti cookie provided, inject it for this sync
    if data.cookie and data.source in ("intigriti", "all"):
        import bounty_intel.config
        bounty_intel.config.settings.intigriti_cookie = data.cookie

    from bounty_intel.sync.delta import sync_all
    source = data.source
    sources = None if source == "all" else [source]
    results = sync_all(sources=sources, force=data.force)
    return results


# ── Forecast ─────────────────────────────────────────────────
@router.get("/forecast", dependencies=[Depends(verify_api_key)])
async def api_forecast():
    from bounty_intel.forecast.engine import compute_forecast
    return compute_forecast()


# ── Admin ────────────────────────────────────────────────────
@router.delete("/programs/{program_id}", dependencies=[Depends(verify_api_key)])
async def delete_program(program_id: int):
    from bounty_intel.db import Program, Submission, Finding, SubmissionReport, Engagement, get_session
    from sqlalchemy import select, func

    session = get_session()
    # Safety: only delete if program has zero findings, reports, and submissions
    for model in (Finding, SubmissionReport, Submission):
        count = session.scalar(select(func.count(model.id)).where(model.program_id == program_id)) or 0
        if count > 0:
            session.close()
            raise HTTPException(409, f"Program has {count} {model.__tablename__}, cannot delete")
    program = session.get(Program, program_id)
    if not program:
        session.close()
        raise HTTPException(404, "Program not found")
    # Delete orphan engagements
    for eng in session.scalars(select(Engagement).where(Engagement.program_id == program_id)).all():
        session.delete(eng)
    session.delete(program)
    session.commit()
    session.close()
    return {"ok": True, "deleted": program_id}


@router.post("/admin/dedup-programs", dependencies=[Depends(verify_api_key)])
async def dedup_programs():
    from bounty_intel.migration.import_existing import deduplicate_programs
    deduplicate_programs()
    return {"ok": True}


@router.post("/admin/sync-report-statuses", dependencies=[Depends(verify_api_key)])
async def sync_report_statuses_endpoint():
    from bounty_intel.migration.import_existing import sync_report_statuses
    sync_report_statuses()
    return {"ok": True}


# ── Stats ────────────────────────────────────────────────────
@router.get("/stats", dependencies=[Depends(verify_api_key)])
async def api_stats():
    from bounty_intel import service
    
    return service.get_stats()
