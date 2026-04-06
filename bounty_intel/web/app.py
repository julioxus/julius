"""FastAPI web application — Bounty Intel Operations Center."""

from __future__ import annotations

from datetime import date, datetime, timezone
from pathlib import Path

import markdown
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from bounty_intel.config import settings
from bounty_intel.web.auth import (
    SESSION_COOKIE,
    SessionAuthMiddleware,
    create_session_cookie,
    oauth,
    render_login,
    setup_oauth,
)

app = FastAPI(title="Bounty Intel", docs_url=None, redoc_url=None)
app.add_middleware(SessionAuthMiddleware)

# Starlette session middleware required by authlib for OAuth state
from starlette.middleware.sessions import SessionMiddleware
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret or "dev-secret")

setup_oauth()

# Mount API router
from bounty_intel.web.api import router as api_router
app.include_router(api_router)

# Trust proxy headers (Cloud Run terminates TLS at the load balancer)
from starlette.middleware.trustedhost import TrustedHostMiddleware
import os
os.environ.setdefault("AUTHLIB_INSECURE_TRANSPORT", "0")  # ensure secure

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _render(request: Request, template: str, context: dict) -> HTMLResponse:
    """Starlette 1.0 compatible template rendering."""
    context["request"] = request
    return templates.TemplateResponse(request, template, context)


def _badge_class(disposition: str) -> str:
    return {
        "new": "badge-blue", "triaged": "badge-green", "accepted": "badge-green",
        "resolved": "badge-green", "needs_more_info": "badge-orange",
        "duplicate": "badge-gray", "informative": "badge-red",
        "not_applicable": "badge-gray", "wont_fix": "badge-gray",
        "out_of_scope": "badge-red",
    }.get(disposition, "badge-gray")


def _severity_badge(severity: str) -> str:
    return {
        "Critical": "badge-red", "Exceptional": "badge-red",
        "High": "badge-orange", "Medium": "badge-yellow",
        "Low": "badge-blue", "None": "badge-gray",
    }.get(severity, "badge-gray")


def _status_badge(status: str) -> str:
    return {
        "active": "badge-green", "paused": "badge-yellow",
        "completed": "badge-blue", "deprioritized": "badge-gray",
        "open": "badge-green", "suspended": "badge-yellow", "closed": "badge-red",
        "draft": "badge-gray", "validated": "badge-blue",
        "ready": "badge-yellow", "submitted": "badge-purple",
        "discovered": "badge-blue", "building_block": "badge-orange",
        "report_draft": "badge-yellow",
    }.get(status, "badge-gray")


def _days_ago(dt) -> str:
    if not dt:
        return "?"
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return "?"
    if isinstance(dt, datetime):
        now = datetime.now(timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = now - dt
    elif isinstance(dt, date):
        delta = date.today() - dt
    else:
        return "?"
    days = delta.days
    if days == 0:
        return "today"
    if days == 1:
        return "1d ago"
    return f"{days}d ago"


# Register template globals
@app.middleware("http")
async def add_template_globals(request: Request, call_next):
    response = await call_next(request)
    return response


# ──────────────────────────────────────────────────────────────
# Health check
# ──────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok"}


# ──────────────────────────────────────────────────────────────
# Login / Logout
# ──────────────────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str = "/", error: str = ""):
    return HTMLResponse(render_login(error=error, next_url=next))


@app.get("/auth/google")
async def google_login(request: Request, next: str = "/"):
    # Build HTTPS redirect URI (Cloud Run terminates TLS upstream)
    redirect_uri = str(request.url_for("google_callback"))
    if redirect_uri.startswith("http://"):
        redirect_uri = "https://" + redirect_uri[7:]
    request.session["next_url"] = next
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/auth/callback")
async def google_callback(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception:
        return RedirectResponse("/login?error=Authentication+failed", status_code=302)

    userinfo = token.get("userinfo", {})
    email = userinfo.get("email", "")

    if email != settings.allowed_email:
        return RedirectResponse(f"/login?error=Access+denied+for+{email}", status_code=302)

    next_url = request.session.pop("next_url", "/")
    response = RedirectResponse(next_url, status_code=302)
    response.set_cookie(
        SESSION_COOKIE,
        create_session_cookie(email),
        max_age=86400 * 30,
        httponly=True,
        secure=True,
        samesite="lax",
    )
    return response


@app.get("/logout")
async def logout():
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie(SESSION_COOKIE)
    return response


# ──────────────────────────────────────────────────────────────
# 4.1 — Dashboard (Home)
# ──────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    from bounty_intel.forecast.engine import compute_forecast
    fc = compute_forecast()

    return _render(request, "dashboard.html", {
        "active_page": "dashboard",
        "fc": fc,
        "badge_class": _badge_class,
        "severity_badge": _severity_badge,
        "days_ago": _days_ago,
    })


# ──────────────────────────────────────────────────────────────
# 4.2 — Programs
# ──────────────────────────────────────────────────────────────
@app.get("/programs", response_class=HTMLResponse)
async def programs_list(request: Request, platform: str = "", status: str = ""):
    from bounty_intel import service
    from bounty_intel.db import Submission, get_session
    from sqlalchemy import func, select

    
    programs = service.list_programs(
        platform=platform or None,
        status=status or None,
    )

    session = get_session()
    # Annotate with submission counts
    prog_data = []
    for p in programs:
        sub_count = session.scalar(select(func.count(Submission.id)).where(Submission.program_id == p.id)) or 0
        paid_count = session.scalar(select(func.count(Submission.id)).where(Submission.program_id == p.id, Submission.disposition == "resolved")) or 0
        prog_data.append({"program": p, "sub_count": sub_count, "paid_count": paid_count})
    session.close()

    return _render(request, "programs.html", {
        "active_page": "programs",
        "programs": prog_data,
        "status_badge": _status_badge,
        "filter_platform": platform,
        "filter_status": status,
    })


# ──────────────────────────────────────────────────────────────
# 4.3 — Program Detail
# ──────────────────────────────────────────────────────────────
@app.get("/programs/{program_id}", response_class=HTMLResponse)
async def program_detail(request: Request, program_id: int):
    from bounty_intel import service
    from bounty_intel.db import Program, get_session

    session = get_session()
    program = session.get(Program, program_id)
    if not program:
        return HTMLResponse("Program not found", status_code=404)

    
    findings = service.get_findings(program_id=program_id)
    reports = service.list_reports(program_id=program_id)
    submissions = service.get_submissions(program_id=program_id)
    building_blocks = [f for f in findings if f.is_building_block]
    activity = service.get_activity(limit=50)  # TODO: filter by engagement

    session.close()

    return _render(request, "program_detail.html", {
        "active_page": "programs",
        "program": program,
        "findings": findings,
        "building_blocks": building_blocks,
        "reports": reports,
        "submissions": submissions,
        "activity": activity,
        "badge_class": _badge_class,
        "severity_badge": _severity_badge,
        "status_badge": _status_badge,
        "days_ago": _days_ago,
    })


# ──────────────────────────────────────────────────────────────
# 4.4 — Findings Browser
# ──────────────────────────────────────────────────────────────
@app.get("/findings", response_class=HTMLResponse)
async def findings_list(request: Request, severity: str = "", vuln_class: str = "", status: str = "", building_blocks: str = ""):
    from bounty_intel import service

    
    findings = service.get_findings(
        severity=severity or None,
        vuln_class=vuln_class or None,
        status=status or None,
        is_building_block=True if building_blocks == "1" else None,
    )

    return _render(request, "findings.html", {
        "active_page": "findings",
        "findings": findings,
        "severity_badge": _severity_badge,
        "status_badge": _status_badge,
        "days_ago": _days_ago,
    })


# ──────────────────────────────────────────────────────────────
# 4.5 — Report Manager
# ──────────────────────────────────────────────────────────────
@app.get("/reports", response_class=HTMLResponse)
async def reports_list(request: Request):
    from bounty_intel import service

    
    all_reports = service.list_reports()

    pipeline = {
        "draft": [r for r in all_reports if r.status == "draft"],
        "validated": [r for r in all_reports if r.status == "validated"],
        "ready": [r for r in all_reports if r.status == "ready"],
        "submitted": [r for r in all_reports if r.status == "submitted"],
        "accepted": [r for r in all_reports if r.status == "accepted"],
        "rejected": [r for r in all_reports if r.status == "rejected"],
    }

    return _render(request, "reports.html", {
        "active_page": "reports",
        "pipeline": pipeline,
        "total": len(all_reports),
        "severity_badge": _severity_badge,
        "status_badge": _status_badge,
        "days_ago": _days_ago,
    })


@app.get("/reports/{report_id}", response_class=HTMLResponse)
async def report_editor(request: Request, report_id: int):
    from bounty_intel.db import SubmissionReport, get_session

    session = get_session()
    report = session.get(SubmissionReport, report_id)
    if not report:
        session.close()
        return HTMLResponse("Report not found", status_code=404)

    rendered_html = markdown.markdown(
        report.markdown_body or "",
        extensions=["fenced_code", "tables", "codehilite"],
    )

    program = report.program
    evidence = report.evidence_files
    session.close()

    return _render(request, "report_editor.html", {
        "active_page": "reports",
        "report": report,
        "program": program,
        "rendered_html": rendered_html,
        "evidence": evidence,
        "severity_badge": _severity_badge,
        "status_badge": _status_badge,
    })


@app.put("/reports/{report_id}", response_class=HTMLResponse)
async def update_report(request: Request, report_id: int):
    from bounty_intel import service

    form = await request.form()
    body = form.get("markdown_body", "")
    
    service.update_report(report_id, markdown_body=body)

    rendered = markdown.markdown(str(body), extensions=["fenced_code", "tables"])
    return HTMLResponse(rendered)


@app.post("/reports/{report_id}/promote", response_class=HTMLResponse)
async def promote_report(request: Request, report_id: int):
    from bounty_intel import service

    form = await request.form()
    new_status = form.get("status", "ready")
    
    service.update_report(report_id, status=new_status)

    return RedirectResponse(f"/reports/{report_id}", status_code=303)


@app.post("/reports/{report_id}/submit", response_class=HTMLResponse)
async def submit_report(request: Request, report_id: int):
    from bounty_intel import service

    form = await request.form()
    platform_id = form.get("platform_submission_id", "")
    
    service.mark_report_submitted(report_id, platform_id)

    return RedirectResponse(f"/reports/{report_id}", status_code=303)


# ──────────────────────────────────────────────────────────────
# 4.6 — Submissions Tracker
# ──────────────────────────────────────────────────────────────
@app.get("/submissions", response_class=HTMLResponse)
async def submissions_list(request: Request, disposition: str = "", platform: str = ""):
    from bounty_intel import service

    
    submissions = service.get_submissions(
        platform=platform or None,
        disposition=disposition or None,
    )

    return _render(request, "submissions.html", {
        "active_page": "submissions",
        "submissions": submissions,
        "badge_class": _badge_class,
        "severity_badge": _severity_badge,
        "days_ago": _days_ago,
        "filter_disposition": disposition,
        "filter_platform": platform,
    })


# ──────────────────────────────────────────────────────────────
# 4.7 — Hunt Intelligence
# ──────────────────────────────────────────────────────────────
@app.get("/hunt", response_class=HTMLResponse)
async def hunt_intel(request: Request):
    from bounty_intel import service

    
    entries = service.get_hunt_memory()

    # Aggregate stats
    stats_by_class: dict[str, dict] = {}
    for e in entries:
        vc = e.vuln_class
        if vc not in stats_by_class:
            stats_by_class[vc] = {"total": 0, "success": 0, "total_payout": 0}
        stats_by_class[vc]["total"] += 1
        if e.success:
            stats_by_class[vc]["success"] += 1
        stats_by_class[vc]["total_payout"] += float(e.payout or 0)

    return _render(request, "hunt.html", {
        "active_page": "hunt",
        "entries": entries,
        "stats_by_class": stats_by_class,
    })


# ──────────────────────────────────────────────────────────────
# 4.8 — Activity Feed
# ──────────────────────────────────────────────────────────────
@app.get("/activity", response_class=HTMLResponse)
async def activity_feed(request: Request):
    from bounty_intel import service

    
    activity = service.get_activity(limit=200)

    return _render(request, "activity.html", {
        "active_page": "activity",
        "activity": activity,
        "days_ago": _days_ago,
    })


# ──────────────────────────────────────────────────────────────
# 4.9 — Recommendations
# ──────────────────────────────────────────────────────────────
@app.get("/recommendations", response_class=HTMLResponse)
async def recommendations(request: Request):
    from bounty_intel.forecast.engine import compute_forecast

    fc = compute_forecast()
    ranked = fc.get("ranked_submissions", [])

    # Group by program and compute ROI per program
    program_ev: dict[str, dict] = {}
    for s in ranked:
        prog = s["program"]
        if prog not in program_ev:
            program_ev[prog] = {"total_ev": 0, "count": 0, "top_ev": 0, "platform": s.get("platform", "")}
        program_ev[prog]["total_ev"] += s["expected_value_eur"]
        program_ev[prog]["count"] += 1
        program_ev[prog]["top_ev"] = max(program_ev[prog]["top_ev"], s["expected_value_eur"])

    sorted_programs = sorted(program_ev.items(), key=lambda x: x[1]["total_ev"], reverse=True)

    return _render(request, "recommendations.html", {
        "active_page": "recommendations",
        "ranked": ranked[:20],
        "program_ranking": sorted_programs,
        "severity_badge": _severity_badge,
    })


# ──────────────────────────────────────────────────────────────
# 4.10 — Settings
# ──────────────────────────────────────────────────────────────
@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    from bounty_intel import service

    
    stats = service.get_stats()

    h1_state = service.get_sync_state("hackerone")
    inti_state = service.get_sync_state("intigriti")

    return _render(request, "settings.html", {
        "active_page": "settings",
        "stats": stats,
        "h1_sync": h1_state,
        "inti_sync": inti_state,
        "h1_configured": bool(settings.hackerone_username and settings.hackerone_api_token),
        "days_ago": _days_ago,
    })


# ──────────────────────────────────────────────────────────────
# Sync endpoint (HTMX)
# ──────────────────────────────────────────────────────────────
@app.post("/sync")
async def trigger_sync(request: Request):
    from bounty_intel.sync.delta import sync_all

    results = sync_all(sources=["hackerone"])  # Only H1 from server (Intigriti needs browser)
    return HTMLResponse(
        content="<span class='badge badge-green'>Synced</span>",
        headers={"HX-Trigger": "reload-all"},
    )


# ──────────────────────────────────────────────────────────────
# Evidence signed URL redirect
# ──────────────────────────────────────────────────────────────
@app.get("/evidence/{evidence_id}")
async def evidence_redirect(evidence_id: int):
    from bounty_intel.db import EvidenceFile, get_session
    from bounty_intel.evidence.uploader import generate_signed_url

    session = get_session()
    ef = session.get(EvidenceFile, evidence_id)
    session.close()

    if not ef:
        return HTMLResponse("Not found", status_code=404)

    url = generate_signed_url(ef.gcs_path)
    return RedirectResponse(url)
