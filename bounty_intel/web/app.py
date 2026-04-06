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


def _platform_url(platform: str, platform_id: str) -> str:
    """Generate direct link to the report on the platform."""
    if not platform_id:
        return ""
    if platform == "hackerone":
        return f"https://hackerone.com/reports/{platform_id}"
    if platform == "intigriti":
        return f"https://app.intigriti.com/researcher/submissions/{platform_id}"
    return ""


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
async def findings_list(request: Request):
    """Findings are explored per-program — redirect to programs page."""
    return RedirectResponse("/programs", status_code=302)


@app.get("/findings/{finding_id}", response_class=HTMLResponse)
async def finding_detail(request: Request, finding_id: int):
    from bounty_intel import service
    from bounty_intel.db import Finding, get_session

    session = get_session()
    finding = session.get(Finding, finding_id)
    if not finding:
        session.close()
        return HTMLResponse("Finding not found", status_code=404)

    program = finding.program
    rendered_desc = markdown.markdown(
        finding.description or "", extensions=["fenced_code", "tables"]
    )
    rendered_steps = markdown.markdown(
        finding.steps_to_reproduce or "", extensions=["fenced_code", "tables"]
    )
    rendered_impact = markdown.markdown(
        finding.impact or "", extensions=["fenced_code", "tables"]
    )
    session.close()

    return _render(request, "finding_detail.html", {
        "active_page": "programs",
        "finding": finding,
        "program": program,
        "rendered_desc": rendered_desc,
        "rendered_steps": rendered_steps,
        "rendered_impact": rendered_impact,
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
        "platform_url": _platform_url,
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
        "platform_url": _platform_url,
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
    from bounty_intel.db import SubmissionReport, Submission, get_session
    from sqlalchemy import select

    form = await request.form()
    platform_id = form.get("platform_submission_id", "").strip()

    if not platform_id:
        return RedirectResponse(f"/reports/{report_id}?error=Platform+ID+required", status_code=303)

    session = get_session()
    report = session.get(SubmissionReport, report_id)
    if not report:
        session.close()
        return HTMLResponse("Report not found", status_code=404)

    # Mark report as submitted
    service.mark_report_submitted(report_id, platform_id)

    # Try to link with existing submission record (from platform sync)
    sub = session.scalar(
        select(Submission).where(
            Submission.platform == report.platform,
            Submission.platform_id == platform_id,
        )
    )
    if sub:
        # Cross-link: submission.report_id → this report
        sub.report_id = report_id
        session.commit()

    session.close()
    return RedirectResponse(f"/reports/{report_id}", status_code=303)


# ──────────────────────────────────────────────────────────────
# 4.6 — Submissions Tracker (enriched with AI evaluations + forecast)
# ──────────────────────────────────────────────────────────────
@app.get("/submissions", response_class=HTMLResponse)
async def submissions_list(request: Request):
    from bounty_intel.forecast.engine import compute_forecast
    from bounty_intel import service
    from bounty_intel.db import AIEvaluation, Submission, get_session
    from sqlalchemy import select

    fc = compute_forecast()
    ranked = fc.get("ranked_submissions", [])
    ranked_by_id = {str(s["id"]): s for s in ranked}

    session = get_session()
    all_subs = service.get_submissions()

    # Split into pending (with forecast data) and closed (with outcome analysis)
    pending = []
    closed_paid = []
    closed_rejected = []

    for sub in all_subs:
        forecast_data = ranked_by_id.get(sub.platform_id, {})
        ai_eval = session.scalar(select(AIEvaluation).where(AIEvaluation.submission_id == sub.id))

        entry = {
            "sub": sub,
            "ev": forecast_data.get("expected_value_eur", 0),
            "prob": forecast_data.get("acceptance_prob", 0),
            "prob_source": forecast_data.get("prob_source", ""),
            "est_resolve": forecast_data.get("est_resolve_date", ""),
            "overdue": forecast_data.get("est_overdue", False),
            "ai_reasoning": ai_eval.triager_reasoning if ai_eval else "",
            "ai_strengths": ai_eval.strengths if ai_eval else [],
            "ai_weaknesses": ai_eval.weaknesses if ai_eval else [],
            "ai_outcome": ai_eval.likely_outcome if ai_eval else "",
        }

        if sub.disposition in ("new", "triaged", "needs_more_info", "accepted"):
            pending.append(entry)
        elif sub.disposition == "resolved":
            closed_paid.append(entry)
        else:
            closed_rejected.append(entry)

    pending.sort(key=lambda x: x["ev"], reverse=True)
    session.close()

    return _render(request, "submissions.html", {
        "active_page": "submissions",
        "pending": pending,
        "closed_paid": closed_paid,
        "closed_rejected": closed_rejected,
        "total": len(all_subs),
        "total_pending_ev": sum(e["ev"] for e in pending),
        "badge_class": _badge_class,
        "severity_badge": _severity_badge,
        "days_ago": _days_ago,
    })


# ──────────────────────────────────────────────────────────────
# 4.7 — Hunt Intelligence (techniques + patterns + lessons)
# ──────────────────────────────────────────────────────────────
@app.get("/hunt", response_class=HTMLResponse)
async def hunt_intel(request: Request):
    from bounty_intel import service
    from bounty_intel.db import Finding, Submission, get_session
    from sqlalchemy import func, select

    session = get_session()
    hunt_entries = service.get_hunt_memory()

    # Aggregate by tech_stack → what vulns work
    tech_vulns: dict[str, list] = {}
    for e in hunt_entries:
        for tech in (e.tech_stack or []):
            if tech not in tech_vulns:
                tech_vulns[tech] = []
            tech_vulns[tech].append({
                "vuln_class": e.vuln_class, "success": e.success,
                "technique": e.technique_summary, "target": e.target,
                "payout": float(e.payout or 0),
            })

    # Aggregate by vuln_class
    vuln_stats: dict[str, dict] = {}
    for e in hunt_entries:
        vc = e.vuln_class
        if vc not in vuln_stats:
            vuln_stats[vc] = {"total": 0, "success": 0, "payout": 0, "techniques": [], "targets": []}
        vuln_stats[vc]["total"] += 1
        if e.success:
            vuln_stats[vc]["success"] += 1
        vuln_stats[vc]["payout"] += float(e.payout or 0)
        if e.technique_summary and e.technique_summary not in vuln_stats[vc]["techniques"]:
            vuln_stats[vc]["techniques"].append(e.technique_summary)
        if e.target not in vuln_stats[vc]["targets"]:
            vuln_stats[vc]["targets"].append(e.target)

    # Lessons from rejections: what disposition + severity combos fail most
    rejection_patterns = session.execute(
        select(Submission.disposition, Submission.severity, func.count().label("cnt"))
        .where(Submission.disposition.in_(["duplicate", "informative", "not_applicable"]))
        .group_by(Submission.disposition, Submission.severity)
        .order_by(func.count().desc())
    ).all()

    # Success patterns: what severity + platform combos get paid
    success_patterns = session.execute(
        select(Submission.platform, Submission.severity, func.count().label("cnt"))
        .where(Submission.disposition == "resolved")
        .group_by(Submission.platform, Submission.severity)
        .order_by(func.count().desc())
    ).all()

    session.close()

    return _render(request, "hunt.html", {
        "active_page": "hunt",
        "hunt_entries": hunt_entries,
        "tech_vulns": tech_vulns,
        "vuln_stats": vuln_stats,
        "rejection_patterns": rejection_patterns,
        "success_patterns": success_patterns,
        "badge_class": _badge_class,
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
    from bounty_intel import service
    from bounty_intel.db import Finding, Submission, get_session
    from sqlalchemy import func, select

    fc = compute_forecast()
    ranked = fc.get("ranked_submissions", [])
    session = get_session()

    # Per-program analysis with context
    program_analysis: dict[str, dict] = {}
    for s in ranked:
        prog = s["program"]
        if prog not in program_analysis:
            program_analysis[prog] = {
                "total_ev": 0, "count": 0, "top_submission": None,
                "platform": s.get("platform", ""), "severities": [],
                "ai_strengths": [], "ai_weaknesses": [],
            }
        pa = program_analysis[prog]
        pa["total_ev"] += s["expected_value_eur"]
        pa["count"] += 1
        pa["severities"].append(s["severity"])
        if pa["top_submission"] is None or s["expected_value_eur"] > pa["top_submission"]["expected_value_eur"]:
            pa["top_submission"] = s
        if s.get("strengths"):
            pa["ai_strengths"].extend(s["strengths"][:2])
        if s.get("weaknesses"):
            pa["ai_weaknesses"].extend(s["weaknesses"][:2])

    # Enrich with historical data: paid vs rejected per program
    for prog_name, pa in program_analysis.items():
        # Find the program in DB
        programs = service.list_programs()
        matching = [p for p in programs if p.company_name == prog_name]
        if matching:
            pid = matching[0].id
            paid = session.scalar(select(func.count(Submission.id)).where(
                Submission.program_id == pid, Submission.disposition == "resolved")) or 0
            rejected = session.scalar(select(func.count(Submission.id)).where(
                Submission.program_id == pid, Submission.disposition.in_(["duplicate", "informative", "not_applicable"]))) or 0
            total_findings = session.scalar(select(func.count(Finding.id)).where(Finding.program_id == pid)) or 0
            building_blocks = session.scalar(select(func.count(Finding.id)).where(
                Finding.program_id == pid, Finding.is_building_block.is_(True))) or 0
            pa["paid"] = paid
            pa["rejected"] = rejected
            pa["total_findings"] = total_findings
            pa["building_blocks"] = building_blocks
            pa["acceptance_rate"] = paid / (paid + rejected) if (paid + rejected) > 0 else None

    # Sort by total EV
    sorted_programs = sorted(program_analysis.items(), key=lambda x: x[1]["total_ev"], reverse=True)

    # Programs with unexploited building blocks (chain opportunities)
    chain_opportunities = []
    bbs = session.scalars(select(Finding).where(Finding.is_building_block.is_(True))).all()
    for bb in bbs:
        if bb.building_block_notes:
            chain_opportunities.append({
                "program": bb.program.company_name if bb.program else "?",
                "title": bb.title,
                "notes": bb.building_block_notes,
                "severity": bb.severity,
            })

    # Rejection lessons: most common rejection reasons
    top_rejections = session.execute(
        select(Submission.disposition, func.count().label("cnt"))
        .where(Submission.disposition.in_(["duplicate", "informative", "not_applicable", "wont_fix"]))
        .group_by(Submission.disposition)
        .order_by(func.count().desc())
    ).all()

    session.close()

    return _render(request, "recommendations.html", {
        "active_page": "recommendations",
        "program_ranking": sorted_programs,
        "chain_opportunities": chain_opportunities,
        "top_rejections": top_rejections,
        "confirmed_eur": fc.get("confirmed_earnings_eur", 0),
        "expected_eur": fc.get("scenarios", {}).get("expected", {}).get("total_eur", 0),
        "acceptance_rate": fc.get("historical_acceptance_rate", 0),
        "severity_badge": _severity_badge,
        "badge_class": _badge_class,
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
# Sync endpoints (HTMX)
# ──────────────────────────────────────────────────────────────
@app.post("/sync")
async def trigger_sync(request: Request):
    """Sync HackerOne only (token-based, automatic)."""
    from bounty_intel.sync.delta import sync_all

    results = sync_all(sources=["hackerone"])
    h1_count = results.get("hackerone", {}).get("upserted", 0)
    return HTMLResponse(
        content=f"<span class='badge badge-green'>H1: {h1_count} synced</span>",
        headers={"HX-Trigger": "reload-all"},
    )


@app.post("/sync/intigriti")
async def trigger_intigriti_sync(request: Request):
    """Sync Intigriti using a pasted session cookie."""
    form = await request.form()
    cookie = form.get("cookie", "").strip()
    if not cookie:
        return HTMLResponse("<span class='badge badge-red'>No cookie provided</span>")

    # Validate cookie works
    from bounty_intel.sync.intigriti import _validate_cookie, sync as inti_sync
    if not _validate_cookie(cookie):
        return HTMLResponse("<span class='badge badge-red'>Cookie invalid or expired</span>")

    # Store cookie for this sync (temporarily set in settings)
    import bounty_intel.config
    bounty_intel.config.settings.intigriti_cookie = cookie

    # Run sync
    result = inti_sync()
    upserted = result.get("upserted", 0)

    # Update watermark
    if result.get("max_updated"):
        from bounty_intel import service
        service.update_sync_state("intigriti", result["max_updated"])

    return HTMLResponse(
        content=f"<span class='badge badge-green'>Intigriti: {upserted} synced</span>",
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
