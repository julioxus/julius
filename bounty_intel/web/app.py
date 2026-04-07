"""FastAPI web application — Bounty Intel Operations Center."""

from __future__ import annotations

from datetime import date, datetime, timezone
from pathlib import Path

import markdown
import nh3
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
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret or "startup-will-fail")

setup_oauth()

# Run schema migrations (adds new columns safely)
from bounty_intel.migration.schema import _add_missing_columns
try:
    _add_missing_columns()
except Exception:
    pass  # non-fatal if DB not ready yet

# Mount API router
from bounty_intel.web.api import router as api_router
app.include_router(api_router)

# Trust proxy headers (Cloud Run terminates TLS at the load balancer)
from starlette.middleware.trustedhost import TrustedHostMiddleware
import os
os.environ.setdefault("AUTHLIB_INSECURE_TRANSPORT", "0")  # ensure secure

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.globals["platform_badge"] = lambda p: {"hackerone": "badge-blue", "intigriti": "badge-purple", "custom": "badge-orange"}.get(p, "badge-gray")


def _render(request: Request, template: str, context: dict) -> HTMLResponse:
    """Starlette 1.0 compatible template rendering."""
    context["request"] = request
    return templates.TemplateResponse(request, template, context)


def _safe_markdown(text: str) -> str:
    """Render markdown to HTML and sanitize to prevent XSS."""
    raw_html = markdown.markdown(text or "", extensions=["fenced_code", "tables", "codehilite"])
    return nh3.clean(raw_html)


def _platform_url(platform: str, platform_id: str) -> str:
    """Generate direct link to the report on the platform."""
    if not platform_id:
        return ""
    if platform == "hackerone":
        return f"https://hackerone.com/reports/{platform_id}"
    if platform == "intigriti":
        return f"https://app.intigriti.com/researcher/submissions/{platform_id}"
    return ""


def _program_platform_url(platform: str, handle: str) -> str:
    """Generate direct link to the program on the platform."""
    if not handle:
        return ""
    if platform == "hackerone":
        return f"https://hackerone.com/{handle}"
    if platform == "intigriti":
        # handles are "company/program" or just "slug" (needs company/slug/slug)
        if "/" in handle:
            return f"https://app.intigriti.com/researcher/programs/{handle}/detail"
        return f"https://app.intigriti.com/researcher/programs/{handle}/{handle}/detail"
    return ""


_DOMAIN_HINTS: dict[str, str] = {
    "bcny": "arc.net",
    "neon_bbp": "neon.tech",
    "lightspark_bbp": "lightspark.com",
    "toolsforhumanity": "worldcoin.org",
    "agentschapwegenenverkeerbugbounty": "wegenenverkeer.be",
    "quadcodebugbounty": "iqoption.com",
    "capitalcom": "capital.com",
    "virginmedia": "virginmedia.com",
}


def _company_logo_url(program) -> str:
    """Return Google Favicon URL for the company."""
    import re
    handle = getattr(program, "platform_handle", "") or ""
    name = getattr(program, "company_name", "") or ""
    key = re.sub(r"[^a-z0-9]", "", (handle.split("/")[0] if "/" in handle else handle or name).lower())
    domain = _DOMAIN_HINTS.get(key)
    if not domain:
        clean = re.sub(r"(bugbounty|_bbp|bbp)", "", key)
        domain = f"{clean}.com" if clean else ""
    if not domain:
        return ""
    return f"https://t1.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=https://{domain}&size=64"


def _platform_badge(platform: str) -> str:
    return {"hackerone": "badge-blue", "intigriti": "badge-purple", "custom": "badge-orange"}.get(platform, "badge-gray")


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
        "active": "badge-green", "paused": "badge-orange",
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


# Prevent browser caching of HTML pages
@app.middleware("http")
async def no_cache_html(request: Request, call_next):
    response = await call_next(request)
    ct = response.headers.get("content-type", "")
    if "text/html" in ct:
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
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

    if email.lower() != settings.allowed_email.lower():
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
    from bounty_intel import service
    from bounty_intel.db import Submission, get_session
    from sqlalchemy import func, select

    fc = compute_forecast()

    session = get_session()
    total_subs = session.scalar(select(func.count(Submission.id))) or 0
    pending_count = session.scalar(select(func.count(Submission.id)).where(
        Submission.disposition.in_(["new", "triaged", "needs_more_info", "accepted"]))) or 0
    paid_count = session.scalar(select(func.count(Submission.id)).where(Submission.disposition == "resolved")) or 0
    rejected_all = session.scalars(select(Submission.disposition).where(
        Submission.disposition.in_(["duplicate", "informative", "not_applicable", "wont_fix"]))).all()
    rejected_count = len(rejected_all)
    dup_count = sum(1 for d in rejected_all if d == "duplicate")
    info_count = sum(1 for d in rejected_all if d == "informative")
    session.close()

    return _render(request, "dashboard.html", {
        "active_page": "dashboard",
        "fc": fc,
        "total_subs": total_subs,
        "pending_count": pending_count,
        "paid_count": paid_count,
        "rejected_count": rejected_count,
        "dup_count": dup_count,
        "info_count": info_count,
        "badge_class": _badge_class,
        "severity_badge": _severity_badge,
        "days_ago": _days_ago,
    })


# ──────────────────────────────────────────────────────────────
# 4.2 — Programs
# ──────────────────────────────────────────────────────────────
@app.get("/programs", response_class=HTMLResponse)
async def programs_list(
    request: Request,
    platform: str = "",
    status: str = "",
    search: str = "",
    sort: str = "",
):
    from bounty_intel import service
    from bounty_intel.db import Submission, SubmissionReport, get_session
    from sqlalchemy import func, select

    programs = service.list_programs(
        platform=platform or None,
        status=status or None,
        search=search.strip() or None,
        sort=sort or None,
    )

    session = get_session()
    # Annotate with submission counts + last submitted report date
    prog_data = []
    for p in programs:
        sub_count = session.scalar(select(func.count(Submission.id)).where(Submission.program_id == p.id)) or 0
        paid_count = session.scalar(select(func.count(Submission.id)).where(Submission.program_id == p.id, Submission.disposition == "resolved")) or 0
        # Only consider reports that were actually submitted
        last_report_at = session.scalar(
            select(func.max(SubmissionReport.submitted_at)).where(
                SubmissionReport.program_id == p.id,
                SubmissionReport.status.in_(["submitted", "accepted", "rejected"]),
            )
        )
        prog_data.append({"program": p, "sub_count": sub_count, "paid_count": paid_count, "last_report_at": last_report_at})
    session.close()

    # In-memory sort for derived columns
    _min_dt = datetime.min.replace(tzinfo=timezone.utc)
    derived_sorts = {
        "subs": lambda x: x["sub_count"],
        "paid": lambda x: x["paid_count"],
        "rate": lambda x: (x["paid_count"] / x["sub_count"] * 100 if x["sub_count"] > 0 else -1),
        "last_report": lambda x: x["last_report_at"] or _min_dt,
    }
    sort_key_name = sort.lstrip("-") if sort else ""
    if sort_key_name in derived_sorts:
        prog_data.sort(key=derived_sorts[sort_key_name], reverse=sort.startswith("-"))
    elif not sort:
        # Default: last report desc (most recent activity first), no-reports at bottom
        prog_data.sort(key=lambda x: x["last_report_at"] or _min_dt, reverse=True)

    return _render(request, "programs.html", {
        "active_page": "programs",
        "programs": prog_data,
        "status_badge": _status_badge,
        "filter_platform": platform,
        "filter_status": status,
        "filter_search": search,
        "current_sort": sort,
        "company_logo_url": _company_logo_url,
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

    # Recon & attack surface from engagement
    engagement = service.get_engagement_by_program(program_id)
    recon_data = engagement.recon_data if engagement else {}
    attack_surface = engagement.attack_surface if engagement else {}

    session.close()

    return _render(request, "program_detail.html", {
        "active_page": "programs",
        "program": program,
        "findings": findings,
        "building_blocks": building_blocks,
        "reports": reports,
        "submissions": submissions,
        "activity": activity,
        "recon_data": recon_data or {},
        "attack_surface": attack_surface or {},
        "badge_class": _badge_class,
        "severity_badge": _severity_badge,
        "status_badge": _status_badge,
        "days_ago": _days_ago,
        "platform_url": _platform_url,
        "program_platform_url": _program_platform_url,
        "company_logo_url": _company_logo_url,
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
    rendered_desc = _safe_markdown(finding.description)
    rendered_steps = _safe_markdown(finding.steps_to_reproduce)
    rendered_impact = _safe_markdown(finding.impact)
    evidence_files = service.get_finding_evidence(finding_id)
    session.close()

    return _render(request, "finding_detail.html", {
        "active_page": "programs",
        "finding": finding,
        "program": program,
        "rendered_desc": rendered_desc,
        "rendered_steps": rendered_steps,
        "rendered_impact": rendered_impact,
        "evidence_files": evidence_files,
        "severity_badge": _severity_badge,
        "status_badge": _status_badge,
        "days_ago": _days_ago,
    })


@app.get("/evidence/{evidence_id}/preview", response_class=HTMLResponse)
async def evidence_preview(request: Request, evidence_id: int):
    """Return text content of a local evidence file as an HTML fragment (HTMX)."""
    from bounty_intel.db import EvidenceFile, get_session

    session = get_session()
    ef = session.get(EvidenceFile, evidence_id)
    if not ef:
        session.close()
        return HTMLResponse("<em class='muted'>Not found</em>", status_code=404)

    local_path = ef.local_path or ""
    content_type = ef.content_type or ""
    session.close()

    # Only serve text-based previews
    if not content_type.startswith("text/") and content_type not in (
        "application/json", "application/xml", "application/yaml",
    ):
        return HTMLResponse("<em class='muted'>Binary file — preview not available</em>")

    if not local_path:
        return HTMLResponse("<em class='muted'>No local file path</em>")

    try:
        p = Path(local_path)
        if not p.exists():
            return HTMLResponse("<em class='muted'>File not found on disk</em>")
        content = p.read_text(errors="replace")[:100_000]
        # Escape HTML
        import html as html_mod
        escaped = html_mod.escape(content)
        return HTMLResponse(
            f'<pre style="max-height:400px;overflow:auto;background:var(--surface);'
            f'padding:0.8rem;border-radius:6px;font-size:0.8rem;white-space:pre-wrap">'
            f'{escaped}</pre>'
        )
    except Exception:
        return HTMLResponse("<em class='muted'>Error reading file</em>")


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
        "company_logo_url": _company_logo_url,
    })


@app.get("/reports/{report_id}", response_class=HTMLResponse)
async def report_editor(request: Request, report_id: int):
    from bounty_intel.db import SubmissionReport, get_session

    session = get_session()
    report = session.get(SubmissionReport, report_id)
    if not report:
        session.close()
        return HTMLResponse("Report not found", status_code=404)

    rendered_html = _safe_markdown(report.markdown_body)

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
        "company_logo_url": _company_logo_url,
    })


@app.put("/reports/{report_id}", response_class=HTMLResponse)
async def update_report(request: Request, report_id: int):
    from bounty_intel import service

    form = await request.form()
    body = form.get("markdown_body", "")
    
    service.update_report(report_id, markdown_body=body)

    rendered = _safe_markdown(str(body))
    return HTMLResponse(rendered)


# ── Delete actions ───────────────────────────────────────────
@app.post("/findings/{finding_id}/delete", response_class=HTMLResponse)
async def delete_finding_web(request: Request, finding_id: int):
    from bounty_intel.db import Finding, SubmissionReport, get_session
    from sqlalchemy import select

    session = get_session()
    finding = session.get(Finding, finding_id)
    if not finding:
        session.close()
        return HTMLResponse("Not found", status_code=404)
    # Block if linked to submitted report
    linked = session.scalar(
        select(SubmissionReport).where(
            SubmissionReport.finding_id == finding_id,
            SubmissionReport.status.in_(["submitted", "accepted"]),
        )
    )
    if linked:
        session.close()
        return RedirectResponse(f"/findings/{finding_id}?error=Cannot+delete:+linked+to+submitted+report", status_code=303)
    program_id = finding.program_id
    session.delete(finding)
    session.commit()
    session.close()
    return RedirectResponse(f"/programs/{program_id}", status_code=303)


@app.post("/reports/{report_id}/delete", response_class=HTMLResponse)
async def delete_report_web(request: Request, report_id: int):
    from bounty_intel.db import SubmissionReport, get_session

    session = get_session()
    report = session.get(SubmissionReport, report_id)
    if not report:
        session.close()
        return HTMLResponse("Not found", status_code=404)
    if report.status in ("submitted", "accepted"):
        session.close()
        return RedirectResponse(f"/reports/{report_id}?error=Cannot+delete+submitted+report", status_code=303)
    session.delete(report)
    session.commit()
    session.close()
    return RedirectResponse("/reports", status_code=303)


@app.post("/programs/{program_id}/delete", response_class=HTMLResponse)
async def delete_program_web(request: Request, program_id: int):
    from bounty_intel.db import (Program, Finding, SubmissionReport, Submission,
                                  Engagement, Payout, AIEvaluation, EvidenceFile, get_session)
    from sqlalchemy import select

    form = await request.form()
    force = form.get("force") == "1"

    session = get_session()
    program = session.get(Program, program_id)
    if not program:
        session.close()
        return HTMLResponse("Not found", status_code=404)

    # Block if there are active/triaged submissions (real platform state)
    active_subs = [s for s in session.scalars(
        select(Submission).where(Submission.program_id == program_id)
    ).all() if s.disposition in ("resolved", "accepted", "triaged", "new")]
    if active_subs and not force:
        session.close()
        return RedirectResponse(f"/programs/{program_id}?error=Has+active+submissions", status_code=303)

    # Cascade delete via SQL (order matters for FK constraints)
    from sqlalchemy import delete

    # Submissions children first
    sub_ids = [s.id for s in session.scalars(select(Submission).where(Submission.program_id == program_id)).all()]
    if sub_ids:
        session.execute(delete(Payout).where(Payout.submission_id.in_(sub_ids)))
        session.execute(delete(AIEvaluation).where(AIEvaluation.submission_id.in_(sub_ids)))

    # Evidence files (finding + report)
    finding_ids = [f.id for f in session.scalars(select(Finding).where(Finding.program_id == program_id)).all()]
    report_ids = [r.id for r in session.scalars(select(SubmissionReport).where(SubmissionReport.program_id == program_id)).all()]
    if finding_ids:
        session.execute(delete(EvidenceFile).where(EvidenceFile.finding_id.in_(finding_ids)))
    if report_ids:
        session.execute(delete(EvidenceFile).where(EvidenceFile.report_id.in_(report_ids)))

    # Main tables
    session.execute(delete(Submission).where(Submission.program_id == program_id))
    session.execute(delete(SubmissionReport).where(SubmissionReport.program_id == program_id))
    session.execute(delete(Finding).where(Finding.program_id == program_id))
    session.execute(delete(Engagement).where(Engagement.program_id == program_id))
    session.delete(program)
    session.commit()
    session.close()
    return RedirectResponse("/programs", status_code=303)


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
        "company_logo_url": _company_logo_url,
    })


# ──────────────────────────────────────────────────────────────
# 4.7 — Hunt Intelligence (techniques + patterns + lessons)
# ──────────────────────────────────────────────────────────────
@app.get("/hunt", response_class=HTMLResponse)
async def hunt_intel(request: Request):
    from bounty_intel import service
    from bounty_intel.db import Finding, Payout, Program, Submission, SubmissionReport, get_session
    from sqlalchemy import func, select
    from sqlalchemy.orm import joinedload
    from collections import defaultdict

    session = get_session()

    # ── Overall stats ──
    total_subs = session.scalar(select(func.count(Submission.id))) or 0
    resolved = session.scalar(select(func.count(Submission.id)).where(Submission.disposition == "resolved")) or 0
    accepted = session.scalar(select(func.count(Submission.id)).where(Submission.disposition == "accepted")) or 0
    duplicates = session.scalar(select(func.count(Submission.id)).where(Submission.disposition == "duplicate")) or 0
    informative = session.scalar(select(func.count(Submission.id)).where(Submission.disposition == "informative")) or 0
    pending = session.scalar(select(func.count(Submission.id)).where(
        Submission.disposition.in_(["new", "triaged", "needs_more_info"]))) or 0
    # Calculate earnings with proper FX conversion
    from bounty_intel.forecast.fx import fetch_ecb_rate
    all_payouts = session.scalars(select(Payout)).all()
    total_paid = 0.0
    for p in all_payouts:
        amount = float(p.amount or 0)
        if amount <= 0:
            continue
        cur = p.currency or "EUR"
        if cur == "EUR":
            total_paid += amount
        else:
            pdate = p.paid_date.isoformat() if p.paid_date else date.today().isoformat()
            total_paid += amount * fetch_ecb_rate(cur, pdate)

    overview = {
        "total": total_subs,
        "resolved": resolved,
        "accepted": accepted,
        "pending": pending,
        "duplicates": duplicates,
        "informative": informative,
        "acceptance_rate": round((resolved + accepted) / total_subs * 100, 1) if total_subs else 0,
        "rejection_rate": round((duplicates + informative) / total_subs * 100, 1) if total_subs else 0,
        "total_paid": round(total_paid, 2),
    }

    # ── Per-program performance ──
    all_subs = session.scalars(
        select(Submission).options(joinedload(Submission.program)).order_by(Submission.created_at.desc())
    ).unique().all()

    program_perf: dict[int, dict] = {}
    for sub in all_subs:
        pid = sub.program_id
        if pid not in program_perf:
            program_perf[pid] = {
                "name": sub.program.company_name if sub.program else "?",
                "platform": sub.platform,
                "total": 0, "resolved": 0, "accepted": 0, "rejected": 0, "pending": 0,
                "severities": [], "latest": sub.created_at,
            }
        pp = program_perf[pid]
        pp["total"] += 1
        if sub.disposition in ("resolved",):
            pp["resolved"] += 1
        elif sub.disposition in ("accepted",):
            pp["accepted"] += 1
        elif sub.disposition in ("duplicate", "informative", "not_applicable", "out_of_scope", "wont_fix"):
            pp["rejected"] += 1
        else:
            pp["pending"] += 1
        if sub.severity:
            pp["severities"].append(sub.severity)

    # Add payout totals per program (with FX conversion)
    for pid in program_perf:
        payouts = session.scalars(
            select(Payout).join(Submission).where(Submission.program_id == pid)
        ).all()
        paid_eur = 0.0
        for p in payouts:
            amt = float(p.amount or 0)
            if amt <= 0:
                continue
            cur = p.currency or "EUR"
            if cur == "EUR":
                paid_eur += amt
            else:
                pdate = p.paid_date.isoformat() if p.paid_date else date.today().isoformat()
                paid_eur += amt * fetch_ecb_rate(cur, pdate)
        program_perf[pid]["paid"] = round(paid_eur, 2)
        total = program_perf[pid]["total"]
        won = program_perf[pid]["resolved"] + program_perf[pid]["accepted"]
        program_perf[pid]["rate"] = round(won / total * 100) if total else 0

    sorted_programs = sorted(program_perf.values(), key=lambda x: x["paid"], reverse=True)

    # ── Submission timeline (by week) ──
    timeline: dict[str, dict] = {}
    for sub in all_subs:
        if not sub.created_at:
            continue
        week = sub.created_at.strftime("%Y-W%W")
        if week not in timeline:
            timeline[week] = {"submitted": 0, "accepted": 0, "rejected": 0}
        timeline[week]["submitted"] += 1
        if sub.disposition in ("resolved", "accepted"):
            timeline[week]["accepted"] += 1
        elif sub.disposition in ("duplicate", "informative", "not_applicable", "out_of_scope"):
            timeline[week]["rejected"] += 1
    sorted_timeline = sorted(timeline.items())[-12:]  # last 12 weeks

    # ── Rejection deep-dive: per-disposition with example titles ──
    rejection_detail: dict[str, dict] = {}
    for sub in all_subs:
        if sub.disposition not in ("duplicate", "informative", "not_applicable", "out_of_scope", "wont_fix"):
            continue
        d = sub.disposition
        if d not in rejection_detail:
            rejection_detail[d] = {"count": 0, "examples": [], "programs": set()}
        rejection_detail[d]["count"] += 1
        rejection_detail[d]["programs"].add(sub.program.company_name if sub.program else "?")
        if len(rejection_detail[d]["examples"]) < 3:
            rejection_detail[d]["examples"].append({
                "title": sub.title[:80] if sub.title else "",
                "program": sub.program.company_name if sub.program else "?",
                "severity": sub.severity,
            })
    # Convert sets to lists for template
    for d in rejection_detail:
        rejection_detail[d]["programs"] = sorted(rejection_detail[d]["programs"])

    # ── Severity distribution: what severity gets accepted vs rejected ──
    severity_matrix: dict[str, dict] = {}
    for sub in all_subs:
        sev = sub.severity or "Unknown"
        if sev not in severity_matrix:
            severity_matrix[sev] = {"total": 0, "won": 0, "rejected": 0, "pending": 0}
        severity_matrix[sev]["total"] += 1
        if sub.disposition in ("resolved", "accepted"):
            severity_matrix[sev]["won"] += 1
        elif sub.disposition in ("duplicate", "informative", "not_applicable", "out_of_scope"):
            severity_matrix[sev]["rejected"] += 1
        else:
            severity_matrix[sev]["pending"] += 1
    sev_order = ["Critical", "Exceptional", "High", "Medium", "Low", "None", "Unknown"]
    sorted_severity = [(s, severity_matrix[s]) for s in sev_order if s in severity_matrix]

    # ── Platform comparison ──
    platform_stats: dict[str, dict] = {}
    for sub in all_subs:
        p = sub.platform
        if p not in platform_stats:
            platform_stats[p] = {"total": 0, "won": 0, "rejected": 0, "pending": 0}
        platform_stats[p]["total"] += 1
        if sub.disposition in ("resolved", "accepted"):
            platform_stats[p]["won"] += 1
        elif sub.disposition in ("duplicate", "informative", "not_applicable", "out_of_scope"):
            platform_stats[p]["rejected"] += 1
        else:
            platform_stats[p]["pending"] += 1

    # ── Hunt memory techniques ──
    hunt_entries = service.get_hunt_memory()
    tech_vulns: dict[str, list] = {}
    for e in hunt_entries:
        for tech in (e.tech_stack or []):
            if tech not in tech_vulns:
                tech_vulns[tech] = []
            tech_vulns[tech].append({
                "vuln_class": e.vuln_class, "success": e.success,
                "technique": e.technique_summary,
            })

    session.close()

    return _render(request, "hunt.html", {
        "active_page": "hunt",
        "overview": overview,
        "program_perf": sorted_programs,
        "timeline": sorted_timeline,
        "rejection_detail": rejection_detail,
        "severity_matrix": sorted_severity,
        "platform_stats": platform_stats,
        "tech_vulns": tech_vulns,
        "hunt_entries": hunt_entries,
        "badge_class": _badge_class,
        "severity_badge": _severity_badge,
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

    session = get_session()
    ef = session.get(EvidenceFile, evidence_id)
    if not ef:
        session.close()
        return HTMLResponse("Not found", status_code=404)

    gcs_path = ef.gcs_path or ""
    local_path = ef.local_path or ""
    content_type = ef.content_type or "application/octet-stream"
    filename = ef.filename or "evidence"
    session.close()

    # Try GCS signed URL first
    if gcs_path:
        try:
            from bounty_intel.evidence.uploader import generate_signed_url
            url = generate_signed_url(gcs_path)
            return RedirectResponse(url)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("Signed URL failed for %s: %s", gcs_path, exc)

    # Fall back to serving local file
    if local_path:
        from pathlib import Path
        p = Path(local_path)
        if p.exists():
            from fastapi.responses import FileResponse
            return FileResponse(p, media_type=content_type, filename=filename)

    return HTMLResponse("Evidence file not available", status_code=404)
