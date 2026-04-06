"""Internal database service — used by the web app and API endpoints.

This module provides direct DB access for server-side code.
External consumers (skills) use BountyIntelClient (HTTP) instead.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from sqlalchemy import Integer, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, joinedload

from bounty_intel.db import (
    AIEvaluation,
    ActivityLog,
    Engagement,
    EngagementSnapshot,
    EvidenceFile,
    Finding,
    HuntMemory,
    Payout,
    Program,
    Submission,
    SubmissionReport,
    SyncState,
    get_session,
)


def _utcnow():
    return datetime.now(timezone.utc)


# ── Programs ─────────────────────────────────────────────────
def list_programs(platform: str | None = None, status: str | None = None) -> list[Program]:
    with get_session() as s:
        q = select(Program)
        if platform:
            q = q.where(Program.platform == platform)
        if status:
            q = q.where(Program.status == status)
        return list(s.scalars(q.order_by(Program.company_name)).all())


def upsert_program(*, platform: str, handle: str, company_name: str, **kwargs) -> int:
    with get_session() as s:
        stmt = pg_insert(Program).values(
            platform=platform, platform_handle=handle, company_name=company_name, **kwargs,
        )
        stmt = stmt.on_conflict_do_update(
            constraint="uq_program_platform_handle",
            set_={"company_name": stmt.excluded.company_name, "updated_at": _utcnow(),
                   **{k: getattr(stmt.excluded, k) for k in kwargs if k != "created_at"}},
        )
        result = s.execute(stmt.returning(Program.id))
        s.commit()
        return result.scalar_one()


# ── Engagements ──────────────────────────────────────────────
def get_engagement(platform: str, handle: str) -> Engagement | None:
    with get_session() as s:
        program = s.scalar(select(Program).where(Program.platform == platform, Program.platform_handle == handle))
        if not program:
            return None
        return s.scalar(select(Engagement).where(Engagement.program_id == program.id).order_by(Engagement.started_at.desc()))


def create_engagement(program_id: int, **kwargs) -> int:
    with get_session() as s:
        eng = Engagement(program_id=program_id, **kwargs)
        s.add(eng)
        s.commit()
        return eng.id


def update_engagement(engagement_id: int, **kwargs) -> None:
    with get_session() as s:
        eng = s.get(Engagement, engagement_id)
        if eng:
            for k, v in kwargs.items():
                setattr(eng, k, v)
            s.commit()


# ── Findings ─────────────────────────────────────────────────
def get_findings(*, engagement_id: int | None = None, program_id: int | None = None,
                 status: str | None = None, severity: str | None = None,
                 vuln_class: str | None = None, is_building_block: bool | None = None) -> list[Finding]:
    with get_session() as s:
        q = select(Finding).options(joinedload(Finding.program))
        if engagement_id is not None:
            q = q.where(Finding.engagement_id == engagement_id)
        if program_id is not None:
            q = q.where(Finding.program_id == program_id)
        if status is not None:
            q = q.where(Finding.status == status)
        if severity is not None:
            q = q.where(Finding.severity == severity)
        if vuln_class is not None:
            q = q.where(Finding.vuln_class == vuln_class)
        if is_building_block is not None:
            q = q.where(Finding.is_building_block == is_building_block)
        return list(s.scalars(q.order_by(Finding.created_at.desc())).unique().all())


def save_finding(*, program_id: int, **kwargs) -> int:
    with get_session() as s:
        finding = Finding(program_id=program_id, **kwargs)
        s.add(finding)
        s.commit()
        return finding.id


def update_finding(finding_id: int, **kwargs) -> None:
    with get_session() as s:
        finding = s.get(Finding, finding_id)
        if finding:
            for k, v in kwargs.items():
                setattr(finding, k, v)
            finding.updated_at = _utcnow()
            s.commit()


# ── Reports ──────────────────────────────────────────────────
def list_reports(status: str | None = None, program_id: int | None = None) -> list[SubmissionReport]:
    with get_session() as s:
        q = select(SubmissionReport).options(joinedload(SubmissionReport.program))
        if status:
            q = q.where(SubmissionReport.status == status)
        if program_id:
            q = q.where(SubmissionReport.program_id == program_id)
        return list(s.scalars(q.order_by(SubmissionReport.updated_at.desc())).unique().all())


def create_report(**kwargs) -> int:
    with get_session() as s:
        report = SubmissionReport(status="draft", **kwargs)
        s.add(report)
        s.commit()
        return report.id


def update_report(report_id: int, **kwargs) -> None:
    with get_session() as s:
        report = s.get(SubmissionReport, report_id)
        if report:
            for k, v in kwargs.items():
                setattr(report, k, v)
            report.updated_at = _utcnow()
            s.commit()


def mark_report_submitted(report_id: int, platform_submission_id: str) -> None:
    with get_session() as s:
        report = s.get(SubmissionReport, report_id)
        if report:
            report.status = "submitted"
            report.submitted_at = _utcnow()
            report.platform_submission_id = platform_submission_id
            s.commit()


# ── Submissions ──────────────────────────────────────────────
def get_submissions(*, platform: str | None = None, disposition: str | None = None,
                    program_id: int | None = None) -> list[Submission]:
    with get_session() as s:
        q = select(Submission).options(joinedload(Submission.program))
        if platform:
            q = q.where(Submission.platform == platform)
        if disposition:
            q = q.where(Submission.disposition == disposition)
        if program_id:
            q = q.where(Submission.program_id == program_id)
        return list(s.scalars(q.order_by(Submission.created_at.desc())).unique().all())


# ── Hunt Memory ──────────────────────────────────────────────
def record_hunt(**kwargs) -> int:
    with get_session() as s:
        if "payout" in kwargs:
            kwargs["payout"] = Decimal(str(kwargs["payout"]))
        hm = HuntMemory(**kwargs)
        s.add(hm)
        s.commit()
        return hm.id


def get_hunt_memory(target: str | None = None, vuln_class: str | None = None) -> list[HuntMemory]:
    with get_session() as s:
        q = select(HuntMemory)
        if target:
            q = q.where(HuntMemory.target == target)
        if vuln_class:
            q = q.where(HuntMemory.vuln_class == vuln_class)
        return list(s.scalars(q.order_by(HuntMemory.recorded_at.desc())).all())


def suggest_attacks(tech_stack: list[str]) -> list[dict]:
    with get_session() as s:
        results = s.execute(
            select(
                HuntMemory.vuln_class,
                func.count().label("total"),
                func.sum(HuntMemory.success.cast(Integer)).label("successes"),
                func.avg(HuntMemory.payout).label("avg_payout"),
            )
            .where(HuntMemory.tech_stack.overlap(tech_stack))
            .group_by(HuntMemory.vuln_class)
            .order_by(func.sum(HuntMemory.success.cast(Integer)).desc())
        ).all()
        return [{"vuln_class": r.vuln_class, "total_attempts": r.total,
                 "successes": r.successes or 0,
                 "success_rate": (r.successes or 0) / r.total if r.total else 0,
                 "avg_payout": float(r.avg_payout or 0)} for r in results]


# ── Activity ─────────────────────────────────────────────────
def log_activity(engagement_id: int | None, action: str, details: dict | None = None) -> int:
    with get_session() as s:
        log = ActivityLog(engagement_id=engagement_id, action=action, details=details or {})
        s.add(log)
        s.commit()
        return log.id


def get_activity(engagement_id: int | None = None, limit: int = 100) -> list[ActivityLog]:
    with get_session() as s:
        q = select(ActivityLog)
        if engagement_id:
            q = q.where(ActivityLog.engagement_id == engagement_id)
        return list(s.scalars(q.order_by(ActivityLog.created_at.desc()).limit(limit)).all())


# ── AI Evaluations ───────────────────────────────────────────
def save_ai_evaluation(submission_id: int, **kwargs) -> int:
    with get_session() as s:
        existing = s.scalar(select(AIEvaluation).where(AIEvaluation.submission_id == submission_id))
        if existing:
            for k, v in kwargs.items():
                setattr(existing, k, v)
            existing.evaluated_at = _utcnow()
            s.commit()
            return existing.id
        ev = AIEvaluation(submission_id=submission_id, **kwargs)
        s.add(ev)
        s.commit()
        return ev.id


# ── Sync State ───────────────────────────────────────────────
def get_sync_state(source: str) -> SyncState | None:
    with get_session() as s:
        return s.get(SyncState, source)


def update_sync_state(source: str, last_submission_updated: datetime) -> None:
    with get_session() as s:
        stmt = pg_insert(SyncState).values(
            source=source, last_sync_at=_utcnow(), last_submission_updated=last_submission_updated,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=["source"],
            set_={"last_sync_at": _utcnow(), "last_submission_updated": stmt.excluded.last_submission_updated},
        )
        s.execute(stmt)
        s.commit()


# ── Stats ────────────────────────────────────────────────────
def get_stats() -> dict:
    with get_session() as s:
        return {
            "total_programs": s.scalar(select(func.count(Program.id))) or 0,
            "total_engagements": s.scalar(select(func.count(Engagement.id))) or 0,
            "total_findings": s.scalar(select(func.count(Finding.id))) or 0,
            "total_building_blocks": s.scalar(select(func.count(Finding.id)).where(Finding.is_building_block.is_(True))) or 0,
            "total_submissions": s.scalar(select(func.count(Submission.id))) or 0,
            "total_reports": s.scalar(select(func.count(SubmissionReport.id))) or 0,
            "total_hunt_entries": s.scalar(select(func.count(HuntMemory.id))) or 0,
            "total_evidence_files": s.scalar(select(func.count(EvidenceFile.id))) or 0,
        }
