"""SQLAlchemy 2.0 models and engine factory for the Bounty Intelligence System."""

from datetime import date, datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker

from bounty_intel.config import settings


class Base(DeclarativeBase):
    pass


def _utcnow():
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# 1. programs
# ---------------------------------------------------------------------------
class Program(Base):
    __tablename__ = "programs"

    id = Column(Integer, primary_key=True)
    platform = Column(String(20), nullable=False)
    platform_handle = Column(String(255), nullable=False)
    company_name = Column(String(255), nullable=False)
    program_name = Column(String(255))
    status = Column(String(20), default="open")
    bounty_type = Column(String(10), default="bounty")
    scope = Column(JSONB, default=dict)
    oos_rules = Column(JSONB, default=dict)
    tech_stack = Column(ARRAY(Text), default=list)
    logo_url = Column(Text, default="")
    notes = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        UniqueConstraint("platform", "platform_handle", name="uq_program_platform_handle"),
    )

    engagements = relationship("Engagement", back_populates="program")
    findings = relationship("Finding", back_populates="program")
    submissions = relationship("Submission", back_populates="program")
    submission_reports = relationship("SubmissionReport", back_populates="program")


# ---------------------------------------------------------------------------
# 2. engagements
# ---------------------------------------------------------------------------
class Engagement(Base):
    __tablename__ = "engagements"

    id = Column(Integer, primary_key=True)
    program_id = Column(Integer, ForeignKey("programs.id"), nullable=False)
    status = Column(String(20), default="active")
    started_at = Column(DateTime(timezone=True), default=_utcnow)
    notes = Column(Text, default="")
    recon_data = Column(JSONB, default=dict)
    attack_surface = Column(JSONB, default=dict)

    program = relationship("Program", back_populates="engagements")
    findings = relationship("Finding", back_populates="engagement")
    activity_logs = relationship("ActivityLog", back_populates="engagement")


# ---------------------------------------------------------------------------
# 3. findings
# ---------------------------------------------------------------------------
class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    engagement_id = Column(Integer, ForeignKey("engagements.id"))
    program_id = Column(Integer, ForeignKey("programs.id"), nullable=False)
    title = Column(Text, nullable=False)
    vuln_class = Column(String(100))
    severity = Column(String(20))
    cvss_vector = Column(String(100))
    status = Column(String(30), default="discovered")
    description = Column(Text, default="")
    steps_to_reproduce = Column(Text, default="")
    impact = Column(Text, default="")
    poc_code = Column(Text, default="")
    poc_output = Column(Text, default="")
    chain_with = Column(ARRAY(Integer), default=list)
    is_building_block = Column(Boolean, default=False)
    building_block_notes = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        Index("ix_finding_engagement", "engagement_id"),
        Index("ix_finding_program_status", "program_id", "status"),
        Index("ix_finding_vuln_class", "vuln_class"),
        Index("ix_finding_building_block", "is_building_block"),
    )

    engagement = relationship("Engagement", back_populates="findings")
    program = relationship("Program", back_populates="findings")
    evidence_files = relationship("EvidenceFile", back_populates="finding")
    submission_report = relationship("SubmissionReport", back_populates="finding", uselist=False)


# ---------------------------------------------------------------------------
# 4. submission_reports
# ---------------------------------------------------------------------------
class SubmissionReport(Base):
    __tablename__ = "submission_reports"

    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey("findings.id"))
    program_id = Column(Integer, ForeignKey("programs.id"), nullable=False)
    platform = Column(String(20), nullable=False)
    report_slug = Column(String(100))
    title = Column(Text, nullable=False)
    severity = Column(String(20))
    cvss_vector = Column(String(100))
    markdown_body = Column(Text, nullable=False)
    status = Column(String(30), default="draft")
    validation_result = Column(JSONB, default=dict)
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    submitted_at = Column(DateTime(timezone=True))
    platform_submission_id = Column(String(255))

    __table_args__ = (
        Index("ix_report_program_status", "program_id", "status"),
        Index("ix_report_platform_slug", "platform", "report_slug"),
    )

    finding = relationship("Finding", back_populates="submission_report")
    program = relationship("Program", back_populates="submission_reports")
    evidence_files = relationship("EvidenceFile", back_populates="report")
    submission = relationship(
        "Submission", back_populates="report", uselist=False, foreign_keys="Submission.report_id"
    )


# ---------------------------------------------------------------------------
# 5. submissions (synced from platform APIs)
# ---------------------------------------------------------------------------
class Submission(Base):
    __tablename__ = "submissions"

    id = Column(Integer, primary_key=True)
    platform_id = Column(String(255), nullable=False)
    program_id = Column(Integer, ForeignKey("programs.id"))
    report_id = Column(Integer, ForeignKey("submission_reports.id"))
    platform = Column(String(20), nullable=False)
    title = Column(Text)
    severity = Column(String(20))
    disposition = Column(String(30), nullable=False)
    listed_bounty = Column(Numeric(12, 2), default=0)
    listed_currency = Column(String(3), default="EUR")
    created_at = Column(DateTime(timezone=True))
    last_updated = Column(DateTime(timezone=True))
    synced_at = Column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        UniqueConstraint("platform", "platform_id", name="uq_submission_platform_id"),
        Index("ix_submission_platform_disposition", "platform", "disposition"),
        Index("ix_submission_program", "program_id"),
        Index("ix_submission_created", "created_at"),
        Index("ix_submission_synced", "synced_at"),
    )

    program = relationship("Program", back_populates="submissions")
    report = relationship("SubmissionReport", back_populates="submission", foreign_keys=[report_id])
    payouts = relationship("Payout", back_populates="submission", cascade="all, delete-orphan")
    ai_evaluation = relationship("AIEvaluation", back_populates="submission", uselist=False)


# ---------------------------------------------------------------------------
# 6. payouts
# ---------------------------------------------------------------------------
class Payout(Base):
    __tablename__ = "payouts"

    id = Column(Integer, primary_key=True)
    submission_id = Column(Integer, ForeignKey("submissions.id", ondelete="CASCADE"), nullable=False)
    amount = Column(Numeric(12, 2), nullable=False)
    currency = Column(String(3), nullable=False)
    amount_eur = Column(Numeric(12, 2))
    exchange_rate = Column(Numeric(10, 6))
    rate_date = Column(Date)
    payout_type = Column(String(20), default="Bounty")
    status = Column(String(20), default="Pending")
    paid_date = Column(Date)

    submission = relationship("Submission", back_populates="payouts")


# ---------------------------------------------------------------------------
# 7. ai_evaluations
# ---------------------------------------------------------------------------
class AIEvaluation(Base):
    __tablename__ = "ai_evaluations"

    id = Column(Integer, primary_key=True)
    submission_id = Column(Integer, ForeignKey("submissions.id", ondelete="CASCADE"), nullable=False)
    acceptance_probability = Column(Numeric(4, 2))
    confidence = Column(Numeric(4, 2))
    likely_outcome = Column(String(30))
    severity_assessment = Column(String(20))
    strengths = Column(ARRAY(Text), default=list)
    weaknesses = Column(ARRAY(Text), default=list)
    triager_reasoning = Column(Text, default="")
    suggested_improvements = Column(ARRAY(Text), default=list)
    evaluated_at = Column(DateTime(timezone=True), default=_utcnow)

    submission = relationship("Submission", back_populates="ai_evaluation")


# ---------------------------------------------------------------------------
# 8. evidence_files
# ---------------------------------------------------------------------------
class EvidenceFile(Base):
    __tablename__ = "evidence_files"

    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey("findings.id"))
    report_id = Column(Integer, ForeignKey("submission_reports.id"))
    gcs_path = Column(Text, nullable=False)
    filename = Column(Text, nullable=False)
    content_type = Column(String(100))
    size_bytes = Column(BigInteger)
    uploaded_at = Column(DateTime(timezone=True), default=_utcnow)

    finding = relationship("Finding", back_populates="evidence_files")
    report = relationship("SubmissionReport", back_populates="evidence_files")


# ---------------------------------------------------------------------------
# 9. hunt_memory
# ---------------------------------------------------------------------------
class HuntMemory(Base):
    __tablename__ = "hunt_memory"

    id = Column(Integer, primary_key=True)
    target = Column(String(255), nullable=False)
    domain = Column(String(255))
    vuln_class = Column(String(100), nullable=False)
    tech_stack = Column(ARRAY(Text), default=list)
    success = Column(Boolean, default=False)
    payout = Column(Numeric(12, 2), default=0)
    severity = Column(String(20))
    technique_summary = Column(Text, default="")
    chain = Column(String(255))
    platform = Column(String(20))
    recorded_at = Column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        Index("ix_hunt_vuln_class", "vuln_class"),
        Index("ix_hunt_tech_stack", "tech_stack", postgresql_using="gin"),
    )


# ---------------------------------------------------------------------------
# 10. activity_log
# ---------------------------------------------------------------------------
class ActivityLog(Base):
    __tablename__ = "activity_log"

    id = Column(Integer, primary_key=True)
    engagement_id = Column(Integer, ForeignKey("engagements.id"))
    action = Column(String(100), nullable=False)
    details = Column(JSONB, default=dict)
    created_at = Column(DateTime(timezone=True), default=_utcnow)

    engagement = relationship("Engagement", back_populates="activity_logs")


# ---------------------------------------------------------------------------
# 11. sync_state
# ---------------------------------------------------------------------------
class SyncState(Base):
    __tablename__ = "sync_state"

    source = Column(String(50), primary_key=True)
    last_sync_at = Column(DateTime(timezone=True))
    last_submission_updated = Column(DateTime(timezone=True))
    sync_metadata = Column(JSONB, default=dict)


# ---------------------------------------------------------------------------
# 12. engagement_snapshots
# ---------------------------------------------------------------------------
class EngagementSnapshot(Base):
    __tablename__ = "engagement_snapshots"

    id = Column(Integer, primary_key=True)
    snapshot_date = Column(Date, unique=True, nullable=False)
    confirmed_earnings_eur = Column(Numeric(12, 2), default=0)
    expected_earnings_eur = Column(Numeric(12, 2), default=0)
    acceptance_rate = Column(Numeric(4, 2), default=0)
    forecast_json = Column(JSONB, default=dict)


# ---------------------------------------------------------------------------
# Engine factory
# ---------------------------------------------------------------------------
_engine = None
_SessionLocal = None


def get_engine():
    global _engine
    if _engine is not None:
        return _engine

    db_url = settings.get_database_url()
    _engine = create_engine(db_url, pool_pre_ping=True, pool_size=5, max_overflow=10)
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine())
    return _SessionLocal


def get_session() -> Session:
    return get_session_factory()()


def create_all_tables():
    Base.metadata.create_all(get_engine())
