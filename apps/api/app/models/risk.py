import uuid
from datetime import date, datetime

from sqlalchemy import (
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import Level, RiskKind, RiskStatus
from app.models.base import Base, StrEnumType, TenantOwned, Timestamps, UUIDPrimaryKey


class Risk(UUIDPrimaryKey, TenantOwned, Timestamps, Base):
    """What a finding *means* in business context.

    Separate entity from Finding on purpose: "RDP is open" is a fact about a
    config; "an internet-reachable production jump box accepts RDP from
    anywhere" is a risk. 1:1 with findings for the MVP, via risk_findings.
    """

    __tablename__ = "risks"

    kind: Mapped[RiskKind] = mapped_column(
        StrEnumType(RiskKind, 16), nullable=False, default=RiskKind.FINDING
    )
    # The route, hop by hop, for a scenario risk. Empty for a finding risk,
    # which is about one asset and has no route to describe.
    path: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # What makes a scenario the same scenario between scans. A finding risk is
    # identified by its finding; a path has no finding of its own, so it is
    # identified by where it starts and ends.
    scenario_key: Mapped[str | None] = mapped_column(String(2100))

    title: Mapped[str] = mapped_column(String(400), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    risk_score: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False, default=0)
    risk_level: Mapped[Level] = mapped_column(
        StrEnumType(Level, 16), nullable=False, default=Level.LOW
    )
    status: Mapped[RiskStatus] = mapped_column(
        StrEnumType(RiskStatus, 16), nullable=False, default=RiskStatus.OPEN, index=True
    )

    # The scored inputs, retained so the UI can show "why is this 78?" without
    # recomputing anything.
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    asset_criticality: Mapped[Level] = mapped_column(StrEnumType(Level, 16), nullable=False)
    data_sensitivity: Mapped[Level] = mapped_column(StrEnumType(Level, 16), nullable=False)
    internet_exposure: Mapped[Level] = mapped_column(StrEnumType(Level, 16), nullable=False)
    exploitability: Mapped[int] = mapped_column(Numeric(3, 1), nullable=False, default=0)
    # Computed (mean of criticality and sensitivity), never set by hand.
    business_impact: Mapped[float] = mapped_column(Numeric(3, 1), nullable=False, default=0)

    # Full component -> contribution breakdown from the scorer.
    score_breakdown: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    owner_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))
    due_date: Mapped[date | None] = mapped_column(Date)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RiskFinding(Base):
    """Junction. 1:1 today; the shape already supports grouping several findings
    into one risk later without a migration (RISK_ENGINE.md section 2)."""

    __tablename__ = "risk_findings"

    risk_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("risks.id", ondelete="CASCADE"),
        primary_key=True,
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        primary_key=True,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )


class RiskHistory(UUIDPrimaryKey, TenantOwned, Base):
    """What the posture was, each time CloudGuard looked.

    "Did my risk go up?" is the question a customer asks after doing the work,
    and nothing recorded the answer. The dashboard showed a delta, and it was an
    estimate rather than a measurement: it reconstructed a prior score by adding
    back the deduction for every finding ever verified fixed, which answers
    "how much better than when we started" and was labelled "movement since the
    last scan".

    Denormalized on purpose. This is a time series, and the point of one is
    being read as a run of numbers without joining anything -- these counts are
    what was true at that moment, not a query that would answer differently
    tomorrow because a finding has since been reclassified or a risk regrouped.
    """

    __tablename__ = "risk_history"
    __table_args__ = (
        Index("ix_risk_history_timeline", "organization_id", "observed_at"),
    )

    # SET NULL rather than CASCADE: pruning an execution log must not rewrite
    # history, exactly as deleting a scan leaves the findings it raised alone.
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )
    # When the provider was read, not when this row was written. A replay
    # carries its capture's own time, and a history plotted on write time would
    # put month-old evidence at today's date.
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    security_score: Mapped[int] = mapped_column(Integer, nullable=False)
    open_finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings_by_severity: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    risk_bands: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # Routes open at that moment. "Did a new attack path appear" is answerable
    # from the risks table; this is what makes "are there more than last week"
    # answerable at a glance.
    attack_path_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
