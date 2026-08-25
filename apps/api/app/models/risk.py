import uuid
from datetime import date, datetime

from sqlalchemy import Date, DateTime, ForeignKey, Numeric, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import Level, RiskStatus
from app.models.base import Base, StrEnumType, TenantOwned, Timestamps, UUIDPrimaryKey


class Risk(UUIDPrimaryKey, TenantOwned, Timestamps, Base):
    """What a finding *means* in business context.

    Separate entity from Finding on purpose: "RDP is open" is a fact about a
    config; "an internet-reachable production jump box accepts RDP from
    anywhere" is a risk. 1:1 with findings for the MVP, via risk_findings.
    """

    __tablename__ = "risks"

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
