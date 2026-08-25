import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Numeric, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import FindingStatus, Severity
from app.models.base import Base, StrEnumType, TenantOwned, Timestamps, UUIDPrimaryKey


class Finding(UUIDPrimaryKey, TenantOwned, Timestamps, Base):
    """A technical observation: "we saw this, and it is wrong."

    Identity is (organization, rule, resource) -- a re-detection updates the
    existing row rather than piling up duplicates every scan. ``scan_id`` records
    the scan that most recently detected it.
    """

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "rule_id", "resource_id", name="uq_findings_org_rule_resource"
        ),
        Index("ix_findings_org_status", "organization_id", "status"),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    rule_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    # NULL for AGGREGATE-scope findings that are about the tenant, not a resource.
    resource_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_resources.id", ondelete="CASCADE")
    )

    severity: Mapped[Severity] = mapped_column(StrEnumType(Severity, 16), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(
        StrEnumType(FindingStatus, 24), nullable=False, default=FindingStatus.OPEN
    )
    title: Mapped[str] = mapped_column(String(400), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Snapshot-copied from the rule at creation so later edits to a rule's
    # guidance do not rewrite the history of old findings.
    remediation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    rule_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")

    risk_score: Mapped[float | None] = mapped_column(Numeric(5, 2))

    first_detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # The scan whose PASS verified the fix. This IS the verification -- there is
    # no human "mark as verified" step (RULE_ENGINE.md section 3).
    resolved_by_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )
