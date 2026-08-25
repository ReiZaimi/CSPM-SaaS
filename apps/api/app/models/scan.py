import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import ScanStatus
from app.models.base import Base, StrEnumType, TenantOwned, Timestamps, UUIDPrimaryKey


class Scan(UUIDPrimaryKey, TenantOwned, Timestamps, Base):
    __tablename__ = "scans"

    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[ScanStatus] = mapped_column(
        StrEnumType(ScanStatus, 24), nullable=False, default=ScanStatus.QUEUED, index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    resource_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rule_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    error_message: Mapped[str | None] = mapped_column(Text)
    # Category-level collection failures, e.g. {"storage": "timeout"}. Drives
    # PARTIAL status and the UNKNOWN degradation path (AZURE_INTEGRATION.md section 5).
    collection_errors: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class CloudSnapshot(UUIDPrimaryKey, TenantOwned, Base):
    """The raw, pre-normalization capture. Every scan produces exactly one.

    Kept verbatim so a scan can be replayed against new rules, and so drift
    between two scans is a diff rather than an inference.
    """

    __tablename__ = "cloud_snapshots"
    __table_args__ = (UniqueConstraint("scan_id", name="uq_cloud_snapshots_scan_id"),)

    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    snapshot_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    data: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ScanRuleResult(UUIDPrimaryKey, TenantOwned, Base):
    """Per-(scan, rule) aggregate. PASS/NOT_APPLICABLE live here rather than as
    millions of per-resource rows (RULE_ENGINE.md section 2)."""

    __tablename__ = "scan_rule_results"
    __table_args__ = (UniqueConstraint("scan_id", "rule_id"),)

    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(32), nullable=False)

    evaluated_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    passed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unknown_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    not_applicable_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ScanEvaluationGap(UUIDPrimaryKey, TenantOwned, Base):
    """One row per UNKNOWN evaluation -- why we could not tell.

    This is the coverage ledger. An UNKNOWN never becomes a Finding, but it must
    never vanish either, or "84/100" would silently mean "84/100 of what we
    happened to be able to look at".
    """

    __tablename__ = "scan_evaluation_gaps"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(32), nullable=False)
    # NULL for AGGREGATE-scope rules, which are not about any single resource.
    resource_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_resources.id", ondelete="CASCADE")
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
