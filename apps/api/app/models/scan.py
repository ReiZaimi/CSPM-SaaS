import uuid
from datetime import UTC, datetime
from typing import ClassVar

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

    # Who asked for this run. Not an FK: auth.users belongs to Supabase.
    triggered_by_user_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))

    # How far along a running scan is. Status moves in five coarse jumps, so a
    # large tenant sits on one of them long enough to look stalled.
    progress_done: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    progress_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    @property
    def duration_seconds(self) -> int | None:
        """Elapsed time, live while running and fixed once finished."""
        if self.started_at is None:
            return None
        end = self.completed_at or datetime.now(UTC)
        return max(0, int((end - self.started_at).total_seconds()))

    # How long a scan may sit unclaimed before the UI stops implying it is
    # about to start. A worker picks work up in seconds when one is running, so
    # minutes of silence means nothing is listening -- almost always the Celery
    # worker service not deployed, or unable to reach Redis.
    QUEUE_PATIENCE_SECONDS: ClassVar[int] = 120

    @property
    def stuck_in_queue(self) -> bool:
        """Queued long enough that waiting no longer explains it."""
        if self.status != ScanStatus.QUEUED or self.created_at is None:
            return False
        waited = datetime.now(UTC) - self.created_at
        return waited.total_seconds() > self.QUEUE_PATIENCE_SECONDS
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
