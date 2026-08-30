import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import AssetChange, FindingEvent, FindingStatus
from app.models.base import Base, StrEnumType, TenantOwned, UUIDPrimaryKey


class AssetChangeEvent(UUIDPrimaryKey, TenantOwned, Base):
    """One thing that changed about one asset, between two readings.

    The environment was previously described only by its current state and two
    timestamps. "What changed since last week" was answerable by diffing
    multi-megabyte snapshot blobs in application code, which is another way of
    saying it was not answerable -- and it is the question a customer asks first
    after a week of somebody else's deployments.

    Append-only, and one row per change rather than one per scan. A scan that
    finds nothing different writes nothing, so the feed is a record of movement
    instead of a log of having looked.
    """

    __tablename__ = "asset_change_events"
    __table_args__ = (
        # How the feed is read: newest first, per tenant.
        Index("ix_asset_change_events_feed", "organization_id", "observed_at"),
        Index("ix_asset_change_events_resource", "resource_id", "observed_at"),
    )

    resource_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("cloud_resources.id", ondelete="CASCADE"),
        nullable=False,
    )
    # SET NULL rather than CASCADE: pruning an execution log must not rewrite
    # what happened to the environment, the same rule ``risk_history`` follows.
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )

    change: Mapped[AssetChange] = mapped_column(
        StrEnumType(AssetChange, 24), nullable=False
    )
    # NULL on APPEARED and DISAPPEARED, which are about the asset rather than
    # about one of its attributes.
    previous_value: Mapped[str | None] = mapped_column(String(32))
    current_value: Mapped[str | None] = mapped_column(String(32))

    # When the provider was read, not when the row was written. A replay
    # carries its capture's own time, and a feed plotted on write time would
    # put month-old evidence at today's date.
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class FindingEventRecord(UUIDPrimaryKey, TenantOwned, Base):
    """A transition in a finding's life, with what caused it.

    ``first_detected_at`` and ``resolved_at`` are two points on a line nobody
    could see the rest of: a finding raised, fixed, regressed and fixed again
    was indistinguishable from one raised and fixed once. On a product whose
    north-star metric is *verified risk reduction*, that made the metric an
    estimate over the current state rather than a measurement of what happened.

    Either a scan or a person caused each row, never both and never neither.
    That is not enforced by a constraint because a third case exists and is
    real: a finding accepted through the API by a user carries both the user and
    the scan that last detected it.
    """

    __tablename__ = "finding_events"
    __table_args__ = (
        Index("ix_finding_events_timeline", "finding_id", "observed_at"),
        Index("ix_finding_events_org", "organization_id", "observed_at"),
    )

    finding_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )
    # Not an FK: auth.users belongs to Supabase.
    user_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))

    event: Mapped[FindingEvent] = mapped_column(
        StrEnumType(FindingEvent, 24), nullable=False
    )
    previous_status: Mapped[FindingStatus | None] = mapped_column(
        StrEnumType(FindingStatus, 24)
    )
    current_status: Mapped[FindingStatus] = mapped_column(
        StrEnumType(FindingStatus, 24), nullable=False
    )
    # The sentence a timeline shows. Written for a person, like the
    # verification detail beside it.
    detail: Mapped[str | None] = mapped_column(Text)

    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
