import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import Level, Provider, RelationshipType, ResourceType
from app.models.base import Base, StrEnumType, TenantOwned, Timestamps, UUIDPrimaryKey


class ResourceRecord(UUIDPrimaryKey, TenantOwned, Timestamps, Base):
    """A normalized asset. Cloud-neutral by design -- no Azure types leak in.

    An asset belongs to exactly one of two scopes, and which one is not a
    detail. A virtual machine is in a subscription; a directory user is in a
    tenant and in no subscription at all. Modelling the second as though it
    were the first is what made one administrator into one asset per
    subscription -- and, through the finding's (organization, rule, resource)
    identity, one MFA finding per subscription for the same person.

    So ``cloud_account_id`` is set for account-scoped assets and NULL for
    directory-scoped ones, which carry ``connection_id`` instead. Exactly one
    of the two is always present; the database enforces that rather than
    trusting this comment.
    """

    __tablename__ = "cloud_resources"
    __table_args__ = (
        UniqueConstraint("cloud_account_id", "provider_resource_id"),
        Index("ix_cloud_resources_org_type", "organization_id", "resource_type"),
    )

    # NULL for a directory-scoped asset. PostgreSQL treats NULLs as distinct in
    # the unique constraint above, so those rows are keyed by the partial index
    # on (connection_id, provider_resource_id) created in migration 0008.
    cloud_account_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_accounts.id", ondelete="CASCADE")
    )
    # Set for directory-scoped assets, and the reason they survive the deletion
    # of any one subscription: the directory outlives the subscriptions under
    # it, and is gone only when the connection is.
    connection_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("cloud_connections.id", ondelete="CASCADE"),
        index=True,
    )
    provider: Mapped[Provider] = mapped_column(StrEnumType(Provider, 16), nullable=False)
    provider_resource_id: Mapped[str] = mapped_column(String(1024), nullable=False)

    resource_type: Mapped[ResourceType] = mapped_column(
        StrEnumType(ResourceType, 64), nullable=False
    )
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    region: Mapped[str | None] = mapped_column(String(64))
    environment: Mapped[str | None] = mapped_column(String(64))

    # Context that drives risk scoring. UNKNOWN is honest and scored cautiously;
    # it is never quietly downgraded to LOW (RISK_ENGINE.md section 1).
    criticality: Mapped[Level] = mapped_column(
        StrEnumType(Level, 16), nullable=False, default=Level.UNKNOWN
    )
    data_sensitivity: Mapped[Level] = mapped_column(
        StrEnumType(Level, 16), nullable=False, default=Level.UNKNOWN
    )
    public_exposure: Mapped[Level] = mapped_column(
        StrEnumType(Level, 16), nullable=False, default=Level.UNKNOWN
    )

    resource_metadata: Mapped[dict] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ResourceRelationship(UUIDPrimaryKey, TenantOwned, Base):
    """Lets a rule ask "is this NSG actually attached to anything?".

    An unattached NSG that allows RDP is noise, not a Critical finding
    (RULE_ENGINE.md section 1).
    """

    __tablename__ = "resource_relationships"
    __table_args__ = (
        UniqueConstraint(
            "source_resource_id", "target_resource_id", "relationship_type",
            name="uq_resource_relationships_edge",
        ),
    )

    source_resource_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_resources.id", ondelete="CASCADE"), nullable=False
    )
    target_resource_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_resources.id", ondelete="CASCADE"), nullable=False
    )
    relationship_type: Mapped[RelationshipType] = mapped_column(
        StrEnumType(RelationshipType, 32), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
