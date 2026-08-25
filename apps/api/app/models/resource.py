import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import Level, Provider, RelationshipType, ResourceType
from app.models.base import Base, StrEnumType, TenantOwned, Timestamps, UUIDPrimaryKey


class ResourceRecord(UUIDPrimaryKey, TenantOwned, Timestamps, Base):
    """A normalized asset. Cloud-neutral by design -- no Azure types leak in."""

    __tablename__ = "cloud_resources"
    __table_args__ = (
        UniqueConstraint("cloud_account_id", "provider_resource_id"),
        Index("ix_cloud_resources_org_type", "organization_id", "resource_type"),
    )

    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_accounts.id", ondelete="CASCADE"), nullable=False
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
