import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import CloudAccountStatus, ConsentStatus, Provider
from app.models.base import Base, StrEnumType, TenantOwned, Timestamps, UUIDPrimaryKey


class CloudAccount(UUIDPrimaryKey, TenantOwned, Timestamps, Base):
    """One subscription, discovered beneath a :class:`CloudConnection`.

    Deliberately holds NO customer secret. CloudGuard authenticates as its own
    multi-tenant Entra app against the customer's tenant, so there is nothing
    per-customer to store or leak (AZURE_INTEGRATION.md section 2).

    Rows here are now produced by discovery rather than typed in: the connection
    holds the grant, and every subscription that grant can see becomes one of
    these. Everything downstream -- scans, resources, findings, risk -- still
    hangs off a cloud account, so the whole pipeline below this line is
    unchanged by that.
    """

    __tablename__ = "cloud_accounts"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider", "tenant_id", "subscription_id"),
    )

    # Nullable only so the migration can adopt pre-existing rows; every account
    # created from here on belongs to a connection.
    connection_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_connections.id", ondelete="CASCADE"), index=True
    )

    # Azure's own display name for the subscription, so the confirmation screen
    # shows the customer names they recognise instead of GUIDs.
    display_name: Mapped[str | None] = mapped_column(String(200))
    discovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # A discovered subscription the customer chose not to scan. Kept rather than
    # deleted: it must not silently reappear on the next discovery run.
    in_scope: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # When that choice was last made. A boolean can say a subscription is
    # excluded; only this can say whether somebody decided that last week or
    # last year, which is what makes "excluded by you" readable as a decision
    # rather than as a defect.
    scope_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    provider: Mapped[Provider] = mapped_column(
        StrEnumType(Provider, 16), nullable=False, default=Provider.AZURE
    )
    account_name: Mapped[str] = mapped_column(String(200), nullable=False)

    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    subscription_id: Mapped[str | None] = mapped_column(String(64))

    consent_status: Mapped[ConsentStatus] = mapped_column(
        StrEnumType(ConsentStatus, 16), nullable=False, default=ConsentStatus.PENDING
    )
    consented_scopes: Mapped[dict | None] = mapped_column(JSONB)
    consented_by_user_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))
    consented_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Proof the RBAC Reader assignment actually works -- set by a live test call,
    # not by the customer telling us they did it.
    rbac_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    status: Mapped[CloudAccountStatus] = mapped_column(
        StrEnumType(CloudAccountStatus, 16), nullable=False, default=CloudAccountStatus.PENDING
    )
    status_detail: Mapped[str | None] = mapped_column(Text)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    @property
    def is_scannable(self) -> bool:
        """Unchanged in shape, but the inputs now come down from the connection.

        ``consent_status`` and ``rbac_verified_at`` are copied onto each child
        by discovery rather than read through the relationship. Denormalized on
        purpose: it keeps this a plain property with no lazy load, which is what
        lets the scan pipeline stay exactly as it was.
        """
        return (
            self.in_scope
            and self.consent_status == ConsentStatus.GRANTED
            and self.rbac_verified_at is not None
            and self.subscription_id is not None
        )
