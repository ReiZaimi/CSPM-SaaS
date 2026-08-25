import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import CloudAccountStatus, ConsentStatus, Provider
from app.models.base import Base, StrEnumType, TenantOwned, Timestamps, UUIDPrimaryKey


class CloudAccount(UUIDPrimaryKey, TenantOwned, Timestamps, Base):
    """A customer cloud environment CloudGuard has been granted read access to.

    Deliberately holds NO customer secret. CloudGuard authenticates as its own
    multi-tenant Entra app against the customer's tenant, so there is nothing
    per-customer to store or leak (AZURE_INTEGRATION.md section 2).
    """

    __tablename__ = "cloud_accounts"
    __table_args__ = (
        UniqueConstraint("organization_id", "provider", "tenant_id", "subscription_id"),
    )

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
        return (
            self.consent_status == ConsentStatus.GRANTED
            and self.rbac_verified_at is not None
            and self.subscription_id is not None
        )
