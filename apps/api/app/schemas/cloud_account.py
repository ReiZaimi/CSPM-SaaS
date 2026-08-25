from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import CloudAccountStatus, ConsentStatus, Provider


class CloudAccountCreate(BaseModel):
    """Starting a connection needs only what identifies the tenant.

    Note what is absent: no client id, no client secret, no certificate. The
    customer never hands CloudGuard a credential (AZURE_INTEGRATION.md 2).
    """

    account_name: str = Field(min_length=1, max_length=200)
    provider: Provider = Provider.AZURE
    tenant_id: str = Field(min_length=1, max_length=64)
    subscription_id: str | None = Field(default=None, max_length=64)


class CloudAccountOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    provider: Provider
    account_name: str
    tenant_id: str
    subscription_id: str | None = None
    consent_status: ConsentStatus
    rbac_verified_at: datetime | None = None
    status: CloudAccountStatus
    status_detail: str | None = None
    last_scan_at: datetime | None = None
    created_at: datetime
    is_scannable: bool = False


class ConsentLink(BaseModel):
    consent_url: str
    expires_in_seconds: int
    permissions: dict


class ValidationResult(BaseModel):
    ok: bool
    detail: str
    permissions_verified: list[str] = Field(default_factory=list)
    problems: list[str] = Field(default_factory=list)
    subscription_id: str | None = None
