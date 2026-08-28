from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import (
    CloudAccountStatus,
    ConnectionScope,
    ConsentStatus,
    Provider,
)


class CloudConnectionCreate(BaseModel):
    """Starting a connection needs a name and a decision about scope.

    Note what is absent: no tenant id, no subscription id, no client id, no
    secret. The tenant comes from Entra's consent callback, subscriptions come
    from discovery, and CloudGuard never holds a customer credential at all
    (AZURE_INTEGRATION.md 2).
    """

    name: str = Field(min_length=1, max_length=200)
    provider: Provider = Provider.AZURE
    scope_type: ConnectionScope = ConnectionScope.TENANT_ROOT
    # Required for MANAGEMENT_GROUP and SUBSCRIPTION; meaningless for
    # TENANT_ROOT, whose scope is not knowable until consent completes.
    scope_id: str | None = Field(default=None, max_length=200)


class CloudConnectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    provider: Provider
    name: str
    scope_type: ConnectionScope
    scope_id: str | None = None
    scope_path: str | None = None
    role_version: str
    tenant_id: str | None = None
    service_principal_object_id: str | None = None
    consent_status: ConsentStatus
    consented_at: datetime | None = None
    rbac_verified_at: datetime | None = None
    status: CloudAccountStatus
    status_detail: str | None = None
    last_discovery_at: datetime | None = None
    created_at: datetime
    is_verified: bool = False
    subscription_count: int = 0
    subscriptions: list["DiscoveredSubscription"] = Field(default_factory=list)
    consent_url: str | None = None
    template_url: str | None = None
    # True once the deployment has been outstanding long enough that "still in
    # progress" no longer explains it.
    deploy_stalled: bool = False


class DiscoveredSubscription(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    subscription_id: str | None = None
    display_name: str | None = None
    in_scope: bool
    status: CloudAccountStatus
    discovered_at: datetime | None = None
    last_scan_at: datetime | None = None
    is_scannable: bool = False


class ScopeSelection(BaseModel):
    """Which discovered subscriptions to actually scan, keyed by subscription id."""

    in_scope: dict[str, bool]
