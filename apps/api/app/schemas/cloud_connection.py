from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import (
    CloudAccountStatus,
    ConnectionScope,
    ConsentStatus,
    PermissionMode,
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
    permission_mode: PermissionMode = PermissionMode.READER


class CloudConnectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    provider: Provider
    name: str
    scope_type: ConnectionScope
    scope_id: str | None = None
    scope_path: str | None = None
    permission_mode: PermissionMode
    role_version: str
    tenant_id: str | None = None
    service_principal_object_id: str | None = None
    consent_status: ConsentStatus
    consented_at: datetime | None = None
    rbac_verified_at: datetime | None = None
    external_id_verified: bool = False
    status: CloudAccountStatus
    status_detail: str | None = None
    last_discovery_at: datetime | None = None
    created_at: datetime
    is_verified: bool = False
    subscription_count: int = 0


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


class ArtifactLinks(BaseModel):
    """Where to fetch each deployment format, and what it will grant."""

    # API-relative paths. The client prefixes its own API base rather than the
    # server guessing its public scheme and host, which it cannot do correctly
    # from behind a proxy.
    formats: dict[str, str]
    expires_in_seconds: int
    scope_path: str | None = None
    principal_id: str | None = None
    permission_mode: PermissionMode
    arm_actions: list[str] = Field(default_factory=list)
    cloud_shell_url: str
