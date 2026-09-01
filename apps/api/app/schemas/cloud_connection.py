from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import (
    CloudAccountStatus,
    ConnectionScope,
    ConsentStatus,
    Provider,
)
from app.models.cloud_connection import CloudConnection


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
    # How often this environment is re-read. NULL means manual only.
    scan_interval_hours: int | None = None
    created_at: datetime
    is_verified: bool = False
    subscription_count: int = 0
    subscriptions: list["DiscoveredSubscription"] = Field(default_factory=list)
    consent_url: str | None = None
    template_url: str | None = None
    # True once the deployment has been outstanding long enough that "still in
    # progress" no longer explains it.
    deploy_stalled: bool = False
    # True when CloudGuard's scanner role has moved on since this connection
    # deployed it. Checks needing the newer permissions cannot be evaluated
    # until the customer redeploys, so this drives a prompt rather than leaving
    # them to wonder why a rule reports UNKNOWN.
    role_upgrade_available: bool = False
    # Verified *and* holding at least one subscription that can be scanned.
    # ``is_verified`` alone says both grants work, which is true of a connection
    # with nothing beneath it.
    is_ready_to_scan: bool = False


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


class ScheduleUpdate(BaseModel):
    """How often this environment should be re-read.

    ``None`` turns scheduling off and leaves the connection scannable by hand,
    which is where every connection starts: turning a customer's cloud into a
    recurring API cost without being asked would be a surprise on their bill.
    """

    scan_interval_hours: int | None = Field(
        default=None,
        ge=CloudConnection.MIN_INTERVAL_HOURS,
        le=CloudConnection.MAX_INTERVAL_HOURS,
        description=(
            "Read this environment at least this often. Omit or send null for "
            "manual scanning only."
        ),
    )


class ScopeSelection(BaseModel):
    """Which discovered subscriptions to actually scan, keyed by subscription id."""

    in_scope: dict[str, bool]


class ChangeEventsUpdate(BaseModel):
    """Turn change-triggered scanning on or off.

    A bare boolean, because there is nothing else for the customer to choose:
    the quiet period and the minimum interval between change-triggered scans are
    CloudGuard's judgement about not turning a deployment into a scan storm, not
    a preference.
    """

    enabled: bool
