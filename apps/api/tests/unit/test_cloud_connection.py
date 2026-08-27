"""Connection state, without a database.

Both properties here decide something consequential -- whether an environment
may be scanned, and what scope a grant is written at -- so they are worth
pinning independently of the service that uses them.
"""

from datetime import UTC, datetime

from app.core.enums import ConnectionScope, ConsentStatus
from app.models.cloud_connection import CloudConnection


def connection(**kwargs: object) -> CloudConnection:
    defaults: dict = {
        "name": "Production",
        "scope_type": ConnectionScope.TENANT_ROOT,
        "external_id": "deadbeef",
        "consent_status": ConsentStatus.PENDING,
    }
    return CloudConnection(**{**defaults, **kwargs})


# --- is_verified -----------------------------------------------------------


def test_a_new_connection_is_not_verified() -> None:
    assert connection().is_verified is False


def test_consent_alone_does_not_verify() -> None:
    """Graph consent and the RBAC grant are independent, and customers very
    often complete the first and forget the second."""
    c = connection(
        consent_status=ConsentStatus.GRANTED,
        tenant_id="11111111-1111-1111-1111-111111111111",
    )
    assert c.is_verified is False


def test_rbac_without_consent_does_not_verify() -> None:
    """The tenant-binding guard, at the model level: RBAC proof cannot stand in
    for consent, because the tenant id is only trustworthy when it came from the
    consent callback."""
    c = connection(rbac_verified_at=datetime.now(UTC))
    assert c.is_verified is False


def test_both_grants_verify() -> None:
    c = connection(
        consent_status=ConsentStatus.GRANTED,
        tenant_id="11111111-1111-1111-1111-111111111111",
        rbac_verified_at=datetime.now(UTC),
    )
    assert c.is_verified is True


# --- scope_path ------------------------------------------------------------


def test_tenant_root_scope_is_unknown_before_consent() -> None:
    """A tenant's root management group is named with the tenant id, which
    nobody types -- so there is genuinely no scope to grant at yet."""
    assert connection().scope_path is None


def test_tenant_root_scope_resolves_once_consent_reports_the_tenant() -> None:
    c = connection(tenant_id="contoso-tenant")
    assert c.scope_path == (
        "/providers/Microsoft.Management/managementGroups/contoso-tenant"
    )


def test_management_group_scope_uses_the_named_group() -> None:
    c = connection(
        scope_type=ConnectionScope.MANAGEMENT_GROUP,
        scope_id="platform-mg",
        tenant_id="contoso-tenant",
    )
    assert c.scope_path == "/providers/Microsoft.Management/managementGroups/platform-mg"


def test_subscription_scope_is_the_narrowest_grant() -> None:
    c = connection(scope_type=ConnectionScope.SUBSCRIPTION, scope_id="sub-1")
    assert c.scope_path == "/subscriptions/sub-1"


def test_subscription_scope_without_an_id_has_no_path() -> None:
    c = connection(scope_type=ConnectionScope.SUBSCRIPTION)
    assert c.scope_path is None
