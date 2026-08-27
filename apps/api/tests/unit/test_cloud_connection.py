"""Connection state, without a database.

Both properties here decide something consequential -- whether an environment
may be scanned, and what scope a grant is written at -- so they are worth
pinning independently of the service that uses them.
"""

from datetime import UTC, datetime

import pytest

from app.core.enums import ConnectionScope, ConsentStatus
from app.core.errors import ValidationFailed
from app.models.cloud_connection import CloudConnection
from app.services.cloud_connections import render_artifact


def connection(**kwargs: object) -> CloudConnection:
    defaults: dict = {
        "name": "Production",
        "scope_type": ConnectionScope.TENANT_ROOT,
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


# --- artifact preconditions ------------------------------------------------
#
# The artifact step sits between consent and validation, and it is the only
# step that needs the service principal's object id. Consent resolves that id
# on a best-effort basis, because Entra does not always publish the principal
# by the time the callback fires. So the failure below is a real state a real
# customer reaches, and what it *says* is the whole remedy: retry.


def granted(**kwargs: object) -> CloudConnection:
    return connection(
        consent_status=ConsentStatus.GRANTED,
        tenant_id="72f988bf-86f1-41af-91ab-2d7cd011db47",
        **kwargs,
    )


def test_artifact_refuses_before_a_scope_exists() -> None:
    with pytest.raises(ValidationFailed, match="admin consent"):
        render_artifact(connection(), "cli")


def test_artifact_refuses_while_the_principal_is_unpublished() -> None:
    """Distinct from the scope case: consent *has* completed here.

    Telling this customer that consent is incomplete would send them back to a
    step they already finished. The directory simply has not caught up.
    """
    with pytest.raises(ValidationFailed, match="try again shortly"):
        render_artifact(granted(), "cli")


def test_artifact_renders_once_the_principal_is_known() -> None:
    body = render_artifact(
        granted(service_principal_object_id="9a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"),
        "cli",
    )[2]
    assert "9a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9" in body


def test_unknown_format_is_refused_by_name() -> None:
    with pytest.raises(ValidationFailed, match="Unknown format"):
        render_artifact(granted(service_principal_object_id="abc"), "powershell")
