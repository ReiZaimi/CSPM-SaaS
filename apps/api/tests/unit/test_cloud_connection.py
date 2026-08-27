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
from app.services.cloud_connections import render_template


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


# --- template preconditions ------------------------------------------------
#
# The ARM template needs the service principal's object id, which consent
# resolves on a best-effort basis. Entra does not always publish the principal
# by the time the callback fires — so a customer can reach a state where
# consent succeeded but the template cannot render yet.


def granted(**kwargs: object) -> CloudConnection:
    return connection(
        consent_status=ConsentStatus.GRANTED,
        tenant_id="72f988bf-86f1-41af-91ab-2d7cd011db47",
        **kwargs,
    )


def test_template_refuses_before_consent() -> None:
    with pytest.raises(ValidationFailed, match="consent"):
        render_template(connection())


def test_template_refuses_while_the_principal_is_unpublished() -> None:
    """Distinct from the no-consent case: consent *has* completed here.

    Telling this customer that consent is incomplete would send them back to a
    step they already finished. The directory simply has not caught up.
    """
    with pytest.raises(ValidationFailed, match="consent"):
        render_template(granted())


def test_template_renders_once_the_principal_is_known() -> None:
    body = render_template(
        granted(
            service_principal_object_id="9a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9",
        ),
    )
    assert "9a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9" in body


# --- the template URL points at the API, not the frontend ------------------


def test_template_url_prefers_the_api_url() -> None:
    from app.core.config import settings
    from app.services.cloud_connections import public_api_base

    original = (settings.api_url, settings.azure_redirect_uri)
    try:
        settings.api_url = "https://api.example.com/"
        settings.azure_redirect_uri = "https://other.example.com/callback"
        assert public_api_base() == "https://api.example.com"
    finally:
        settings.api_url, settings.azure_redirect_uri = original


def test_template_url_falls_back_to_the_consent_callback_origin() -> None:
    """API_URL is not a required variable, so it is often unset.

    The redirect URI is the dependable stand-in: Entra compares it character
    for character, so a deployment that has completed consent is proof that
    this value names the API's real public origin.
    """
    from app.core.config import settings
    from app.services.cloud_connections import public_api_base

    original = (settings.api_url, settings.azure_redirect_uri)
    try:
        settings.api_url = ""
        settings.azure_redirect_uri = (
            "https://api.up.railway.app/api/v1/cloud-connections/azure/consent/callback"
        )
        assert public_api_base() == "https://api.up.railway.app"
    finally:
        settings.api_url, settings.azure_redirect_uri = original


def test_no_template_url_rather_than_a_guessed_one() -> None:
    """A hidden button is recoverable; a link to the wrong host is not."""
    from app.core.config import settings
    from app.services.cloud_connections import template_url

    original = (settings.api_url, settings.azure_redirect_uri)
    try:
        settings.api_url = ""
        settings.azure_redirect_uri = ""
        ready = granted(service_principal_object_id="9a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9")
        assert template_url(ready) is None
    finally:
        settings.api_url, settings.azure_redirect_uri = original
