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


# --- the lookup explains itself --------------------------------------------
#
# Every failure here used to return None and log a warning nobody reads, so
# the connection card showed one spinner for four unrelated situations. These
# pin the reasons apart, because they need different people to do different
# things.


async def resolve_with(monkeypatch, raises: Exception | None = None, found=None):
    from app.connectors.azure import client as client_module
    from app.services import cloud_connections as service

    class FakeGraph:
        def __init__(self, *a, **kw) -> None: ...
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a) -> None: ...
        async def find_service_principal(self, app_id: str):
            if raises:
                raise raises
            return found

    monkeypatch.setattr(service, "GraphClient", FakeGraph)
    monkeypatch.setattr(
        "app.connectors.azure.auth.TokenProvider", lambda tenant_id: object()
    )
    assert client_module  # imported for the AzureApiError type used by callers
    return await service._resolve_service_principal(granted())


async def test_a_refused_lookup_names_the_app_registration(monkeypatch) -> None:
    """403 is not the customer's problem, and must not read like one."""
    from app.connectors.azure.client import AzureApiError

    problem = await resolve_with(monkeypatch, raises=AzureApiError("denied", 403))
    assert problem is not None
    assert "app registration" in problem
    assert "CloudGuard's side" in problem


async def test_an_unpublished_principal_says_to_wait(monkeypatch) -> None:
    """Consent succeeded; Entra simply has not replicated yet. Different fix."""
    problem = await resolve_with(monkeypatch, found=None)
    assert problem is not None
    assert "not visible in this directory yet" in problem


async def test_a_successful_lookup_reports_no_problem(monkeypatch) -> None:
    problem = await resolve_with(monkeypatch, found={"id": "spn-object-id"})
    assert problem is None


# --- the consent link must survive a page reload ---------------------------


def test_consent_url_is_regenerated_not_stored(monkeypatch) -> None:
    """The link was previously returned only from the create response.

    A reload lost the button, leaving the connection in PENDING with no route
    forward but deletion. The signed state also expires in 30 minutes, so a
    stored one would usually be dead by the time an administrator looked.
    """
    from app.connectors.azure import auth
    from app.core.config import Settings
    from app.services.cloud_connections import consent_url_for

    monkeypatch.setattr(
        auth,
        "settings",
        Settings(
            azure_client_id="8f39c34c-e523-4914-89ca-d6de1a8691ab",
            azure_client_secret="aBc7Q~exampleSecretValue.With-Punctuation_123",
            azure_redirect_uri=(
                "https://api.example.com/api/v1/cloud-connections/azure/consent/callback"
            ),
            azure_consent_state_secret="a-real-random-32-character-string-here",
        ),
    )
    url, problem = consent_url_for(connection())
    assert problem is None
    assert url is not None and url.startswith("https://login.microsoftonline.com/")


def test_a_misconfigured_deployment_returns_the_reason(monkeypatch) -> None:
    """Not None-and-silence: without the reason the card renders empty."""
    from app.connectors.azure import auth
    from app.core.config import Settings
    from app.services.cloud_connections import consent_url_for

    monkeypatch.setattr(
        auth,
        "settings",
        Settings(
            azure_client_id="8f39c34c-e523-4914-89ca-d6de1a8691ab",
            # The Secret ID rather than the value.
            azure_client_secret="1b2c3d4e-5f60-7182-93a4-b5c6d7e8f901",
            azure_redirect_uri=(
                "https://api.example.com/api/v1/cloud-connections/azure/consent/callback"
            ),
            azure_consent_state_secret="a-real-random-32-character-string-here",
        ),
    )
    url, problem = consent_url_for(connection())
    assert url is None
    assert problem is not None and "Secret ID" in problem


# --- waiting has a limit ---------------------------------------------------


def stalled_case(**kwargs: object) -> CloudConnection:
    from datetime import timedelta

    from app.services.cloud_connections import DEPLOY_PATIENCE_SECONDS

    defaults: dict = {
        "consent_status": ConsentStatus.GRANTED,
        "tenant_id": "72f988bf-86f1-41af-91ab-2d7cd011db47",
        "consented_at": datetime.now(UTC)
        - timedelta(seconds=DEPLOY_PATIENCE_SECONDS + 60),
    }
    return connection(**{**defaults, **kwargs})


def test_a_fresh_consent_is_not_stalled() -> None:
    """Deploying needs a second person; a slow start is normal, not a fault."""
    from app.services.cloud_connections import deploy_stalled

    fresh = connection(
        consent_status=ConsentStatus.GRANTED,
        tenant_id="72f988bf-86f1-41af-91ab-2d7cd011db47",
        consented_at=datetime.now(UTC),
    )
    assert deploy_stalled(fresh) is False


def test_a_long_unverified_wait_is_stalled() -> None:
    from app.services.cloud_connections import deploy_stalled

    assert deploy_stalled(stalled_case()) is True


def test_a_verified_connection_is_never_stalled() -> None:
    from app.services.cloud_connections import deploy_stalled

    assert deploy_stalled(stalled_case(rbac_verified_at=datetime.now(UTC))) is False


def test_an_unconsented_connection_is_never_stalled() -> None:
    """Nothing is outstanding yet — the customer has not been asked to deploy."""
    from app.services.cloud_connections import deploy_stalled

    assert deploy_stalled(stalled_case(consent_status=ConsentStatus.PENDING)) is False
