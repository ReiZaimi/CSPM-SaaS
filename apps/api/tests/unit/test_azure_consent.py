"""The admin-consent URL.

This URL has now been wrong three times, each failure landing on Microsoft's
error page rather than in CloudGuard: a callback path that moved when
connections replaced per-subscription accounts, a redirect URI pasted from the
deployment guide with its placeholder intact, and a missing ``scope`` that the
v2.0 endpoint requires (``AADSTS900144``).

They share a shape. The URL is assembled from configuration, handed to a
browser, and only judged by a server CloudGuard does not own -- so nothing in
this codebase noticed, and the person who found out was a customer's Global
Administrator standing in front of an AADSTS code. Asserting on the assembled
URL is the only place that shape can be caught cheaply.
"""

import time
from urllib.parse import parse_qs, urlparse

import pytest

from app.connectors.azure import auth
from app.connectors.azure.auth import GRAPH_SCOPE, build_consent_url, verify_state
from app.core.config import CONSENT_CALLBACK_PATH, Settings
from app.core.errors import NotConfigured

REDIRECT_URI = f"https://api.example.com{CONSENT_CALLBACK_PATH}"


@pytest.fixture
def configured(monkeypatch: pytest.MonkeyPatch) -> Settings:
    """A deployment whose Entra registration is complete and correct."""
    settings = Settings(
        azure_client_id="8f39c34c-e523-4914-89ca-d6de1a8691ab",
        azure_client_secret="a-secret",
        azure_redirect_uri=REDIRECT_URI,
        azure_consent_state_secret="k" * 32,
    )
    monkeypatch.setattr(auth, "settings", settings)
    return settings


def query(url: str) -> dict[str, str]:
    return {key: values[0] for key, values in parse_qs(urlparse(url).query).items()}


def test_scope_is_present(configured: Settings) -> None:
    """AADSTS900144. The v2.0 endpoint rejects the request without it, before
    the administrator is shown anything to approve."""
    assert query(build_consent_url("state"))["scope"] == GRAPH_SCOPE


def test_scope_is_graph_default_rather_than_a_repeated_list(
    configured: Settings,
) -> None:
    """`.default` means "the permissions this app registration already holds".
    Listing them here instead would let the URL and the registration disagree,
    and the registration is the authority."""
    assert query(build_consent_url("state"))["scope"].endswith("/.default")
    assert "Directory.Read.All" not in build_consent_url("state")


def test_arm_is_not_consented(configured: Settings) -> None:
    """Subscription access comes from the RBAC role assignment. Asking for it
    here would request a grant that consent cannot give."""
    assert "management.azure.com" not in build_consent_url("state")


def test_every_parameter_entra_requires_is_present(configured: Settings) -> None:
    params = query(build_consent_url("signed.state"))
    assert set(params) >= {"client_id", "scope", "redirect_uri", "state"}
    assert params["redirect_uri"] == REDIRECT_URI
    assert params["state"] == "signed.state"


def test_the_tenant_is_not_named(configured: Settings) -> None:
    """`organizations` rather than a tenant id: the administrator signs in and
    Entra reports which directory that was. Naming one would mean having asked
    the customer for it, which is the thing this flow avoids."""
    assert urlparse(build_consent_url("state")).path.startswith("/organizations/")


def test_it_targets_the_v2_admin_consent_endpoint(configured: Settings) -> None:
    url = urlparse(build_consent_url("state"))
    assert url.netloc == "login.microsoftonline.com"
    assert url.path.endswith("/v2.0/adminconsent")


def test_a_misconfigured_deployment_refuses_to_build_a_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Better a CloudGuard error than an AADSTS code on Microsoft's domain."""
    monkeypatch.setattr(
        auth,
        "settings",
        Settings(
            azure_client_id="app-id",
            azure_client_secret="secret",
            azure_redirect_uri=f"https://<placeholder>{CONSENT_CALLBACK_PATH}",
        ),
    )
    with pytest.raises(NotConfigured, match="placeholder"):
        build_consent_url("state")


def test_the_state_survives_the_round_trip(configured: Settings) -> None:
    """The state is what binds a returning callback to one connection, so it
    has to come back out of the URL exactly as it went in."""
    state = auth.sign_state({"cloud_connection_id": "abc", "issued_at": time.time()})
    returned = query(build_consent_url(state))["state"]
    assert verify_state(returned, max_age_seconds=3600)["cloud_connection_id"] == "abc"
