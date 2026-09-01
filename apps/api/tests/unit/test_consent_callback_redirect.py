"""Where the consent callback puts the customer back.

Entra hands the browser back to this API, and the API's only job is to decide
which page the customer lands on. That decision used to be "the connections
list", which is a list of cards during the one moment the customer is mid-setup
and knows exactly which connection they were working on.

The state parameter comes back on a denial as well as on a grant, so a failed
consent knows which connection it failed for -- and can land on that
connection's own step, next to the button that starts consent again. Only a
state that cannot be verified at all has nothing to return to.
"""

import time
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import pytest

from app.api.routes import cloud_connections as routes
from app.core import signing
from app.core.config import Settings
from app.core.signing import sign_state


@pytest.fixture
def configured(monkeypatch: pytest.MonkeyPatch) -> Settings:
    settings = Settings(
        app_url="https://app.example.com",
        azure_consent_state_secret="k" * 32,
    )
    monkeypatch.setattr(routes, "settings", settings)
    monkeypatch.setattr(signing, "settings", settings)
    return settings


def state_for(connection_id: str) -> str:
    return sign_state(
        {"cloud_connection_id": connection_id, "issued_at": int(time.time())}
    )


async def test_a_denied_consent_lands_on_the_step_that_was_denied(
    configured: Settings,
) -> None:
    connection_id = str(uuid4())

    # Every parameter passed by name: called directly rather than through a
    # request, the ones left out would arrive as FastAPI ``Query`` objects.
    response = await routes.consent_callback(
        state=state_for(connection_id),
        tenant="",
        admin_consent="False",
        error="",
        error_description="",
    )

    url = urlparse(response.headers["location"])
    assert url.path == f"/connections/{connection_id}/setup"
    assert parse_qs(url.query)["consent_error"] == ["Admin consent was not granted"]


async def test_azures_own_reason_survives_the_redirect(configured: Settings) -> None:
    # Encoded rather than interpolated raw: these descriptions carry spaces,
    # colons and the occasional ampersand, and an ampersand would otherwise
    # split the message into a second query parameter and truncate it.
    connection_id = str(uuid4())

    response = await routes.consent_callback(
        state=state_for(connection_id),
        tenant="",
        admin_consent="",
        error="access_denied",
        error_description="AADSTS650056: Misconfigured application & no consent",
    )

    url = urlparse(response.headers["location"])
    assert url.path == f"/connections/{connection_id}/setup"
    assert parse_qs(url.query)["consent_error"] == [
        "AADSTS650056: Misconfigured application & no consent"
    ]


async def test_an_unverifiable_state_falls_back_to_the_list(
    configured: Settings,
) -> None:
    # Nothing names a connection here, so there is no step to return to. The
    # list is the only honest destination.
    response = await routes.consent_callback(
        state="tampered.deadbeef",
        tenant="",
        admin_consent="",
        error="",
        error_description="",
    )

    url = urlparse(response.headers["location"])
    assert url.path == "/connections"
    assert "consent_error" in parse_qs(url.query)
