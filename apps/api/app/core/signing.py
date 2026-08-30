"""Signed state that travels through somebody else's system and comes back.

Three places hand a customer -- or Microsoft -- a URL that returns to this API
carrying a claim about which connection it is for: the consent round trip, the
ARM template the Azure Portal fetches, and the Event Grid webhook. None of them
can be authenticated by a session, because the caller is a browser mid-redirect,
a portal fetching server-side, or Microsoft's own infrastructure.

So the claim is signed, and the signature is the whole guard. Without it a
returning callback could name any connection and bind a stranger's tenant to it.

Provider-neutral, and that is why it lives here rather than beside the Azure
connector where it was written. Nothing in it knows what a tenant is: it signs a
dictionary and hands back a string. An AWS onboarding flow that needs the same
round trip would otherwise have imported ``connectors.azure.auth`` to get it,
which is the seam leaking through a utility.

``purpose`` is not enforced here on purpose. Every caller checks its own, and it
must: the tokens are signed with one secret, so a template token and a webhook
token differ *only* by that field, and a caller that verified the signature and
skipped the purpose would accept the other one.
"""

import base64
import hashlib
import hmac
import json
import time
from typing import Any

from app.core.config import settings


class SignedStateError(ValueError):
    """The state did not verify, was malformed, or has expired."""


def sign_state(payload: dict[str, Any]) -> str:
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    mac = hmac.new(
        settings.azure_consent_state_secret.encode(), body.encode(), hashlib.sha256
    ).hexdigest()[:32]
    return f"{body}.{mac}"


def verify_state(state: str, max_age_seconds: int = 1800) -> dict[str, Any]:
    try:
        body, mac = state.rsplit(".", 1)
    except ValueError as exc:
        raise SignedStateError("Malformed state token") from exc

    expected = hmac.new(
        settings.azure_consent_state_secret.encode(), body.encode(), hashlib.sha256
    ).hexdigest()[:32]
    # Constant time: a token is a credential, and a comparison that returns
    # early tells an attacker how much of one they have guessed.
    if not hmac.compare_digest(mac, expected):
        raise SignedStateError("State signature does not verify")

    padding = "=" * (-len(body) % 4)
    payload: dict[str, Any] = json.loads(base64.urlsafe_b64decode(body + padding))

    if time.time() - payload.get("issued_at", 0) > max_age_seconds:
        raise SignedStateError("Consent link has expired — please start again")
    return payload
