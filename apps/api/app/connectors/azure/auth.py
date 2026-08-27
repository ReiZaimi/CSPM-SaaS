"""Entra ID authentication for customer tenants.

The model, stated once because it drives everything else in this package:
CloudGuard is a **multi-tenant Entra application**. When a customer's admin
grants consent, a service principal for CloudGuard's app is created *in their
tenant*. CloudGuard then authenticates as itself against that tenant, using its
own client secret, and receives a token scoped to that customer.

There is therefore no per-customer credential anywhere in this system — nothing
to store, rotate, leak, or paste into a form (AZURE_INTEGRATION.md section 2).

Two grants are required and they are genuinely separate:

1. **Graph admin consent** — directory data (users, roles, MFA methods).
2. **Azure RBAC Reader** — subscription data (ARM resources). Consent does not
   grant this; someone has to assign the role.
"""

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from urllib.parse import urlencode

import msal

from app.core.config import settings
from app.core.errors import CloudConnectionError, NotConfigured
from app.core.logging import get_logger

log = get_logger(__name__)

ARM_SCOPE = "https://management.azure.com/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

# Application permissions requested at consent time. Every one is read-only --
# CloudGuard never asks for a write permission (SECURITY.md section 3).
REQUIRED_GRAPH_PERMISSIONS = [
    "Directory.Read.All",
    "User.Read.All",
    "RoleManagement.Read.Directory",
    "UserAuthenticationMethod.Read.All",
    "Policy.Read.All",
]


@dataclass(frozen=True)
class AccessToken:
    token: str
    expires_at: float

    @property
    def is_valid(self) -> bool:
        return time.time() < self.expires_at - 60


class ConsentStateError(ValueError):
    """The state token returned from Entra did not verify."""


def build_consent_url(state: str, tenant_hint: str = "organizations") -> str:
    """The single link a customer's Global Administrator clicks.

    ``/adminconsent`` grants the app's application permissions tenant-wide, so
    individual users never see a consent prompt.

    ``scope`` is required on the **v2.0** admin-consent endpoint -- omitting it
    is rejected with ``AADSTS900144`` before the admin sees anything to approve.
    (The older v1 endpoint takes no scope, which is the source of most examples
    that leave it out.)

    The value is Graph's ``/.default``, which means "every application
    permission already configured on this app registration" rather than a list
    repeated here. That is deliberate: ``REQUIRED_GRAPH_PERMISSIONS`` documents
    what the registration should hold, but the registration is the authority,
    and a list duplicated in the URL could quietly disagree with it.

    Only Graph is consented. ARM needs no consent at all -- subscription access
    comes from the RBAC role assignment, which is the separate second grant.
    """
    # Checked here rather than left to Entra. A malformed redirect URI comes
    # back as AADSTS90013 on Microsoft's domain, after the administrator has
    # already been sent away, naming neither the parameter nor the deployment.
    problem = settings.azure_consent_problem
    if problem:
        raise NotConfigured(problem)
    params = {
        "client_id": settings.azure_client_id,
        "scope": GRAPH_SCOPE,
        "redirect_uri": settings.azure_redirect_uri,
        "state": state,
    }
    return (
        f"https://login.microsoftonline.com/{tenant_hint}/v2.0/adminconsent?"
        + urlencode(params)
    )


def sign_state(payload: dict) -> str:
    """Sign the consent round-trip state.

    The customer's browser carries this to Entra and back, so it must be
    tamper-evident: without a signature, a returning callback could claim any
    cloud_account_id and bind a stranger's tenant to it.
    """
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    mac = hmac.new(
        settings.azure_consent_state_secret.encode(), body.encode(), hashlib.sha256
    ).hexdigest()[:32]
    return f"{body}.{mac}"


def verify_state(state: str, max_age_seconds: int = 1800) -> dict:
    try:
        body, mac = state.rsplit(".", 1)
    except ValueError as exc:
        raise ConsentStateError("Malformed state token") from exc

    expected = hmac.new(
        settings.azure_consent_state_secret.encode(), body.encode(), hashlib.sha256
    ).hexdigest()[:32]
    if not hmac.compare_digest(mac, expected):
        raise ConsentStateError("State signature does not verify")

    padding = "=" * (-len(body) % 4)
    payload = json.loads(base64.urlsafe_b64decode(body + padding))

    if time.time() - payload.get("issued_at", 0) > max_age_seconds:
        raise ConsentStateError("Consent link has expired — please start again")
    return payload


class TokenProvider:
    """Acquires tokens for one customer tenant, caching them in memory.

    MSAL's client-credentials flow with ``authority`` pointed at the customer's
    tenant is exactly the multi-tenant app pattern: same app registration, same
    secret, different tenant, different service principal.
    """

    def __init__(self, tenant_id: str) -> None:
        if not settings.azure_configured:
            raise NotConfigured(
                "CloudGuard's Azure application identity is not configured on this server"
            )
        self.tenant_id = tenant_id
        self._cache: dict[str, AccessToken] = {}
        self._app = msal.ConfidentialClientApplication(
            client_id=settings.azure_client_id,
            client_credential=settings.azure_client_secret,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
        )

    def get_token(self, scope: str) -> str:
        cached = self._cache.get(scope)
        if cached and cached.is_valid:
            return cached.token

        result = self._app.acquire_token_for_client(scopes=[scope])
        if "access_token" not in result:
            error = result.get("error_description") or result.get("error") or "unknown error"
            log.warning(
                "azure.token_failed", tenant_id=self.tenant_id, scope=scope, error=error
            )
            raise CloudConnectionError(
                f"Could not obtain an Azure token for this tenant: {error}"
            )

        token = AccessToken(
            token=result["access_token"],
            expires_at=time.time() + int(result.get("expires_in", 3600)),
        )
        self._cache[scope] = token
        return token.token

    def arm_token(self) -> str:
        return self.get_token(ARM_SCOPE)

    def graph_token(self) -> str:
        return self.get_token(GRAPH_SCOPE)
