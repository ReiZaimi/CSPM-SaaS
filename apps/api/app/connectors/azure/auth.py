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

import jwt
import msal

from app.core.config import settings
from app.core.errors import CloudConnectionError, NotConfigured
from app.core.logging import get_logger

log = get_logger(__name__)

ARM_SCOPE = "https://management.azure.com/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

# Application permissions requested at consent time. Every one is read-only --
# CloudGuard never asks for a write permission (SECURITY.md section 3).
# These must be declared on the app registration in Azure Portal before any
# customer can consent (AZURE_CONNECTOR_REDESIGN.md section 9).
REQUIRED_GRAPH_PERMISSIONS = [
    "Directory.Read.All",
    "User.Read.All",
    "RoleManagement.Read.Directory",
    "UserAuthenticationMethod.Read.All",
    "Policy.Read.All",
    "Application.Read.All",
    "Group.Read.All",
    "IdentityRiskyUser.Read.All",
    "AuditLog.Read.All",
]

# Microsoft Graph's own application id, and the app role id behind each
# permission above. Entra's manifest and ``az ad app`` both address permissions
# by id, never by name, so a reproducible registration needs these.
#
# Every id below was read from Microsoft's published reference rather than
# recalled, for the reason ``rbac.py`` records about ARM actions: a wrong
# identifier here is indistinguishable from a right one by inspection, and
# fails only in front of a customer's Global Administrator.
GRAPH_RESOURCE_APP_ID = "00000003-0000-0000-c000-000000000000"

GRAPH_APP_ROLES: dict[str, str] = {
    "Directory.Read.All": "7ab1d382-f21e-4acd-a863-ba3e13f7da61",
    "User.Read.All": "df021288-bdef-4463-88db-98f22de89214",
    "RoleManagement.Read.Directory": "483bed4a-2ad3-4361-a73b-c83ccdbdc53c",
    "UserAuthenticationMethod.Read.All": "38d9df27-64da-44fd-b7c5-a6fbac20248f",
    "Policy.Read.All": "246dd0d5-5bd0-4def-940b-0421030a5b68",
    "Application.Read.All": "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30",
    "Group.Read.All": "5b567255-7703-4780-807c-7be8301ae99b",
    "IdentityRiskyUser.Read.All": "dc5007c0-2d7d-4c42-879c-2dab87571379",
    "AuditLog.Read.All": "b0afded3-3588-46d8-8b3d-9842eff778da",
}


def granted_permissions(graph_token: str) -> frozenset[str]:
    """The Graph application permissions this token actually carries.

    A client-credentials token lists its granted application permissions in the
    ``roles`` claim, so the authoritative answer to "what did consent actually
    grant in this tenant" is already in hand before any API call is made. There
    is no Graph endpoint that answers it as directly, and the obvious
    candidates all require a permission that may itself be missing.

    The signature is deliberately not verified, and this value is deliberately
    never used to authorize anything. It is read for diagnosis only -- to turn
    "Insufficient privileges to complete the operation" into a list of names a
    Global Administrator can act on. Microsoft remains the enforcer: a token
    claiming a permission it was not granted still gets a 403 from Graph.
    """
    try:
        claims = jwt.decode(graph_token, options={"verify_signature": False})
    except Exception as exc:  # pragma: no cover -- malformed token
        log.warning("azure.token_undecodable", error=str(exc))
        return frozenset()
    roles = claims.get("roles") or []
    return frozenset(str(r) for r in roles)


def missing_permissions(graph_token: str) -> tuple[str, ...]:
    """Required permissions this tenant's consent did not grant, in order.

    Empty when the token could not be read at all: an unreadable token is not
    evidence of a missing grant, and reporting nine phantom gaps would send an
    administrator to fix something that is not broken.
    """
    granted = granted_permissions(graph_token)
    if not granted:
        return ()
    return tuple(p for p in REQUIRED_GRAPH_PERMISSIONS if p not in granted)


def app_registration_manifest() -> list[dict]:
    """``requiredResourceAccess`` for CloudGuard's own app registration.

    The ARM template grants the *subscription* half of the access and can never
    grant this half: Graph application permissions live on the app registration
    in CloudGuard's home tenant, and a customer's admin consent grants whatever
    that registration happens to declare at the moment they click.

    Which makes the registration a deployment artefact like any other, and it
    has been a checklist in a comment. Generated here so it can be applied with
    ``az ad app update --required-resource-accesses`` and diffed, rather than
    clicked into a portal and hoped over.
    """
    return [
        {
            "resourceAppId": GRAPH_RESOURCE_APP_ID,
            "resourceAccess": [
                # "Role" is an application permission; "Scope" would be
                # delegated, which a background scanner with no signed-in user
                # can never exercise.
                {"id": GRAPH_APP_ROLES[name], "type": "Role"}
                for name in REQUIRED_GRAPH_PERMISSIONS
            ],
        }
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

    ``tenant_hint`` defaults to ``organizations``, which accepts work and school
    accounts and refuses personal Microsoft accounts outright ("You can't sign
    in here with a personal account"). That refusal is correct, not a
    misconfiguration: tenant-wide admin consent is a directory operation, and an
    MSA is not a member of the directory even when it owns the subscription
    underneath it. A customer in that position needs a member account in their
    own tenant -- typically ``admin@<tenant>.onmicrosoft.com`` -- holding Global
    Administrator.
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
