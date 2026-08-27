"""Connecting a customer's Azure environment, at a scope they choose.

The redesigned flow (AZURE_CONNECTOR_REDESIGN.md) has two customer actions:

1. Grant admin consent — the customer clicks "Connect with Microsoft",
   approves Graph permissions, and Entra's callback reports the tenant.
2. Deploy the scanner role — the customer clicks "Deploy to Azure", which
   opens the Azure Portal with a pre-filled ARM template that creates the
   custom role and assigns it to CloudGuard's service principal.

Everything else is automatic: CloudGuard polls for the RBAC grant and
discovers subscriptions once it detects access.
"""

import time
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.azure.auth import build_consent_url, sign_state
from app.connectors.azure.client import ArmClient, AzureApiError, GraphClient
from app.connectors.azure.rbac import ARM_READ_ACTIONS, ROLE_VERSION, TemplateContext, arm_template
from app.connectors.base import ConnectionCheck
from app.core.config import settings
from app.core.deps import TenantContext
from app.core.enums import (
    CloudAccountStatus,
    ConnectionScope,
    ConsentStatus,
)
from app.core.errors import CloudAccountNotFound, NotConfigured, ValidationFailed
from app.core.logging import get_logger
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.schemas.cloud_connection import CloudConnectionCreate

log = get_logger(__name__)

CONSENT_LINK_TTL_SECONDS = 1800
TEMPLATE_TOKEN_TTL_SECONDS = 7 * 24 * 3600


# ---------------------------------------------------------------------------
# Create + consent URL (merged into one call)
# ---------------------------------------------------------------------------


async def create_connection(
    session: AsyncSession, tenant: TenantContext, payload: CloudConnectionCreate
) -> tuple[CloudConnection, str | None]:
    """Create a connection and return it with the consent redirect URL.

    One API call does both, so the frontend has everything it needs to
    redirect the customer to Microsoft. The consent URL is best-effort:
    if Azure is not configured on this deployment, the connection is still
    created and the URL is None.
    """
    if payload.scope_type != ConnectionScope.TENANT_ROOT and not payload.scope_id:
        raise ValidationFailed(
            "A management group or subscription id is required for this scope"
        )

    connection = CloudConnection(
        organization_id=tenant.organization_id,
        provider=payload.provider,
        name=payload.name,
        scope_type=payload.scope_type,
        scope_id=payload.scope_id,
        role_version=ROLE_VERSION,
        consent_status=ConsentStatus.PENDING,
        status=CloudAccountStatus.PENDING,
        status_detail="Grant admin consent to continue.",
    )
    session.add(connection)
    await session.flush()

    consent_url, problem = consent_url_for(connection)
    if problem:
        connection.status_detail = problem
    return connection, consent_url


def consent_url_for(connection: CloudConnection) -> tuple[str | None, str | None]:
    """A fresh consent link, or the reason there cannot be one.

    Regenerated on every read rather than stored, for two reasons. The state is
    signed with a 30-minute TTL, so a URL persisted at creation would be dead
    long before most customers get their administrator's attention. And it used
    to be returned *only* from the create response, which meant a page reload
    lost the consent button entirely and stranded the connection in PENDING
    with no way forward but deleting it.

    The failure reason is returned rather than swallowed. A deployment whose
    Entra credentials are wrong cannot produce this URL at all, and the
    customer needs to see that instead of a card with nothing on it.
    """
    try:
        state = sign_state(
            {
                "cloud_connection_id": str(connection.id),
                "organization_id": str(connection.organization_id),
                "issued_at": time.time(),
            }
        )
        return build_consent_url(state), None
    except NotConfigured as exc:
        return None, str(exc)
    except Exception as exc:  # pragma: no cover -- signing failure is unexpected
        log.warning(
            "azure.consent_url_failed", connection_id=str(connection.id), error=str(exc)
        )
        return None, f"Could not build a consent link: {exc}"


# ---------------------------------------------------------------------------
# Get / list connections
# ---------------------------------------------------------------------------


async def get_connection(
    session: AsyncSession, tenant: TenantContext, connection_id: UUID
) -> CloudConnection:
    connection = (
        await session.execute(
            select(CloudConnection).where(
                CloudConnection.id == connection_id,
                CloudConnection.organization_id == tenant.organization_id,
            )
        )
    ).scalar_one_or_none()
    if connection is None:
        raise CloudAccountNotFound("Connection not found")
    return connection


async def get_connection_with_subscriptions(
    session: AsyncSession, tenant: TenantContext, connection_id: UUID
) -> tuple[CloudConnection, list[CloudAccount]]:
    """Fetch a connection and its discovered subscriptions in one call."""
    connection = await get_connection(session, tenant, connection_id)
    subscriptions = await _list_subscriptions(session, connection)
    return connection, subscriptions


async def list_connections(
    session: AsyncSession, tenant: TenantContext
) -> list[tuple[CloudConnection, int]]:
    """All connections for the org, each with a subscription count."""
    rows = (
        await session.execute(
            select(
                CloudConnection,
                func.count(CloudAccount.id).label("sub_count"),
            )
            .outerjoin(CloudAccount, CloudAccount.connection_id == CloudConnection.id)
            .where(CloudConnection.organization_id == tenant.organization_id)
            .group_by(CloudConnection.id)
            .order_by(CloudConnection.created_at.desc())
        )
    ).all()
    return [(row[0], row[1]) for row in rows]


async def _list_subscriptions(
    session: AsyncSession, connection: CloudConnection
) -> list[CloudAccount]:
    return list(
        (
            await session.execute(
                select(CloudAccount)
                .where(CloudAccount.connection_id == connection.id)
                .order_by(CloudAccount.display_name)
            )
        )
        .scalars()
        .all()
    )


READY_TO_DEPLOY = "Admin consent granted. Deploy the scanner role next."


# ---------------------------------------------------------------------------
# Consent callback
# ---------------------------------------------------------------------------


async def record_consent(
    session: AsyncSession, connection_id: UUID, tenant_id: str
) -> CloudConnection:
    """Mark consent granted after Entra's callback.

    ``tenant_id`` arrives from Entra, not from the customer, and this is the
    only place it is ever written.
    """
    connection = await session.get(CloudConnection, connection_id)
    if connection is None:
        raise CloudAccountNotFound("Connection not found")

    connection.consent_status = ConsentStatus.GRANTED
    connection.consented_at = datetime.now(UTC)
    connection.tenant_id = tenant_id or connection.tenant_id
    connection.status_detail = READY_TO_DEPLOY

    if connection.tenant_id:
        problem = await _resolve_service_principal(connection)
        if problem and not connection.service_principal_object_id:
            connection.status_detail = problem

    await session.commit()
    return connection


async def ensure_service_principal(
    session: AsyncSession, connection: CloudConnection
) -> bool:
    """Resolve the service principal now if consent has not yielded one yet.

    Entra creates the principal during consent, but it is not always queryable
    by the time the callback fires a moment later -- directory replication gets
    there when it gets there. The callback therefore treats the lookup as best
    effort, which left a hole: the artifact step needs that object id, comes
    *before* validation, and validation was the only thing that retried. A
    customer whose lookup lost that race had no way forward at all.

    So the artifact endpoints resolve on demand. Retrying is the fix, and this
    is what makes retrying do something.
    """
    if connection.service_principal_object_id:
        return True
    if connection.consent_status != ConsentStatus.GRANTED or not connection.tenant_id:
        return False

    problem = await _resolve_service_principal(connection)
    if connection.service_principal_object_id:
        connection.status_detail = READY_TO_DEPLOY
        await session.commit()
        return True

    # Committed so it survives the request and reaches the card. Without this
    # the connection kept reporting the cheerful "deploy the scanner role next"
    # under a spinner, while the thing that would let anyone deploy had failed.
    if problem:
        connection.status_detail = problem
        await session.commit()
    return False


async def _resolve_service_principal(connection: CloudConnection) -> str | None:
    """Look the principal up. Returns None on success, or why it failed.

    Returning the reason rather than swallowing it is the point. Every way this
    can fail used to collapse into the same silent nothing, and the connection
    card showed a spinner that would never stop -- identical whether Entra
    needed another few seconds or the app registration had no permissions to
    grant in the first place. Those need different actions from different
    people, so they have to read differently.
    """
    from app.connectors.azure.auth import TokenProvider

    if not connection.tenant_id:
        return "No Entra tenant is bound to this connection yet."

    try:
        tokens = TokenProvider(connection.tenant_id)
        async with GraphClient(tokens) as graph:
            principal = await graph.find_service_principal(settings.azure_client_id)
    except AzureApiError as exc:
        log.warning(
            "azure.service_principal_lookup_failed",
            connection_id=str(connection.id),
            status_code=exc.azure_status_code,
            error=str(exc),
        )
        if exc.azure_status_code in (401, 403):
            # The overwhelmingly likely cause, and not something the customer
            # can fix in their own tenant: consent can only grant permissions
            # the app registration actually declares, so a registration with
            # none grants nothing and every Graph call is refused afterwards.
            return (
                "Microsoft Graph refused this lookup. CloudGuard's own app "
                "registration is most likely missing its API permissions, so "
                "admin consent had nothing to grant. This is a setup step on "
                "CloudGuard's side (AZURE_INTEGRATION.md §2.1)."
            )
        return f"Microsoft Graph could not be read: {exc}"
    except Exception as exc:
        log.warning(
            "azure.service_principal_lookup_failed",
            connection_id=str(connection.id),
            error=str(exc),
        )
        return f"Could not reach Microsoft Graph for this tenant: {exc}"

    if principal and principal.get("id"):
        connection.service_principal_object_id = str(principal["id"])
        return None

    return (
        "Admin consent completed, but CloudGuard's service principal is not "
        "visible in this directory yet. Entra can take a minute to publish it."
    )


# ---------------------------------------------------------------------------
# ARM template
# ---------------------------------------------------------------------------


def template_token(connection: CloudConnection) -> str:
    """Sign a token for the unauthenticated ARM template endpoint.

    Azure Portal fetches the template server-side, so it cannot carry a
    CloudGuard session. The token is signed and has a 7-day TTL.
    """
    return sign_state(
        {
            "cloud_connection_id": str(connection.id),
            "purpose": "template",
            "issued_at": time.time(),
        }
    )


def public_api_base() -> str | None:
    """The API's own public origin, for a URL Azure Portal will fetch.

    Not ``app_url``: that is the *frontend*, and the two are separate hosts in
    this deployment (Vercel and Railway). Pointing a template URL at the
    frontend returns the SPA's index.html, and Azure Portal fails to parse it
    as ARM -- a failure that reads as a broken template rather than a wrong
    host.

    ``API_URL`` is the direct answer but is not a required variable, so it may
    be unset. ``AZURE_REDIRECT_URI`` is the reliable fallback: it is this API's
    own public callback URL, and it cannot be subtly wrong, because Entra
    compares it character for character and consent fails outright otherwise.
    Anything reaching this function has already completed consent.

    None rather than a guess when neither is available -- a hidden button is
    recoverable, a link to the wrong host is a support ticket.
    """
    if settings.api_url:
        return settings.api_url.rstrip("/")
    if settings.azure_redirect_uri:
        parts = urlsplit(settings.azure_redirect_uri)
        if parts.scheme and parts.netloc:
            return f"{parts.scheme}://{parts.netloc}"
    return None


def template_url(connection: CloudConnection) -> str | None:
    """The full URL for the ARM template endpoint, or None if not ready."""
    if not connection.service_principal_object_id or not connection.scope_path:
        return None
    base = public_api_base()
    if not base:
        return None
    token = template_token(connection)
    return f"{base}/api/v1/cloud-connections/{connection.id}/template?token={token}"


def render_template(connection: CloudConnection) -> str:
    """Generate the ARM template JSON for this connection."""
    if not connection.service_principal_object_id or not connection.scope_path:
        raise ValidationFailed(
            "Admin consent has not completed yet, so there is no service "
            "principal to grant access to."
        )

    context = TemplateContext(
        principal_id=connection.service_principal_object_id,
        scope_path=connection.scope_path,
        scope_type=connection.scope_type,
        role_version=connection.role_version,
    )
    return arm_template(context)


def deploy_to_azure_url(connection: CloudConnection) -> str | None:
    """The Deploy to Azure button URL, or None if the template isn't ready."""
    tpl_url = template_url(connection)
    if not tpl_url:
        return None
    from urllib.parse import quote

    return f"https://portal.azure.com/#create/Microsoft.Template/uri/{quote(tpl_url, safe='')}"


# ---------------------------------------------------------------------------
# Auto-validation (called during polling)
# ---------------------------------------------------------------------------


async def try_auto_validate(
    session: AsyncSession, connection: CloudConnection
) -> CloudConnection:
    """Attempt validation and discovery silently during polling.

    Failures are silent — they mean the customer hasn't deployed the role yet.
    The UI shows "Waiting for deployment..." rather than an error.
    """
    if connection.consent_status != ConsentStatus.GRANTED or not connection.tenant_id:
        return connection

    # Retry the lookup if it is still missing, through the committing wrapper.
    # The bare call left a resolved id in memory only: when the probe below
    # then failed -- which it does every poll until the role is deployed --
    # nothing committed, so the id was rediscovered from Graph on every single
    # poll and never actually stored.
    if not await ensure_service_principal(session, connection):
        return connection

    # Attempt RBAC validation if not yet verified
    if not connection.rbac_verified_at:
        check = await _probe_silently(connection)
        if check.ok:
            connection.status = CloudAccountStatus.ACTIVE
            connection.rbac_verified_at = datetime.now(UTC)
            connection.status_detail = "Connection verified."
            await session.commit()
        # If probe fails, stay silent — customer hasn't deployed yet

    # Auto-discover subscriptions once validated
    if connection.rbac_verified_at and not connection.last_discovery_at:
        await _auto_discover(session, connection)

    return connection


async def _probe_silently(connection: CloudConnection) -> ConnectionCheck:
    """Verify ARM access. Returns ok=False silently on failure."""
    from app.connectors.azure.auth import TokenProvider

    tenant_id = connection.tenant_id or ""
    check = ConnectionCheck(ok=False, tenant_id=tenant_id)

    try:
        tokens = TokenProvider(tenant_id)
    except Exception:
        return check

    try:
        async with ArmClient(tokens) as arm:
            subscriptions = await arm.list_subscriptions()
            if not subscriptions:
                return check
            check.permissions_verified.append(
                f"Azure Resource Manager: {len(subscriptions)} subscription(s) readable"
            )
            check.subscription_id = str(subscriptions[0].get("subscriptionId") or "")

            # Confirm we can actually read resources in at least one subscription
            try:
                await arm.list_resources(check.subscription_id)
                check.permissions_verified.append("Resource listing confirmed")
            except AzureApiError:
                return check
    except Exception:
        return check

    check.ok = True
    check.detail = "Connection verified"
    return check


async def _auto_discover(
    session: AsyncSession, connection: CloudConnection
) -> list[CloudAccount]:
    """Discover subscriptions automatically after validation."""
    from app.connectors.azure.auth import TokenProvider

    try:
        tokens = TokenProvider(connection.tenant_id or "")
        async with ArmClient(tokens) as arm:
            subscriptions = await arm.list_subscriptions()
    except Exception as exc:
        log.warning(
            "azure.auto_discover_failed",
            connection_id=str(connection.id),
            error=str(exc),
        )
        return []

    existing: dict[str, CloudAccount] = {
        account.subscription_id: account
        for account in (
            await session.execute(
                select(CloudAccount).where(CloudAccount.connection_id == connection.id)
            )
        )
        .scalars()
        .all()
        if account.subscription_id
    }

    now = datetime.now(UTC)
    accounts: list[CloudAccount] = []

    for subscription in subscriptions:
        subscription_id = str(subscription.get("subscriptionId") or "")
        if not subscription_id:
            continue
        display_name = str(subscription.get("displayName") or subscription_id)

        account = existing.get(subscription_id)
        if account is None:
            account = CloudAccount(
                organization_id=connection.organization_id,
                connection_id=connection.id,
                provider=connection.provider,
                account_name=display_name,
                display_name=display_name,
                tenant_id=connection.tenant_id or "",
                subscription_id=subscription_id,
                discovered_at=now,
                in_scope=True,
            )
            session.add(account)
        else:
            account.display_name = display_name

        account.consent_status = connection.consent_status
        account.rbac_verified_at = connection.rbac_verified_at
        account.status = (
            CloudAccountStatus.ACTIVE if account.in_scope else CloudAccountStatus.DISABLED
        )
        accounts.append(account)

    # Disable subscriptions that have vanished
    seen = {a.subscription_id for a in accounts}
    for subscription_id, account in existing.items():
        if subscription_id not in seen:
            account.status = CloudAccountStatus.DISABLED
            account.status_detail = "No longer visible to this connection"

    connection.last_discovery_at = now
    await session.commit()
    return accounts


# ---------------------------------------------------------------------------
# Subscription scope management
# ---------------------------------------------------------------------------


async def set_subscription_scope(
    session: AsyncSession, tenant: TenantContext, connection_id: UUID, in_scope: dict[str, bool]
) -> list[CloudAccount]:
    connection = await get_connection(session, tenant, connection_id)
    accounts = list(
        (
            await session.execute(
                select(CloudAccount).where(CloudAccount.connection_id == connection.id)
            )
        )
        .scalars()
        .all()
    )

    for account in accounts:
        if account.subscription_id in in_scope:
            account.in_scope = in_scope[account.subscription_id]
            account.status = (
                CloudAccountStatus.ACTIVE
                if account.in_scope
                else CloudAccountStatus.DISABLED
            )

    await session.commit()
    return accounts


# ---------------------------------------------------------------------------
# Helpers for routes
# ---------------------------------------------------------------------------


def graph_permissions() -> list[str]:
    from app.connectors.azure.auth import REQUIRED_GRAPH_PERMISSIONS

    return list(REQUIRED_GRAPH_PERMISSIONS)


def arm_actions() -> list[str]:
    return list(ARM_READ_ACTIONS)
