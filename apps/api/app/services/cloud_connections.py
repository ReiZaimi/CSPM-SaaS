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

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.azure.auth import build_consent_url, sign_state
from app.connectors.azure.client import ArmClient, AzureApiError, GraphClient
from app.connectors.azure.rbac import (
    ARM_READ_ACTIONS,
    ROLE_NAME,
    ROLE_VERSION,
    TemplateContext,
    arm_template,
    categories_behind,
    role_is_current,
)
from app.connectors.base import ConnectionCheck
from app.connectors.evidence import EvidenceCategory
from app.core.config import settings
from app.core.db import commit_unless_externally_managed
from app.core.deps import TenantContext
from app.core.enums import (
    CloudAccountStatus,
    ConnectionScope,
    ConsentStatus,
    Provider,
)
from app.core.errors import CloudAccountNotFound, NotConfigured, ValidationFailed
from app.core.logging import get_logger
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.schemas.cloud_connection import CloudConnectionCreate
from app.services import findings as findings_service

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
) -> list[tuple[CloudConnection, list[CloudAccount]]]:
    """All connections for the org, each with its discovered subscriptions.

    The subscriptions come back here, not only from the per-connection
    endpoint. The connections page renders from this list, and when it carried
    only a count the cards showed no subscriptions at all for a verified
    connection -- the detail request that would have supplied them never fired,
    because a card that is already verified has nothing left to poll for.
    """
    connections = list(
        (
            await session.execute(
                select(CloudConnection)
                .where(CloudConnection.organization_id == tenant.organization_id)
                .order_by(CloudConnection.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    if not connections:
        return []

    # One query for every connection's subscriptions rather than one each.
    accounts = list(
        (
            await session.execute(
                select(CloudAccount)
                .where(
                    CloudAccount.connection_id.in_([c.id for c in connections]),
                )
                .order_by(CloudAccount.display_name)
            )
        )
        .scalars()
        .all()
    )

    grouped: dict[UUID, list[CloudAccount]] = {}
    for account in accounts:
        if account.connection_id:
            grouped.setdefault(account.connection_id, []).append(account)

    return [(c, grouped.get(c.id, [])) for c in connections]


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

# Marks a status detail as being about the directory grant rather than the
# subscription one. Checked as a prefix so a later step can tell the two apart
# without a schema change: everything else on this connection may be healthy
# while this is not, and the message must not be replaced by a cheerful one.
GRANT_INCOMPLETE_PREFIX = "Admin consent did not grant"


async def graph_grant_problem(connection: CloudConnection) -> str | None:
    """What consent failed to grant, named, or None when it granted everything.

    Consent resolves ``/.default`` to whatever CloudGuard's app registration
    declares at the moment it is clicked, so a registration whose permissions
    are missing -- or declared as delegated rather than application -- produces
    a consent screen that looks entirely successful and a token carrying no
    directory permissions at all. Nothing downstream could tell: the callback
    recorded GRANTED on Entra's redirect alone, and the first evidence anyone
    saw was the identity category failing mid-scan with "Insufficient
    privileges to complete the operation", a sentence naming neither the
    permission nor who can grant it.

    The token answers it before any call is made. Read for diagnosis only --
    Microsoft stays the enforcer (see ``granted_permissions``).
    """
    from app.connectors.azure.auth import (
        REQUIRED_GRAPH_PERMISSIONS,
        TokenProvider,
        missing_permissions,
    )

    if not connection.tenant_id:
        return None

    try:
        tokens = TokenProvider(connection.tenant_id)
        absent = missing_permissions(tokens.graph_token())
    except Exception as exc:
        # Not evidence of a missing grant. A tenant that cannot issue a token
        # has a different problem, and the probes report that one.
        log.warning(
            "azure.grant_check_failed",
            connection_id=str(connection.id),
            error=str(exc),
        )
        return None

    if not absent:
        return None

    total = len(REQUIRED_GRAPH_PERMISSIONS)
    if len(absent) == total:
        scale = f"any of the {total} directory permissions CloudGuard needs"
    else:
        scale = f"{len(absent)} of the {total} directory permissions CloudGuard needs"
    return (
        f"{GRANT_INCOMPLETE_PREFIX} {scale}: {', '.join(absent)}. Subscription "
        "scanning is unaffected; the identity checks cannot run until this is "
        "granted. Add these to CloudGuard's app registration as *application* "
        "permissions -- delegated ones do not appear in a service token -- then "
        "re-run admin consent for this tenant, because consent covers only what "
        "the registration declared at the moment it was granted."
    )


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

        # Checked here because here is where the answer first exists, and
        # because the alternative is a customer discovering it several minutes
        # into a scan. It does not change ``consent_status``: consent did
        # happen, and the subscription half of the connection is unaffected --
        # what is missing is what the registration offered to grant.
        gap = await graph_grant_problem(connection)
        if gap:
            connection.status_detail = gap

    await commit_unless_externally_managed(session)
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
        # A resolved principal does not mean the directory grant is whole, and
        # overwriting the message that says so would hide it behind a
        # reassurance. Re-checked only while that message stands, so the happy
        # path costs nothing and a re-consent still clears it.
        detail = READY_TO_DEPLOY
        if (connection.status_detail or "").startswith(GRANT_INCOMPLETE_PREFIX):
            detail = await graph_grant_problem(connection) or READY_TO_DEPLOY
        connection.status_detail = detail
        await commit_unless_externally_managed(session)
        return True

    # Committed so it survives the request and reaches the card. Without this
    # the connection kept reporting the cheerful "deploy the scanner role next"
    # under a spinner, while the thing that would let anyone deploy had failed.
    if problem:
        connection.status_detail = problem
        await commit_unless_externally_managed(session)
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


def role_upgrade_available(connection: CloudConnection) -> bool:
    """Whether this connection's deployed role is older than the one CloudGuard
    now needs.

    ``CloudConnection.role_version`` has been stamped at creation since
    connections existed, and until now nothing ever read it back. That made the
    version a label rather than a mechanism: bumping ``ROLE_VERSION`` to ship a
    check needing a new ARM action would leave every existing customer silently
    collecting UNKNOWN for it, with no prompt and no explanation.
    """
    return connection.provider == Provider.AZURE and not role_is_current(
        connection.role_version
    )


def degraded_categories(connection: CloudConnection) -> dict[EvidenceCategory, str]:
    """Collection categories this connection's role cannot fully serve.

    Returns category -> the sentence to show the customer. Empty when the role
    is current, and empty for any provider that has no such notion, so the
    scanner can call it without knowing which cloud it is looking at.
    """
    if not role_upgrade_available(connection):
        return {}

    explanation = (
        f"CloudGuard's scanner role was updated to {ROLE_VERSION} and this "
        f"connection still has {connection.role_version}, which does not grant "
        "the permissions these checks need. Redeploy the role from the "
        "connection page to enable them."
    )
    return {
        category: explanation
        for category in categories_behind(connection.role_version)
    }


async def set_scan_schedule(
    session: AsyncSession,
    tenant: TenantContext,
    connection_id: UUID,
    interval_hours: int | None,
) -> CloudConnection:
    """Turn recurring scanning on, off, or to a different cadence.

    Refused on a connection that cannot scan yet: scheduling one would queue a
    scan every interval that fails for the same reason each time, which reads
    to the customer as a broken product rather than as consent they have not
    granted.

    Takes effect on the next tick rather than immediately -- with one
    exception that falls out of the query rather than being special-cased. A
    connection that has never been scanned is overdue by definition, so
    switching scheduling on for a fresh connection starts a scan within
    minutes, which is what somebody who just enabled it expects.
    """
    connection = await get_connection(session, tenant, connection_id)

    if interval_hours is not None and not connection.is_verified:
        raise ValidationFailed(
            "This connection is not ready to scan yet, so there is nothing to "
            "schedule. Grant admin consent and assign the Reader role first."
        )

    connection.scan_interval_hours = interval_hours
    await findings_service.record_audit(
        session,
        tenant,
        action="connection.schedule_changed",
        resource_type="cloud_connection",
        resource_id=connection.id,
        metadata={"scan_interval_hours": interval_hours},
    )
    await commit_unless_externally_managed(session)
    return connection


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


# How long a connection may sit consented-but-unverified before the UI stops
# implying that waiting is the answer. Generous on purpose: the deployment step
# usually needs a *different* person -- whoever holds Owner or User Access
# Administrator on the scope -- so a slow hour here is normal, not a fault.
DEPLOY_PATIENCE_SECONDS = 30 * 60


def deploy_stalled(connection: CloudConnection) -> bool:
    """True once waiting has stopped being a plausible explanation.

    A failing probe is indistinguishable from "not deployed yet" for as long as
    deploying is still plausibly in progress. After that the two need to read
    differently: an unattended spinner claims progress that is not happening,
    and the customer has no way to tell a colleague who has not got round to it
    from a deployment that failed or landed at the wrong scope.
    """
    if connection.consent_status != ConsentStatus.GRANTED:
        return False
    if connection.rbac_verified_at or not connection.consented_at:
        return False
    waited = datetime.now(UTC) - connection.consented_at
    return waited.total_seconds() > DEPLOY_PATIENCE_SECONDS


DEPLOY_STALLED_DETAIL = (
    "CloudGuard still cannot read this environment. The scanner role may not "
    "have been deployed yet, or it may have been deployed at a different scope "
    "than this connection covers. Check that the deployment succeeded in Azure "
    "and that its scope matches, then it will verify on its own."
)


async def try_auto_validate(
    session: AsyncSession, connection: CloudConnection
) -> CloudConnection:
    """Attempt validation and discovery during polling.

    A failing probe stays quiet while the customer is plausibly still deploying
    -- that is the normal state for the whole of this step. Past
    ``DEPLOY_PATIENCE_SECONDS`` it stops being quiet, because by then silence is
    indistinguishable from a deployment that went wrong.
    """
    # A cancelled setup stops being polled. Otherwise "cancel" would mean only
    # that the spinner went away, while the server kept calling Azure every ten
    # seconds on behalf of a customer who said stop.
    if connection.status == CloudAccountStatus.DISABLED:
        return connection

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
            await commit_unless_externally_managed(session)
        elif deploy_stalled(connection):
            # Committed so the message survives the request. Status is left
            # alone: nothing here is known to be broken, and marking a
            # connection ERROR because a colleague is slow would be a lie.
            if connection.status_detail != DEPLOY_STALLED_DETAIL:
                connection.status_detail = DEPLOY_STALLED_DETAIL
                await commit_unless_externally_managed(session)

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

    # Only stamped when something was actually found. ``try_auto_validate``
    # treats this column as "discovery is done", so latching it on an empty
    # result freezes the connection with no subscriptions for good. An empty
    # listing right after a role deployment is not an answer -- ARM's
    # subscription list is eventually consistent and takes minutes to catch up
    # with a fresh assignment.
    if accounts:
        connection.last_discovery_at = now
    else:
        log.warning(
            "azure.discovery_found_nothing",
            connection_id=str(connection.id),
            tenant_id=connection.tenant_id,
        )
    await commit_unless_externally_managed(session)
    return accounts


async def rediscover_subscriptions(
    session: AsyncSession, tenant: TenantContext, connection_id: UUID
) -> tuple[CloudConnection, list[CloudAccount]]:
    """Run discovery again on demand, ignoring whether it has run before.

    The escape hatch that was missing. Discovery otherwise happens only inside
    ``try_auto_validate``, which runs only while the connections page is
    polling -- and the page stops polling the moment a connection reports
    itself verified. Verification and discovery are two ARM calls, so a single
    transient failure on the second one left a connection permanently verified
    with nothing beneath it and no way back short of editing the database.

    Safe to call repeatedly: discovery matches on subscription id, so an
    existing row is updated rather than duplicated, and a subscription the
    customer excluded stays excluded.
    """
    connection = await get_connection(session, tenant, connection_id)

    if not connection.is_verified:
        raise ValidationFailed(
            "This connection is not verified yet, so there is nothing to "
            "discover with. Grant admin consent and deploy the scanner role "
            "first."
        )

    accounts = await _auto_discover(session, connection)
    if not accounts:
        raise ValidationFailed(
            "CloudGuard could not see any subscriptions with this connection. "
            "Check that the scanner role is assigned at the scope you deployed "
            "it to, and that the subscriptions sit beneath it. A role assigned "
            "moments ago can take a few minutes to appear."
        )
    return connection, accounts


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

    await commit_unless_externally_managed(session)
    return accounts


# ---------------------------------------------------------------------------
# Helpers for routes
# ---------------------------------------------------------------------------


def graph_permissions() -> list[str]:
    from app.connectors.azure.auth import REQUIRED_GRAPH_PERMISSIONS

    return list(REQUIRED_GRAPH_PERMISSIONS)


def arm_actions() -> list[str]:
    return list(ARM_READ_ACTIONS)


SETUP_CANCELLED_DETAIL = (
    "Setup cancelled. Nothing was scanned. Resume when you are ready, or "
    "remove the connection."
)


async def set_setup_cancelled(
    session: AsyncSession,
    tenant: TenantContext,
    connection_id: UUID,
    cancelled: bool,
) -> CloudConnection:
    """Stop or restart the setup process for a connection.

    Deliberately reversible, and deliberately not a delete. Cancelling is what
    someone wants when the person who has to run the Azure deployment is not
    available today -- throwing the connection away would mean redoing admin
    consent, which needs a Global Administrator, to get back to exactly where
    they already were.

    A verified connection cannot be cancelled: there is no setup left to stop,
    and DISABLED there would read as "stop scanning", which is a different
    feature and not this one.
    """
    connection = await get_connection(session, tenant, connection_id)

    if cancelled and connection.is_verified:
        raise ValidationFailed(
            "This connection is already verified, so there is no setup to cancel."
        )

    if cancelled:
        connection.status = CloudAccountStatus.DISABLED
        connection.status_detail = SETUP_CANCELLED_DETAIL
    else:
        connection.status = CloudAccountStatus.PENDING
        connection.status_detail = (
            READY_TO_DEPLOY
            if connection.consent_status == ConsentStatus.GRANTED
            else "Grant admin consent to continue."
        )

    await commit_unless_externally_managed(session)
    return connection


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


def revocation_steps(connection: CloudConnection) -> dict:
    """What the customer must run to take CloudGuard's access away.

    CloudGuard cannot do this itself, and that is a design decision rather than
    a gap. Deleting its own role assignment needs
    ``Microsoft.Authorization/roleAssignments/delete``, and removing its service
    principal needs Graph ``Application.ReadWrite.All`` -- write permissions on
    the two most sensitive surfaces in a tenant. A CloudGuard holding the first
    could strip access from the customer's own administrators; holding the
    second it could rewrite any application in the directory. Both are far more
    dangerous than the read access they would revoke, and asking every customer
    to grant them permanently to support a rare teardown is the wrong trade.

    So the commands are generated instead, filled in for this connection, and
    :func:`check_access_revoked` proves afterwards whether they worked. Read
    access is the one thing CloudGuard can honestly report on, because losing it
    is observable.
    """
    principal = connection.service_principal_object_id
    scope = connection.scope_path
    role = f"{ROLE_NAME} ({connection.role_version})"

    steps: list[dict[str, str]] = []
    if principal and scope:
        steps.append(
            {
                "title": "Remove the scanner role assignment",
                "detail": "Ends CloudGuard's ability to read Azure resources.",
                "command": (
                    f"az role assignment delete --assignee {principal} --scope {scope}"
                ),
            }
        )
        steps.append(
            {
                "title": "Delete the custom role definition",
                "detail": "Optional. Removes the now-unused role from the scope.",
                "command": f'az role definition delete --name "{role}" --scope {scope}',
            }
        )
    if principal:
        steps.append(
            {
                "title": "Remove CloudGuard from your directory",
                "detail": (
                    "Withdraws admin consent by deleting the enterprise "
                    "application, ending directory access as well."
                ),
                "command": f"az ad sp delete --id {principal}",
            }
        )

    return {
        "principal_id": principal,
        "scope_path": scope,
        "role_name": role,
        "tenant_id": connection.tenant_id,
        "steps": steps,
        # Stated plainly so nobody expects a button that cannot exist.
        "why_manual": (
            "CloudGuard holds read-only access and no write permission of any "
            "kind, so it cannot remove its own access. These run under your "
            "credentials, not CloudGuard's."
        ),
        "portal_url": (
            "https://portal.azure.com/#view/Microsoft_AAD_IAM/"
            "StartboardApplicationsMenuBlade/~/AppAppsPreview"
        ),
    }


async def check_access_revoked(connection: CloudConnection) -> dict:
    """Ask Azure whether CloudGuard can still read this environment.

    The one honest confirmation available: revocation is verified by the access
    failing, using the same read-only probe that verified it working. A product
    that said "revoked" because a button was pressed would be asserting
    something it had not checked -- the same move this codebase refuses
    everywhere else.
    """
    if not connection.tenant_id:
        return {"revoked": True, "detail": "No tenant is bound to this connection."}

    check = await _probe_silently(connection)
    if check.ok:
        return {
            "revoked": False,
            "detail": (
                "CloudGuard can still read this environment. The role "
                "assignment is in place; Azure can take a minute to apply a "
                "removal."
            ),
        }
    return {
        "revoked": True,
        "detail": "Confirmed: CloudGuard can no longer read this environment.",
    }
