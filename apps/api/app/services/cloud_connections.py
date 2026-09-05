"""Connecting a customer's cloud, at a scope they choose.

The flow has two customer actions on Azure and one on AWS, and this module
knows about neither. It holds what is the same in every cloud -- creating the
connection, polling until the grant proves itself, writing the accounts
discovered beneath it, the scan schedule, the change-event debounce, the scope
choices -- and asks ``ProviderOnboarding`` for everything that is a cloud's own
vocabulary (``connectors/onboarding.py``).

That split is new. Until AWS existed this module imported Azure's token
provider, its ARM and Graph clients and its role definitions directly, and
``MULTI_CLOUD.md`` §2 called it the Azure-coupled half of the application --
correctly, and deliberately, because an abstraction guessed from one example is
usually wrong in the places that matter. §8 step 5 scheduled the split for when
a second provider existed to split it for.

The shape underneath is unchanged: CloudGuard hands the customer something to
deploy, proves the grant by *using* it rather than by being told it exists, and
then discovers what is beneath the scope rather than having it typed in.
"""

import time
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.base import ConnectionCheck
from app.connectors.evidence import EvidenceCategory
from app.connectors.onboarding import DeploymentArtifact, ProviderOnboarding
from app.connectors.registry import get_onboarding
from app.core.config import settings
from app.core.db import commit_unless_externally_managed
from app.core.deps import TenantContext
from app.core.enums import (
    CloudAccountStatus,
    ConsentStatus,
    Provider,
)
from app.core.errors import CloudAccountNotFound, ValidationFailed
from app.core.logging import get_logger
from app.core.signing import sign_state
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.schemas.cloud_connection import CloudConnectionCreate
from app.services import change_events
from app.services import findings as findings_service

log = get_logger(__name__)

CONSENT_LINK_TTL_SECONDS = 1800
TEMPLATE_TOKEN_TTL_SECONDS = 7 * 24 * 3600


def flow(connection: CloudConnection) -> ProviderOnboarding:
    """How this connection's cloud grants access.

    A function rather than a cached attribute: onboarding implementations are
    stateless and take the connection they are about, so building one costs
    nothing and holding one would only invite it to go stale against a row that
    has since been reloaded.
    """
    return get_onboarding(connection.provider)


def scope_path(connection: CloudConnection) -> str | None:
    """The provider's own name for the scope this grant is written at.

    Was a property on the model and is not one any more. It rendered an ARM
    management-group path for whatever it was handed, so an AWS connection
    would have carried a plausible-looking Azure scope on every API response --
    the kind of wrong answer that is worse than no answer, because nothing about
    it reads as a mistake.
    """
    return flow(connection).scope_path(connection)


# ---------------------------------------------------------------------------
# Create + the link that starts the first grant
# ---------------------------------------------------------------------------


async def create_connection(
    session: AsyncSession, tenant: TenantContext, payload: CloudConnectionCreate
) -> tuple[CloudConnection, str | None]:
    """Create a connection and return it with the URL that starts the grant.

    One API call does both, so the frontend has everything it needs to send the
    customer where they have to go next. The URL is best-effort: a deployment
    that is not configured for this provider still gets a connection, and the
    reason lands in ``status_detail`` rather than in an exception. It is also
    legitimately ``None`` for a provider whose only grant is the deployment
    itself, which is AWS.
    """
    onboarding = get_onboarding(payload.provider)

    if onboarding.requires_scope_id(payload.scope_type) and not payload.scope_id:
        raise ValidationFailed(
            "An id is required for this scope. Only a scope the provider can "
            "name for itself may be left blank."
        )

    connection = CloudConnection(
        organization_id=tenant.organization_id,
        provider=payload.provider,
        name=payload.name,
        scope_type=payload.scope_type,
        scope_id=payload.scope_id,
        role_version=onboarding.grant_version(),
        consent_status=ConsentStatus.PENDING,
        status=CloudAccountStatus.PENDING,
        status_detail=onboarding.initial_status_detail,
    )
    # Before the row is written, because the external id has to exist before
    # anything can name it -- and because generating it later would mean a
    # connection that briefly had none.
    connection.provider_ref = onboarding.initial_provider_ref(connection)

    session.add(connection)
    await session.flush()

    start_url, problem = onboarding.start_url(connection)
    if problem:
        connection.status_detail = problem
    return connection, start_url


def grant_start_url(connection: CloudConnection) -> tuple[str | None, str | None]:
    """A fresh link to begin the grant, or the reason there cannot be one.

    Regenerated on every read rather than stored. Azure's is signed with a
    30-minute TTL, so a URL persisted at creation would be dead long before most
    customers get their administrator's attention -- and it used to be returned
    *only* from the create response, which meant a page reload lost the consent
    button entirely and stranded the connection in PENDING with no way forward
    but deleting it.

    ``(None, None)`` is a complete answer for a provider with no such step, and
    not a failure to produce one.
    """
    return flow(connection).start_url(connection)


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


def _record_single_grant(
    connection: CloudConnection,
    onboarding: ProviderOnboarding,
    check: ConnectionCheck,
) -> None:
    """For a cloud with one grant, the probe is the consent.

    Azure records two grants because two people grant them and they fail
    independently. AWS has one, so leaving ``consent_status`` at PENDING for a
    working connection would make ``is_verified`` false for a connection that
    verifies -- and the trust boundary arrives from the same call rather than
    from a callback, because there is no callback (``DECISIONS.md`` §70).
    """
    if onboarding.has_separate_consent:
        return
    connection.consent_status = ConsentStatus.GRANTED
    connection.consented_at = connection.consented_at or datetime.now(UTC)
    # From the provider, never from the customer. The same guarantee the Entra
    # callback gives, reached by a different route.
    if check.tenant_id and not connection.tenant_id:
        connection.tenant_id = check.tenant_id


async def grant_problem(connection: CloudConnection) -> str | None:
    """What the grant failed to cover, named, or None when it covered everything.

    Only some clouds can grant less than was asked for and report success. Entra
    resolves ``/.default`` against whatever CloudGuard's app registration
    declares at the moment consent is clicked, so a registration missing its
    permissions produces a consent screen that looks entirely normal and a token
    carrying nothing. A provider without that failure mode answers None, which
    is why this is asked of every one of them rather than of Azure.
    """
    return await flow(connection).grant_problem(connection)


# ---------------------------------------------------------------------------
# Recording the first grant
# ---------------------------------------------------------------------------


async def record_consent(
    session: AsyncSession, connection_id: UUID, tenant_id: str
) -> CloudConnection:
    """Mark the first grant made, after the provider's callback.

    ``tenant_id`` arrives from the provider, not from the customer, and this is
    the only place it is ever written. That is the whole tenant-binding
    guarantee: when it came from a request body, any user could name an
    organization somebody else had already consented for and validate against
    their environment.
    """
    connection = await session.get(CloudConnection, connection_id)
    if connection is None:
        raise CloudAccountNotFound("Connection not found")
    onboarding = flow(connection)

    connection.consent_status = ConsentStatus.GRANTED
    connection.consented_at = datetime.now(UTC)
    connection.tenant_id = tenant_id or connection.tenant_id
    connection.status_detail = onboarding.ready_to_deploy_detail

    if connection.tenant_id:
        lookup = await onboarding.ensure_principal(connection)
        if lookup.object_id:
            connection.service_principal_object_id = lookup.object_id
        elif lookup.problem:
            connection.status_detail = lookup.problem

        # Checked here because here is where the answer first exists, and
        # because the alternative is a customer discovering it several minutes
        # into a scan. It does not change ``consent_status``: the grant did
        # happen, and the subscription half of the connection is unaffected --
        # what is missing is what the registration offered to grant.
        gap = await onboarding.grant_problem(connection)
        if gap:
            connection.status_detail = gap

    await commit_unless_externally_managed(session)
    return connection


async def ensure_principal(
    session: AsyncSession, connection: CloudConnection
) -> bool:
    """Resolve the identity a grant points at, if this cloud has one.

    Entra creates the principal during consent, but it is not always queryable
    by the time the callback fires a moment later -- directory replication gets
    there when it gets there. The callback therefore treats the lookup as best
    effort, which left a hole: the artefact step needs that object id, comes
    *before* validation, and validation was the only thing that retried. A
    customer whose lookup lost that race had no way forward at all.

    So the artefact endpoints resolve on demand. Retrying is the fix, and this
    is what makes retrying do something. A provider with nothing to resolve says
    it is ready and this returns immediately.
    """
    onboarding = flow(connection)
    lookup = await onboarding.ensure_principal(connection)

    if lookup.object_id and lookup.object_id != connection.service_principal_object_id:
        connection.service_principal_object_id = lookup.object_id

    if lookup.ready:
        if lookup.object_id:
            # A resolved principal does not mean the grant is whole, and
            # overwriting the message that says so would hide it behind a
            # reassurance. Re-checked only while that message stands, so the
            # happy path costs nothing and a re-consent still clears it.
            detail = onboarding.ready_to_deploy_detail
            prefix = onboarding.grant_incomplete_prefix
            if prefix and (connection.status_detail or "").startswith(prefix):
                detail = await onboarding.grant_problem(connection) or detail
            connection.status_detail = detail
            await commit_unless_externally_managed(session)
        return True

    # Committed so it survives the request and reaches the card. Without this
    # the connection kept reporting the cheerful "deploy the scanner role next"
    # under a spinner, while the thing that would let anyone deploy had failed.
    if lookup.problem:
        connection.status_detail = lookup.problem
        await commit_unless_externally_managed(session)
    return False


# ---------------------------------------------------------------------------
# The deployable artefact
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


def artifact_url(connection: CloudConnection) -> str | None:
    """Where the provider's console fetches the artefact, or None if not ready.

    Token-gated rather than authenticated: Azure Portal fetches it from the
    customer's browser with no CloudGuard session, and CloudFormation fetches
    it server-side with none either.
    """
    if not flow(connection).artifact_ready(connection):
        return None
    base = public_api_base()
    if not base:
        return None
    token = template_token(connection)
    return f"{base}/api/v1/cloud-connections/{connection.id}/template?token={token}"


def render_artifact(connection: CloudConnection) -> DeploymentArtifact:
    """The deployable artefact for this connection, rendered now.

    Rendered from the *current* permission set, not the version recorded on the
    connection. Redeploying is how a customer gets the newer grant, so an
    artefact stamped with their stale version deployed the current actions under
    the old name -- which then read back as still behind, and left "redeploy" as
    a button that could be pressed forever without changing anything.
    """
    return flow(connection).artifact(connection)


def deployment_url(connection: CloudConnection) -> str | None:
    """The one-click deploy link, or None while the artefact is not ready.

    Deploy to Azure, or CloudFormation's Launch Stack. The URL the console
    fetches is built here, because it needs a signed token and this API's own
    public origin; what to wrap it in is the provider's answer.
    """
    url = artifact_url(connection)
    if not url:
        return None
    return flow(connection).launch_url(connection, url)


def grant_upgrade_available(connection: CloudConnection) -> bool:
    """Whether this connection's deployed grant is older than the current one.

    ``role_version`` has been stamped at creation since connections existed, and
    until it was read back the version was a label rather than a mechanism:
    bumping it to ship a check needing a new permission would leave every
    existing customer silently collecting UNKNOWN for it, with no prompt and no
    explanation.
    """
    return flow(connection).grant_is_behind(connection)


def required_grant_version(connection: CloudConnection) -> str | None:
    """The version this connection should be on, or None if it has no such
    notion.

    Asked of the provider rather than read from a constant by the route,
    because the route layer is neutral and a role version is not.
    """
    return flow(connection).required_grant_version(connection)


def degraded_categories(connection: CloudConnection) -> dict[EvidenceCategory, str]:
    """Collection categories this connection's grant cannot fully serve.

    Category -> the sentence to show the customer. Empty when the grant is
    current, and empty for any provider that has no such notion, so the scanner
    can call it without knowing which cloud it is looking at.
    """
    return flow(connection).degraded_categories(connection)


async def refresh_grant_version(
    session: AsyncSession, connection: CloudConnection
) -> str | None:
    """Record what the deployed grant actually allows. Returns the new version.

    Returns None when nothing changed, so a caller can tell "checked, same
    answer" from "checked, and this connection just gained the checks it was
    missing". A provider that cannot answer returns None too, and the recorded
    version is left alone rather than replaced by a probe that did not land.
    """
    detected = await flow(connection).detect_grant_version(connection)
    if detected is None or detected == connection.role_version:
        return None

    previous = connection.role_version
    connection.role_version = detected
    await commit_unless_externally_managed(session)
    log.info(
        "connection.grant_version_changed",
        connection_id=str(connection.id),
        previous=previous,
        detected=detected,
    )
    return detected


async def recheck_access(
    session: AsyncSession, tenant: TenantContext, connection_id: UUID
) -> tuple[CloudConnection, list[CloudAccount]]:
    """Ask the provider again what CloudGuard is allowed to do here.

    What "Re-check access" claimed to do all along. It refetched the
    connection, and the only probe on that path runs while a connection is
    *unverified* -- so on a working connection the button re-read the same row
    and repainted the same three lines, including a grant version nothing had
    looked at since the day it was created.

    Two questions, because the panel states two answers: whether the read still
    works, and which grant it works through. A probe that fails leaves the
    recorded state alone -- one refused call is not proof access is gone, and
    ``check_access_revoked`` is where that question is asked deliberately.
    """
    connection, subscriptions = await get_connection_with_subscriptions(
        session, tenant, connection_id
    )

    if (
        flow(connection).has_separate_consent
        and connection.consent_status != ConsentStatus.GRANTED
    ):
        return await try_auto_validate(session, connection), subscriptions

    onboarding = flow(connection)
    check = await onboarding.probe(connection)
    if check.ok:
        connection.rbac_verified_at = datetime.now(UTC)
        if connection.status == CloudAccountStatus.PENDING:
            connection.status = CloudAccountStatus.ACTIVE
            connection.status_detail = "Connection verified."
        _record_single_grant(connection, onboarding, check)
        await commit_unless_externally_managed(session)

    await refresh_grant_version(session, connection)

    # A connection verified by this call has never discovered anything, and the
    # page it answers stops polling as soon as it reports itself ready.
    if connection.rbac_verified_at and not connection.last_discovery_at:
        await _auto_discover(session, connection)
        _, subscriptions = await get_connection_with_subscriptions(
            session, tenant, connection_id
        )

    return connection, subscriptions


async def set_scan_schedule(
    session: AsyncSession,
    tenant: TenantContext,
    connection_id: UUID,
    interval_hours: int | None,
) -> CloudConnection:
    """Turn recurring scanning on, off, or to a different cadence.

    Refused on a connection that cannot scan yet: scheduling one would queue a
    scan every interval that fails for the same reason each time, which reads
    to the customer as a broken product rather than as access they have not
    granted.

    Takes effect on the next tick rather than immediately -- with one exception
    that falls out of the query rather than being special-cased. A connection
    that has never been scanned is overdue by definition, so switching
    scheduling on for a fresh connection starts a scan within minutes, which is
    what somebody who just enabled it expects.
    """
    connection = await get_connection(session, tenant, connection_id)

    if interval_hours is not None and not connection.is_verified:
        raise ValidationFailed(
            "This connection is not ready to scan yet, so there is nothing to "
            "schedule. Finish granting CloudGuard read access first."
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

    onboarding = flow(connection)
    # A cloud with a separate consent step has nothing to probe until consent
    # has happened and reported the trust boundary. A cloud without one has
    # nothing to wait for: the stack is the grant, and the probe is what
    # discovers whether it is deployed yet.
    if onboarding.has_separate_consent and (
        connection.consent_status != ConsentStatus.GRANTED or not connection.tenant_id
    ):
        return connection

    # Retry the lookup if it is still missing, through the committing wrapper.
    # The bare call left a resolved id in memory only: when the probe below
    # then failed -- which it does every poll until the grant is deployed --
    # nothing committed, so the id was rediscovered from the provider on every
    # single poll and never actually stored.
    if not await ensure_principal(session, connection):
        return connection

    # Attempt validation if not yet verified
    if not connection.rbac_verified_at:
        check = await onboarding.probe(connection)
        if check.ok:
            connection.status = CloudAccountStatus.ACTIVE
            connection.rbac_verified_at = datetime.now(UTC)
            connection.status_detail = "Connection verified."
            _record_single_grant(connection, onboarding, check)
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

    # A grant believed to be behind is re-read on each detail request, so a
    # customer who redeploys and comes back to the page finds the banner gone
    # without having to press anything. Costs one listing, and only while the
    # connection is behind: once the current grant is recorded, nothing here
    # asks again.
    if grant_upgrade_available(connection):
        await refresh_grant_version(session, connection)

    return connection


async def _auto_discover(
    session: AsyncSession, connection: CloudConnection
) -> list[CloudAccount]:
    """Write what the provider says is beneath this connection's scope.

    The provider answers *what exists*; everything below decides what that means
    for rows CloudGuard already holds -- which is neutral, and stayed here when
    the listing itself moved behind the seam.
    """
    found = await flow(connection).discover(connection)

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

    for discovered in found:
        account = existing.get(discovered.account_id)
        if account is None:
            account = CloudAccount(
                organization_id=connection.organization_id,
                connection_id=connection.id,
                provider=connection.provider,
                account_name=discovered.display_name,
                display_name=discovered.display_name,
                tenant_id=connection.tenant_id or "",
                subscription_id=discovered.account_id,
                provider_ref=dict(discovered.provider_ref),
                discovered_at=now,
                in_scope=True,
            )
            session.add(account)
        else:
            account.display_name = discovered.display_name
            if discovered.provider_ref:
                account.provider_ref = dict(discovered.provider_ref)

        account.consent_status = connection.consent_status
        account.rbac_verified_at = connection.rbac_verified_at
        account.status = (
            CloudAccountStatus.ACTIVE if account.in_scope else CloudAccountStatus.DISABLED
        )
        accounts.append(account)

    # Disable accounts that have vanished
    seen = {a.subscription_id for a in accounts}
    for account_id, account in existing.items():
        if account_id not in seen:
            account.status = CloudAccountStatus.DISABLED
            account.status_detail = "No longer visible to this connection"

    # Only stamped when something was actually found. ``try_auto_validate``
    # treats this column as "discovery is done", so latching it on an empty
    # result freezes the connection with no accounts for good. An empty listing
    # right after a grant is deployed is not an answer -- a provider's account
    # list is eventually consistent and takes minutes to catch up with a fresh
    # assignment.
    if accounts:
        connection.last_discovery_at = now
    else:
        log.warning(
            "connection.discovery_found_nothing",
            connection_id=str(connection.id),
            tenant_id=connection.tenant_id,
        )
    # Flush before returning, not only commit. ``commit_unless_externally_managed``
    # does nothing inside a request -- ``rls_session`` owns that transaction --
    # so a freshly discovered account went back to the caller with no primary
    # key, and serializing it raised a 500 on the one endpoint whose job is to
    # recover a connection that has none. The flush assigns the ids without
    # ending the transaction, which matters: RLS settings here are
    # transaction-scoped, and a commit would tear them down.
    await session.flush()
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
            "discover with. Finish granting CloudGuard read access first."
        )

    accounts = await _auto_discover(session, connection)
    if not accounts:
        raise ValidationFailed(
            "CloudGuard could not see any accounts with this connection. Check "
            "that the grant is in place at the scope you deployed it to, and "
            "that the accounts sit beneath it. A grant made moments ago can "
            "take a few minutes to appear."
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
            chosen = in_scope[account.subscription_id]
            # Stamped only when the answer actually changes. A screen that
            # re-sends every row it displayed would otherwise move the date on
            # subscriptions nobody touched, and the date is there precisely to
            # say when somebody last made a decision about this one.
            if chosen != account.in_scope:
                account.scope_changed_at = datetime.now(UTC)
            account.in_scope = chosen
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
        onboarding = flow(connection)
        connection.status_detail = (
            onboarding.ready_to_deploy_detail
            if connection.consent_status == ConsentStatus.GRANTED
            else onboarding.initial_status_detail
        )

    await commit_unless_externally_managed(session)
    return connection


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


def revocation_steps(connection: CloudConnection) -> dict:
    """What the customer must run to take CloudGuard's access away.

    CloudGuard cannot do this itself in any cloud, and that is a design decision
    rather than a gap: revoking its own access needs write permissions on the
    two most sensitive surfaces a tenant has, which are far more dangerous than
    the read access they would withdraw. So the commands are generated instead,
    filled in for this connection, and :func:`check_access_revoked` proves
    afterwards whether they worked.
    """
    return flow(connection).revocation_steps(connection)


async def check_access_revoked(connection: CloudConnection) -> dict:
    """Ask the provider whether CloudGuard can still read this environment.

    The one honest confirmation available: revocation is verified by the access
    failing, using the same read-only probe that verified it working. A product
    that said "revoked" because a button was pressed would be asserting
    something it had not checked -- the same move this codebase refuses
    everywhere else.
    """
    if not connection.tenant_id:
        return {"revoked": True, "detail": "No directory is bound to this connection."}

    check = await flow(connection).probe(connection)
    if check.ok:
        return {
            "revoked": False,
            "detail": (
                "CloudGuard can still read this environment. The grant is in "
                "place; a provider can take a minute to apply a removal."
            ),
        }
    return {
        "revoked": True,
        "detail": "Confirmed: CloudGuard can no longer read this environment.",
    }


def event_webhook_token(connection: CloudConnection) -> str:
    """The signed token that opens this connection's webhook, and no other's.

    Signed with the same secret as the template token and separated from it by
    ``purpose`` alone -- which is why the webhook checks that field rather than
    trusting the signature to mean what it hopes.
    """
    return sign_state(
        {
            "cloud_connection_id": str(connection.id),
            "purpose": "event_grid",
            "issued_at": time.time(),
        }
    )


def event_webhook_url(connection: CloudConnection) -> str | None:
    """Where the customer's Event Grid subscription should deliver."""
    base = public_api_base()
    if not base:
        return None
    token = event_webhook_token(connection)
    return f"{base}/api/v1/events/azure/{connection.id}?token={token}"


async def set_change_events(
    session: AsyncSession,
    tenant: TenantContext,
    connection_id: UUID,
    enabled: bool,
) -> CloudConnection:
    """Turn change-triggered scanning on or off for this connection.

    Turning it *on* here does not wire anything up. It cannot: creating an
    Event Grid subscription is a write in the customer's tenant, and CloudGuard
    holds no write permission anywhere -- which is the strongest security claim
    this product makes and not one to spend on a convenience. What this does is
    open the webhook and hand back the command; the customer runs it.

    Turning it *off* closes the webhook immediately, before the customer has
    deleted anything in Azure. Their subscription will keep delivering to an
    endpoint that now refuses it, which is the right way round: the alternative
    is a switch that appears to stop something and does not.
    """
    connection = await get_connection(session, tenant, connection_id)

    if enabled and not connection.is_verified:
        raise ValidationFailed(
            "This connection is not ready to scan yet, so a change in it could "
            "not be read. Finish granting CloudGuard read access first."
        )

    connection.change_events_enabled = enabled
    if not enabled:
        # A burst nobody will now act on. Left set, it would start a scan the
        # moment somebody switched this back on, reporting a change from
        # whenever it happened to have been.
        connection.change_pending_since = None

    await findings_service.record_audit(
        session,
        tenant,
        action="connection.change_events",
        resource_type="cloud_connection",
        resource_id=connection.id,
        metadata={"enabled": enabled},
    )
    # Not ``session.commit()``. A request session is ``rls_session``, which owns
    # its transaction -- and ``SET LOCAL ROLE authenticated`` and the JWT claims
    # are transaction-scoped, so committing here tears them down. Every other
    # write in this file already goes through the helper; this one did not, and
    # it is the only one with a statement still to run afterwards: the route
    # calls ``change_event_setup`` next, which reads the subscriptions to build
    # the wiring commands. That read then ran as the bare ``cloudguard_app``
    # role with no claims, and the request died where nothing had gone wrong.
    #
    # Turning the feature *off* hid it, because the commands are not built in
    # that direction and no statement followed the commit.
    await commit_unless_externally_managed(session)
    return connection


async def change_event_setup(
    session: AsyncSession, connection: CloudConnection
) -> dict:
    """What the customer needs to wire their subscriptions up, per subscription.

    One command per subscription rather than one for the tenant, because that is
    how Event Grid is scoped: a system topic exists on a subscription, and a
    connection covering twelve of them needs twelve subscriptions to it.
    """
    url = event_webhook_url(connection)
    return {
        "enabled": connection.change_events_enabled,
        "webhook_url": url,
        "pending_since": (
            connection.change_pending_since.isoformat()
            if connection.change_pending_since
            else None
        ),
        "last_event_at": (
            connection.last_change_event_at.isoformat()
            if connection.last_change_event_at
            else None
        ),
        "quiet_period_minutes": int(
            change_events.QUIET_PERIOD.total_seconds() // 60
        ),
        "minimum_interval_minutes": int(
            change_events.MIN_INTERVAL.total_seconds() // 60
        ),
        # Nothing to run until the webhook is open. Handing over a command whose
        # endpoint answers 400 would have the customer debugging CloudGuard's
        # configuration rather than their own.
        "commands": [
            {
                "subscription_id": account.subscription_id,
                "command": change_events.event_subscription_command(
                    account.subscription_id, url
                ),
            }
            for account in await _scannable_accounts(session, connection)
            if account.subscription_id
        ]
        if url and connection.change_events_enabled
        else [],
    }


async def _scannable_accounts(
    session: AsyncSession, connection: CloudConnection
) -> list[CloudAccount]:
    """The subscriptions under this connection a scan could actually read.

    ``is_scannable`` is a property over four columns rather than a column, so it
    is applied here rather than in the query -- the same way every other scope
    resolution in this codebase does it.
    """
    rows = (
        (
            await session.execute(
                select(CloudAccount)
                .where(
                    CloudAccount.organization_id == connection.organization_id,
                    CloudAccount.connection_id == connection.id,
                )
                .order_by(CloudAccount.subscription_id)
            )
        )
        .scalars()
        .all()
    )
    return [account for account in rows if account.is_scannable]


def available_providers() -> list[dict]:
    """Which clouds this deployment can actually connect, and why not.

    Answered by the API rather than hard-coded in the wizard, because the
    answer is a property of the deployment: an installation with no Entra app
    registration cannot start a consent flow, and one that has not run the AWS
    verification checklist must not be offering AWS at all.

    Unavailable providers are returned rather than omitted. A picker that
    silently held one option answers "does this product support AWS?" with
    nothing; one that shows it greyed out with a reason answers it.
    """
    return [
        {
            "id": Provider.AZURE.value,
            "name": "Microsoft Azure",
            "available": settings.azure_consent_ready,
            "unavailable_reason": settings.azure_consent_problem,
        },
        {
            "id": Provider.AWS.value,
            "name": "Amazon Web Services",
            "available": settings.aws_offered,
            "unavailable_reason": _aws_problem(),
        },
    ]


def _aws_problem() -> str | None:
    """Why AWS cannot be chosen here, in the order a reader can act on.

    The second reason is the honest one and is not a configuration error: the
    connector has never been run against a live account, and until
    ``docs/AWS_INTEGRATION.md`` section 1 has been completed, offering it would
    be claiming to scan a cloud nobody has scanned.
    """
    if not settings.aws_configured:
        return (
            "CloudGuard has no AWS identity on this deployment. Set "
            "AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_PRINCIPAL_ARN "
            "(docs/AWS_INTEGRATION.md §2)."
        )
    if not settings.aws_enabled:
        return (
            "AWS support is built but has not been verified against a live "
            "account yet. Complete the checklist in docs/AWS_INTEGRATION.md §1, "
            "then set AWS_ENABLED=true."
        )
    return None


def self_registration(provider: Provider) -> dict | None:
    """What CloudGuard's *own* identity in a cloud must declare.

    The half of the deployment no customer artefact can touch: Azure's
    application permissions live on CloudGuard's app registration, not on
    anything a template creates in the customer's tenant. That half had only
    ever existed as a list in a code comment, which is why a registration
    missing seven of nine permissions still produced a consent screen that
    looked entirely normal.

    ``None`` for a provider with no such half.
    """
    return get_onboarding(provider).self_registration()
