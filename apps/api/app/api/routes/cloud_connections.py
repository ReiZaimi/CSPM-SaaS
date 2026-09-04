import json
from urllib.parse import quote
from uuid import UUID

from fastapi import APIRouter, Query, status
from fastapi.responses import JSONResponse, RedirectResponse

from app.core.config import settings
from app.core.db import service_session
from app.core.deps import DbSession, Tenant
from app.core.enums import ConsentStatus, Provider, Role
from app.core.errors import CloudAccountNotFound, envelope
from app.core.signing import SignedStateError, verify_state
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.schemas.cloud_connection import (
    ChangeEventsUpdate,
    CloudConnectionCreate,
    CloudConnectionOut,
    DiscoveredSubscription,
    ScheduleUpdate,
    ScopeSelection,
)
from app.services import cloud_connections as service

router = APIRouter(prefix="/cloud-connections", tags=["cloud-connections"])

# Applied to the ARM template endpoint only, not to the API at large. The
# global CORS policy names this product's own frontend; Azure Portal is a
# third-party origin fetching one deliberately public, token-gated document.
TEMPLATE_CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Cache-Control": "no-store",
}


def _serialize(
    connection: CloudConnection,
    subscription_count: int = 0,
    subscriptions: list[CloudAccount] | None = None,
    consent_url: str | None = None,
) -> dict:
    data = CloudConnectionOut.model_validate(connection).model_dump(mode="json")
    data["is_verified"] = connection.is_verified
    data["scope_path"] = service.scope_path(connection)
    data["subscription_count"] = subscription_count
    data["template_url"] = service.deployment_url(connection)
    # Lets the card stop showing a spinner once waiting has stopped being a
    # plausible explanation for the silence.
    data["deploy_stalled"] = service.deploy_stalled(connection)
    data["role_upgrade_available"] = service.grant_upgrade_available(connection)
    # What to redeploy to, and what is lost until they do. The boolean above
    # says a newer role exists; on its own it can only produce "something is
    # out of date", which is a notification rather than a decision. These two
    # turn it into a sentence a customer can act on -- "database and secrets
    # checks report UNKNOWN until you redeploy" -- and the categories come from
    # the same function the scanner uses to explain the gaps, so the screen and
    # the scan cannot disagree about which checks are affected.
    data["role_required_version"] = service.required_grant_version(connection)
    data["degraded_categories"] = sorted(
        category.value for category in service.degraded_categories(connection)
    )
    # Both grants proven is not the same as having something to scan, and the
    # card said "Ready to scan: Yes" over an empty connection because it read
    # ``is_verified``. Readiness needs a subscription CloudGuard can actually
    # look at. Only meaningful when the caller passed the subscriptions in;
    # endpoints that do not are reporting on a connection mid-setup.
    data["is_ready_to_scan"] = connection.is_verified and any(
        a.is_scannable for a in (subscriptions or [])
    )
    # Whether this environment reports its own changes, and when it last did.
    # Sent with the connection rather than left to the change-events endpoint:
    # the list states how often each environment is read, and a clock is only
    # half of that answer -- fetching the other half would be one request per
    # row to render one line. Coerced, because a connection built in memory has
    # not had the column default applied.
    data["change_events_enabled"] = bool(connection.change_events_enabled)
    data["last_change_event_at"] = (
        connection.last_change_event_at.isoformat()
        if connection.last_change_event_at
        else None
    )

    # Regenerated on every read, not just on create. Returning it only from the
    # create response meant a page reload lost the consent button and left the
    # connection stuck in PENDING with no route forward. The signed state also
    # expires in 30 minutes, so a stored one would usually be dead anyway.
    if connection.consent_status != ConsentStatus.GRANTED:
        fresh, problem = service.grant_start_url(connection)
        consent_url = consent_url or fresh
        if problem:
            data["status_detail"] = problem
    if consent_url:
        data["consent_url"] = consent_url
    if subscriptions is not None:
        data["subscriptions"] = [_serialize_subscription(a) for a in subscriptions]
    return data


def _serialize_subscription(account: CloudAccount) -> dict:
    data = DiscoveredSubscription.model_validate(account).model_dump(mode="json")
    data["is_scannable"] = account.is_scannable
    return data


# Literal paths before parameterised ones — FastAPI matches in declaration
# order, so `/{connection_id}` would otherwise swallow these.


@router.get("/{connection_id}/template", include_in_schema=False)
async def arm_template(
    connection_id: UUID, token: str = Query(default="")
) -> JSONResponse:
    """Serve the ARM template for the Deploy to Azure button.

    Unauthenticated, and readable from any origin. Both are requirements rather
    than conveniences.

    Azure Portal fetches this **from the customer's browser**, not server-side,
    so the response needs CORS headers naming an origin CloudGuard does not
    control and cannot enumerate (portal.azure.com has regional and sovereign
    variants). Without them the portal reports only "There was an error
    downloading the template ... ensure the template is publicly accessible and
    that the publisher has enabled CORS policy on the endpoint" -- which reads
    as an outage, while the endpoint answers 200 to anything that is not a
    browser.

    A wildcard is safe here specifically. Nothing served is secret: the template
    names a service principal object id the customer's own directory already
    lists, and a set of read permissions they are about to review in the portal.
    Access is gated by the HMAC-signed, time-limited token in the query string,
    not by the origin of the request -- so allowing every origin gives away
    nothing that the token does not already control.
    """
    try:
        payload = verify_state(token, max_age_seconds=service.TEMPLATE_TOKEN_TTL_SECONDS)
    except SignedStateError as exc:
        return JSONResponse(
            {"error": str(exc)}, status_code=400, headers=TEMPLATE_CORS_HEADERS
        )

    if payload.get("purpose") != "template":
        return JSONResponse(
            {"error": "Invalid template token"},
            status_code=400,
            headers=TEMPLATE_CORS_HEADERS,
        )

    if str(connection_id) != payload.get("cloud_connection_id"):
        return JSONResponse(
            {"error": "Token does not match connection"},
            status_code=400,
            headers=TEMPLATE_CORS_HEADERS,
        )

    async with service_session() as session:
        connection = await session.get(CloudConnection, connection_id)
        if connection is None:
            raise CloudAccountNotFound("Connection not found")
        artifact = service.render_artifact(connection)

    return JSONResponse(
        content=json.loads(artifact.body),
        media_type=artifact.media_type,
        headers={
            "Content-Disposition": f'inline; filename="{artifact.filename}"',
            **TEMPLATE_CORS_HEADERS,
        },
    )


@router.get("/azure/app-registration")
async def app_registration(tenant: Tenant) -> dict:
    """What CloudGuard's own Entra app registration must declare.

    The other half of the deployment. The ARM template grants subscription
    access in the *customer's* tenant; directory access comes from application
    permissions on CloudGuard's registration in its own tenant, which no
    template a customer runs can touch. That half has only ever existed as a
    list in a code comment, which is why a registration missing seven of nine
    permissions still produced a consent screen that looked entirely normal.

    Returned as the manifest fragment plus the command that applies it, so the
    registration can be diffed against what is deployed instead of inspected by
    eye in a portal.
    """
    tenant.require_role(Role.OWNER, Role.ADMIN)
    return envelope(service.self_registration(Provider.AZURE) or {})


@router.get("/azure/consent/callback", include_in_schema=False)
async def consent_callback(
    state: str = Query(default=""),
    tenant: str = Query(default=""),
    admin_consent: str = Query(default=""),
    error: str = Query(default=""),
    error_description: str = Query(default=""),
) -> RedirectResponse:
    """Entra redirects the customer's browser here after admin consent.

    Redirects into the setup wizard for this connection, which is where the
    customer left off. Failures land on the same page rather than on the
    connections list: the state parameter comes back on a denial too, so the
    reason can be shown against the step it belongs to, next to the button that
    starts consent again.

    The list is the fallback for the one case where there is no connection to
    return to -- a state that is missing, tampered with, or expired.
    """
    frontend = settings.app_url.rstrip("/")

    try:
        payload = verify_state(state)
    except SignedStateError as exc:
        reason = error_description or error or str(exc)
        return RedirectResponse(
            f"{frontend}/connections?consent_error={quote(reason)}"
        )

    connection_id = UUID(payload["cloud_connection_id"])
    setup = f"{frontend}/connections/{connection_id}/setup"

    if error:
        return RedirectResponse(
            f"{setup}?consent_error={quote(error_description or error)}"
        )

    if admin_consent.lower() not in {"true", "1", ""}:
        return RedirectResponse(
            f"{setup}?consent_error={quote('Admin consent was not granted')}"
        )

    async with service_session() as session:
        await service.record_consent(session, connection_id, tenant)

    return RedirectResponse(setup)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_connection(
    payload: CloudConnectionCreate, session: DbSession, tenant: Tenant
) -> dict:
    """Create a connection and return it with the consent redirect URL."""
    tenant.require_role(Role.OWNER, Role.ADMIN)
    connection, consent_url = await service.create_connection(session, tenant, payload)
    await session.commit()
    return envelope(_serialize(connection, consent_url=consent_url))


@router.get("")
async def list_connections(session: DbSession, tenant: Tenant) -> dict:
    rows = await service.list_connections(session, tenant)
    return envelope(
        [_serialize(c, len(subs), subs) for c, subs in rows]
    )


@router.get("/{connection_id}")
async def get_connection(connection_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    """Get a connection with subscriptions. Triggers auto-validation if needed."""
    connection, subscriptions = await service.get_connection_with_subscriptions(
        session, tenant, connection_id
    )
    # Auto-validate during polling — silent failures mean "not deployed yet"
    connection = await service.try_auto_validate(session, connection)
    # Re-fetch subscriptions in case auto-discover just ran
    if connection.last_discovery_at:
        _, subscriptions = await service.get_connection_with_subscriptions(
            session, tenant, connection_id
        )
    return envelope(_serialize(connection, len(subscriptions), subscriptions))


@router.post("/{connection_id}/discover")
async def rediscover(connection_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    """Look for subscriptions again.

    Discovery normally runs by itself, once, while the connections page polls.
    That leaves no way back from the case where verification succeeded and the
    discovery call immediately after it did not: the page stops polling a
    verified connection, so nothing ever asks again. This is the ask-again.
    """
    tenant.require_write()
    connection, subscriptions = await service.rediscover_subscriptions(
        session, tenant, connection_id
    )
    return envelope(_serialize(connection, len(subscriptions), subscriptions))


@router.post("/{connection_id}/recheck")
async def recheck_access(connection_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    """Ask Azure again what this connection is allowed to do.

    A real probe, which is what the access panel's button has always said it
    was. The GET only validates a connection that is not verified yet, so on a
    working connection re-checking read the same row back -- and the role
    version on it had not been looked at since the connection was created.
    """
    tenant.require_write()
    connection, subscriptions = await service.recheck_access(
        session, tenant, connection_id
    )
    return envelope(_serialize(connection, len(subscriptions), subscriptions))


@router.patch("/{connection_id}/subscriptions")
async def set_scope(
    connection_id: UUID, payload: ScopeSelection, session: DbSession, tenant: Tenant
) -> dict:
    """Include or exclude discovered subscriptions from scanning."""
    tenant.require_write()
    accounts = await service.set_subscription_scope(
        session, tenant, connection_id, payload.in_scope
    )
    return envelope([_serialize_subscription(a) for a in accounts])


@router.patch("/{connection_id}/schedule")
async def set_schedule(
    connection_id: UUID, payload: ScheduleUpdate, session: DbSession, tenant: Tenant
) -> dict:
    """Read this environment on a schedule, or stop.

    Every connection starts unscheduled. Turning a customer's cloud into a
    recurring API cost without being asked would be a surprise on their Azure
    bill as much as on ours, so continuous scanning is something they switch on
    rather than something they discover.
    """
    tenant.require_write()
    connection = await service.set_scan_schedule(
        session, tenant, connection_id, payload.scan_interval_hours
    )
    return envelope(_serialize(connection))


@router.get("/{connection_id}/change-events")
async def get_change_events(
    connection_id: UUID, session: DbSession, tenant: Tenant
) -> dict:
    """Whether this connection reacts to change, and how to wire it up.

    The commands are the deliverable. CloudGuard cannot create the Event Grid
    subscription itself -- that is a write in the customer's tenant, and holding
    no write permission anywhere is the strongest security claim this product
    makes -- so it generates what the customer runs, one per subscription,
    because that is how Event Grid is scoped.
    """
    connection = await service.get_connection(session, tenant, connection_id)
    return envelope(await service.change_event_setup(session, connection))


@router.patch("/{connection_id}/change-events")
async def set_change_events(
    connection_id: UUID, payload: ChangeEventsUpdate, session: DbSession, tenant: Tenant
) -> dict:
    """Open or close the webhook for this connection.

    Opening it wires nothing up on its own; closing it takes effect at once,
    before the customer has deleted anything in Azure. That is the right way
    round -- a switch that appears to stop something and does not is worse than
    one that leaves a subscription delivering to an endpoint now refusing it.
    """
    tenant.require_write()
    connection = await service.set_change_events(
        session, tenant, connection_id, payload.enabled
    )
    return envelope(await service.change_event_setup(session, connection))


@router.post("/{connection_id}/cancel")
async def cancel_setup(connection_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    """Stop the setup process without discarding the connection."""
    tenant.require_write()
    connection = await service.set_setup_cancelled(
        session, tenant, connection_id, cancelled=True
    )
    return envelope(_serialize(connection))


@router.post("/{connection_id}/resume")
async def resume_setup(connection_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    """Pick setup back up where it was left."""
    tenant.require_write()
    connection = await service.set_setup_cancelled(
        session, tenant, connection_id, cancelled=False
    )
    return envelope(_serialize(connection))


@router.get("/{connection_id}/revocation")
async def revocation(connection_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    """What to run in Azure to take CloudGuard's access away.

    Generated rather than performed: CloudGuard has no write permission in a
    customer tenant and deliberately never asks for one, so revocation is the
    customer's action. See ``service.revocation_steps``.
    """
    connection = await service.get_connection(session, tenant, connection_id)
    return envelope(service.revocation_steps(connection))


@router.post("/{connection_id}/check-revoked")
async def check_revoked(connection_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    """Confirm by trying: revocation is verified by the access failing."""
    tenant.require_write()
    connection = await service.get_connection(session, tenant, connection_id)
    return envelope(await service.check_access_revoked(connection))


@router.delete("/{connection_id}", status_code=status.HTTP_200_OK)
async def delete_connection(connection_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    tenant.require_role(Role.OWNER, Role.ADMIN)
    connection = await service.get_connection(session, tenant, connection_id)
    await session.delete(connection)
    await session.commit()
    return envelope({"deleted": str(connection_id)})
