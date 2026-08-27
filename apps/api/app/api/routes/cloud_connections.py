import json
from uuid import UUID

from fastapi import APIRouter, Query, status
from fastapi.responses import JSONResponse, RedirectResponse

from app.connectors.azure.auth import ConsentStateError, verify_state
from app.core.config import settings
from app.core.db import service_session
from app.core.deps import DbSession, Tenant
from app.core.enums import ConsentStatus, Role
from app.core.errors import CloudAccountNotFound, envelope
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.schemas.cloud_connection import (
    CloudConnectionCreate,
    CloudConnectionOut,
    DiscoveredSubscription,
    ScopeSelection,
)
from app.services import cloud_connections as service

router = APIRouter(prefix="/cloud-connections", tags=["cloud-connections"])


def _serialize(
    connection: CloudConnection,
    subscription_count: int = 0,
    subscriptions: list[CloudAccount] | None = None,
    consent_url: str | None = None,
) -> dict:
    data = CloudConnectionOut.model_validate(connection).model_dump(mode="json")
    data["is_verified"] = connection.is_verified
    data["scope_path"] = connection.scope_path
    data["subscription_count"] = subscription_count
    data["template_url"] = service.deploy_to_azure_url(connection)

    # Regenerated on every read, not just on create. Returning it only from the
    # create response meant a page reload lost the consent button and left the
    # connection stuck in PENDING with no route forward. The signed state also
    # expires in 30 minutes, so a stored one would usually be dead anyway.
    if connection.consent_status != ConsentStatus.GRANTED:
        fresh, problem = service.consent_url_for(connection)
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

    Unauthenticated — Azure Portal fetches this server-side. The signed token
    is what makes it safe.
    """
    try:
        payload = verify_state(token, max_age_seconds=service.TEMPLATE_TOKEN_TTL_SECONDS)
    except ConsentStateError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    if payload.get("purpose") != "template":
        return JSONResponse({"error": "Invalid template token"}, status_code=400)

    if str(connection_id) != payload.get("cloud_connection_id"):
        return JSONResponse({"error": "Token does not match connection"}, status_code=400)

    async with service_session() as session:
        connection = await session.get(CloudConnection, connection_id)
        if connection is None:
            raise CloudAccountNotFound("Connection not found")
        body = service.render_template(connection)

    return JSONResponse(
        content=json.loads(body),
        media_type="application/json",
        headers={"Content-Disposition": 'inline; filename="cloudguard-scanner.json"'},
    )


@router.get("/azure/consent/callback", include_in_schema=False)
async def consent_callback(
    state: str = Query(default=""),
    tenant: str = Query(default=""),
    admin_consent: str = Query(default=""),
    error: str = Query(default=""),
    error_description: str = Query(default=""),
) -> RedirectResponse:
    """Entra redirects the customer's browser here after admin consent.

    Redirects to the Connect page with the connection ID as a query param.
    """
    frontend = settings.app_url.rstrip("/")

    if error:
        return RedirectResponse(
            f"{frontend}/connections?consent_error={error_description or error}"
        )

    try:
        payload = verify_state(state)
    except ConsentStateError as exc:
        return RedirectResponse(f"{frontend}/connections?consent_error={exc}")

    if admin_consent.lower() not in {"true", "1", ""}:
        return RedirectResponse(
            f"{frontend}/connections?consent_error=Admin+consent+was+not+granted"
        )

    connection_id = UUID(payload["cloud_connection_id"])
    async with service_session() as session:
        await service.record_consent(session, connection_id, tenant)

    return RedirectResponse(f"{frontend}/connections?id={connection_id}")


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
    return envelope([_serialize(c, sub_count) for c, sub_count in rows])


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


@router.delete("/{connection_id}", status_code=status.HTTP_200_OK)
async def delete_connection(connection_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    tenant.require_role(Role.OWNER, Role.ADMIN)
    connection = await service.get_connection(session, tenant, connection_id)
    await session.delete(connection)
    await session.commit()
    return envelope({"deleted": str(connection_id)})
