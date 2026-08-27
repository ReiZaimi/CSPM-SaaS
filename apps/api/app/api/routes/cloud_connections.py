from uuid import UUID

from fastapi import APIRouter, Query, Request, status
from fastapi.responses import PlainTextResponse, RedirectResponse
from sqlalchemy import func, select

from app.connectors.azure.auth import ConsentStateError, verify_state
from app.connectors.azure.rbac import ARM_READ_ACTIONS, ARTIFACT_FORMATS
from app.core.config import settings
from app.core.db import service_session
from app.core.deps import DbSession, Tenant
from app.core.enums import Role
from app.core.errors import CloudAccountNotFound, envelope
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.schemas.cloud_account import ConsentLink, ValidationResult
from app.schemas.cloud_connection import (
    ArtifactLinks,
    CloudConnectionCreate,
    CloudConnectionOut,
    DiscoveredSubscription,
    ScopeSelection,
)
from app.services import cloud_connections as service

router = APIRouter(prefix="/cloud-connections", tags=["cloud-connections"])


def _serialize(connection: CloudConnection, subscription_count: int = 0) -> dict:
    data = CloudConnectionOut.model_validate(connection).model_dump(mode="json")
    data["is_verified"] = connection.is_verified
    data["scope_path"] = connection.scope_path
    data["subscription_count"] = subscription_count
    return data


def _serialize_subscription(account: CloudAccount) -> dict:
    data = DiscoveredSubscription.model_validate(account).model_dump(mode="json")
    data["is_scannable"] = account.is_scannable
    return data


@router.get("/options")
async def connection_options(tenant: Tenant) -> dict:
    """The choices the first screen offers, and what each one grants."""
    return envelope(service.connection_options())


# Literal paths are declared before the parameterised ones below. FastAPI
# matches routes in declaration order, so `/{connection_id}` would otherwise
# swallow `/artifact` -- and because that route carries the tenant dependency,
# the symptom is a 401 on a URL that is deliberately unauthenticated, from a
# customer's shell, with nothing in it that looks like an auth problem.


@router.get("/artifact", include_in_schema=False)
async def artifact(
    token: str = Query(default=""), format: str = Query(default="cli")
) -> PlainTextResponse:
    """Serve one deployment artifact.

    Unauthenticated by necessity: the customer's shell or IaC tooling fetches
    this, not the CloudGuard frontend. The signed token is what makes that safe,
    and nothing served here is secret -- it names a service principal the
    customer's own directory lists and a set of read permissions they are about
    to review.
    """
    try:
        payload = verify_state(token, max_age_seconds=service.ARTIFACT_TTL_SECONDS)
    except ConsentStateError as exc:
        return PlainTextResponse(f"# {exc}\n", status_code=400)

    if payload.get("purpose") != "artifact":
        return PlainTextResponse("# Invalid artifact token\n", status_code=400)

    connection_id = UUID(payload["cloud_connection_id"])
    async with service_session() as session:
        connection = await session.get(CloudConnection, connection_id)
        if connection is None:
            raise CloudAccountNotFound("Connection not found")
        content_type, filename, body = service.render_artifact(connection, format)

    return PlainTextResponse(
        body,
        media_type=content_type,
        headers={"Content-Disposition": f'inline; filename="{filename}"'},
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

    Unauthenticated by necessity -- Entra sends the browser, not our frontend.
    The signed ``state`` is what makes it trustworthy: it is the only reason
    this endpoint can believe which connection it is being told about. The
    ``tenant`` parameter is Entra's own statement of which directory consented,
    and it is the sole source of a connection's tenant id.
    """
    frontend = f"{settings.app_url}/connect/result"

    if error:
        return RedirectResponse(f"{frontend}?status=error&message={error_description or error}")

    try:
        payload = verify_state(state)
    except ConsentStateError as exc:
        return RedirectResponse(f"{frontend}?status=error&message={exc}")

    if admin_consent.lower() not in {"true", "1", ""}:
        return RedirectResponse(f"{frontend}?status=error&message=Admin+consent+was+not+granted")

    connection_id = UUID(payload["cloud_connection_id"])
    async with service_session() as session:
        await service.record_consent(session, connection_id, tenant, None)

    return RedirectResponse(f"{frontend}?status=granted&cloud_connection_id={connection_id}")


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_connection(
    payload: CloudConnectionCreate, session: DbSession, tenant: Tenant
) -> dict:
    tenant.require_role(Role.OWNER, Role.ADMIN)
    connection = await service.create_connection(session, tenant, payload)
    await session.commit()
    return envelope(_serialize(connection))


@router.get("")
async def list_connections(session: DbSession, tenant: Tenant) -> dict:
    rows = (
        (
            await session.execute(
                select(CloudConnection)
                .where(CloudConnection.organization_id == tenant.organization_id)
                .order_by(CloudConnection.created_at)
            )
        )
        .scalars()
        .all()
    )

    count_rows = (
        await session.execute(
            select(CloudAccount.connection_id, func.count())
            .where(CloudAccount.organization_id == tenant.organization_id)
            .group_by(CloudAccount.connection_id)
        )
    ).all()
    counts: dict[UUID, int] = {
        connection_id: int(count)
        for connection_id, count in count_rows
        if connection_id is not None
    }
    return envelope([_serialize(c, counts.get(c.id, 0)) for c in rows])


@router.get("/{connection_id}")
async def get_connection(connection_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    connection = await service.get_connection(session, tenant, connection_id)
    count = (
        await session.execute(
            select(func.count()).where(CloudAccount.connection_id == connection.id)
        )
    ).scalar_one()
    return envelope(_serialize(connection, int(count)))


@router.post("/{connection_id}/consent-url")
async def consent_url(connection_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    """The single link the customer's Global Administrator clicks."""
    tenant.require_role(Role.OWNER, Role.ADMIN)
    connection = await service.get_connection(session, tenant, connection_id)
    url, ttl = service.consent_url_for(connection)
    return envelope(
        ConsentLink(
            consent_url=url,
            expires_in_seconds=ttl,
            permissions=service.connection_options(),
        ).model_dump()
    )


@router.get("/{connection_id}/artifacts")
async def artifact_links(
    connection_id: UUID, request: Request, session: DbSession, tenant: Tenant
) -> dict:
    """Where to fetch each deployment format for this connection.

    The URLs themselves are unauthenticated and signed -- Cloud Shell, Terraform
    and the portal all fetch them without a CloudGuard session.
    """
    connection = await service.get_connection(session, tenant, connection_id)
    token = service.artifact_token(connection)
    base = str(request.base_url).rstrip("/")

    formats = {
        fmt: f"{base}/api/v1/cloud-connections/artifact?token={token}&format={fmt}"
        for fmt in ARTIFACT_FORMATS
    }
    return envelope(
        ArtifactLinks(
            formats=formats,
            expires_in_seconds=service.ARTIFACT_TTL_SECONDS,
            scope_path=connection.scope_path,
            principal_id=connection.service_principal_object_id,
            permission_mode=connection.permission_mode,
            arm_actions=list(ARM_READ_ACTIONS),
            # Opens Cloud Shell already signed in as the customer, where `az` is
            # present and no local install is needed.
            cloud_shell_url="https://shell.azure.com/bash",
        ).model_dump()
    )


@router.post("/{connection_id}/validate")
async def validate_connection(connection_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    """Verify both grants by actually calling Azure."""
    tenant.require_write()
    check = await service.validate_connection(session, tenant, connection_id)
    return envelope(
        ValidationResult(
            ok=check.ok,
            detail=check.detail,
            permissions_verified=check.permissions_verified,
            problems=check.problems,
            subscription_id=check.subscription_id,
        ).model_dump()
    )


@router.post("/{connection_id}/discover")
async def discover(connection_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    """Find every subscription this connection's grant can see."""
    tenant.require_write()
    accounts = await service.discover_subscriptions(session, tenant, connection_id)
    return envelope([_serialize_subscription(a) for a in accounts])


@router.get("/{connection_id}/subscriptions")
async def list_subscriptions(connection_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    connection = await service.get_connection(session, tenant, connection_id)
    rows = (
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
    return envelope([_serialize_subscription(a) for a in rows])


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
