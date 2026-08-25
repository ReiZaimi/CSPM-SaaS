from uuid import UUID

from fastapi import APIRouter, Query, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from app.connectors.azure.auth import ConsentStateError, verify_state
from app.core.config import settings
from app.core.db import service_session
from app.core.deps import DbSession, Tenant
from app.core.enums import Role
from app.core.errors import envelope
from app.models.cloud_account import CloudAccount
from app.schemas.cloud_account import (
    CloudAccountCreate,
    CloudAccountOut,
    ConsentLink,
    ValidationResult,
)
from app.services import cloud_accounts as service

router = APIRouter(prefix="/cloud-accounts", tags=["cloud-accounts"])


def _serialize(account: CloudAccount) -> dict:
    data = CloudAccountOut.model_validate(account).model_dump(mode="json")
    data["is_scannable"] = account.is_scannable
    return data


@router.get("/azure/permissions")
async def azure_permissions() -> dict:
    """What CloudGuard will be able to see, shown before anyone consents."""
    return envelope(service.required_permissions())


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_cloud_account(
    payload: CloudAccountCreate, session: DbSession, tenant: Tenant
) -> dict:
    tenant.require_role(Role.OWNER, Role.ADMIN)
    account = await service.create_cloud_account(session, tenant, payload)
    await session.commit()
    return envelope(_serialize(account))


@router.get("")
async def list_cloud_accounts(session: DbSession, tenant: Tenant) -> dict:
    rows = (
        (
            await session.execute(
                select(CloudAccount)
                .where(CloudAccount.organization_id == tenant.organization_id)
                .order_by(CloudAccount.created_at)
            )
        )
        .scalars()
        .all()
    )
    return envelope([_serialize(a) for a in rows])


@router.get("/{account_id}")
async def get_cloud_account(account_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    account = await service.get_cloud_account(session, tenant, account_id)
    return envelope(_serialize(account))


@router.post("/{account_id}/consent-url")
async def consent_url(account_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    """The single link the customer's Global Administrator clicks."""
    tenant.require_role(Role.OWNER, Role.ADMIN)
    account = await service.get_cloud_account(session, tenant, account_id)
    url, ttl = service.consent_url_for(account)
    return envelope(
        ConsentLink(
            consent_url=url,
            expires_in_seconds=ttl,
            permissions=service.required_permissions(),
        ).model_dump()
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
    this endpoint can believe which cloud account it is being told about. Writes
    use the service connection because there is no authenticated user here, and
    the account id comes from the verified state rather than a query parameter.
    """
    frontend = f"{settings.app_url}/connect/result"

    if error:
        return RedirectResponse(
            f"{frontend}?status=error&message={error_description or error}"
        )

    try:
        payload = verify_state(state)
    except ConsentStateError as exc:
        return RedirectResponse(f"{frontend}?status=error&message={exc}")

    if admin_consent.lower() not in {"true", "1", ""}:
        return RedirectResponse(
            f"{frontend}?status=error&message=Admin+consent+was+not+granted"
        )

    account_id = UUID(payload["cloud_account_id"])
    async with service_session() as session:
        await service.record_consent(session, account_id, tenant, None)

    return RedirectResponse(f"{frontend}?status=granted&cloud_account_id={account_id}")


@router.post("/{account_id}/validate")
async def validate_cloud_account(
    account_id: UUID, session: DbSession, tenant: Tenant
) -> dict:
    """Verify read access by actually calling Azure."""
    tenant.require_write()
    check = await service.validate_cloud_account(session, tenant, account_id)
    return envelope(
        ValidationResult(
            ok=check.ok,
            detail=check.detail,
            permissions_verified=check.permissions_verified,
            problems=check.problems,
            subscription_id=check.subscription_id,
        ).model_dump()
    )


@router.delete("/{account_id}", status_code=status.HTTP_200_OK)
async def delete_cloud_account(
    account_id: UUID, session: DbSession, tenant: Tenant
) -> dict:
    tenant.require_role(Role.OWNER, Role.ADMIN)
    account = await service.get_cloud_account(session, tenant, account_id)
    await session.delete(account)
    await session.commit()
    return envelope({"deleted": str(account_id)})
