from uuid import UUID

from fastapi import APIRouter
from sqlalchemy import select

from app.core.deps import DbSession, Tenant
from app.core.errors import envelope
from app.models.cloud_account import CloudAccount
from app.schemas.cloud_account import CloudAccountOut
from app.services import cloud_accounts as service

router = APIRouter(prefix="/cloud-accounts", tags=["cloud-accounts"])

# Read-only on purpose. A cloud account is no longer something a customer
# registers -- it is a subscription *discovered* beneath a cloud connection
# (app/services/cloud_connections.py), so there is nothing here to create,
# consent to, or validate. Those endpoints moved to /cloud-connections, and
# removing rather than keeping them is deliberate: the create path accepted a
# tenant id from the request body, and validation checked only whether Azure
# answered. Since CloudGuard's service principal exists in every tenant that
# ever consented, that combination let one organization name another's tenant
# and verify successfully against an environment it had no claim to.
#
# Scoping a discovered subscription in or out is a PATCH on the connection that
# found it, not a delete here -- a deleted row would simply come back on the
# next discovery run.


def _serialize(account: CloudAccount) -> dict:
    data = CloudAccountOut.model_validate(account).model_dump(mode="json")
    data["is_scannable"] = account.is_scannable
    return data


@router.get("/azure/permissions")
async def azure_permissions() -> dict:
    """What CloudGuard will be able to see, shown before anyone consents."""
    return envelope(service.required_permissions())


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
