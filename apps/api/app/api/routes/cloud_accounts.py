from uuid import UUID

from fastapi import APIRouter
from sqlalchemy import select

from app.core.deps import DbSession, Tenant
from app.core.errors import envelope
from app.models.cloud_account import CloudAccount
from app.schemas.cloud_account import CloudAccountOut
from app.schemas.context import ContextDeclarationIn, ContextDeclarationOut
from app.services import cloud_accounts as service
from app.services import context as context_service

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


# --- what the customer says about a subscription ---------------------------
# The one write path here, on an otherwise read-only router, and the exception
# is principled: everything else about a cloud account is a record of what
# Azure said, while a declaration is a record of what a person said. A customer
# marking a subscription "production" beats any amount of tag inference, and
# there was previously nowhere to put the answer.


def _declaration(record: object | None) -> dict | None:
    if record is None:
        return None
    return ContextDeclarationOut.model_validate(record).model_dump(mode="json")


@router.get("/{account_id}/context")
async def get_account_context(
    account_id: UUID, session: DbSession, tenant: Tenant
) -> dict:
    """What has been declared about this subscription, or null if nothing has."""
    record = await context_service.get_declaration(session, tenant, account_id)
    return envelope(_declaration(record))


@router.put("/{account_id}/context")
async def declare_account_context(
    account_id: UUID, payload: ContextDeclarationIn, session: DbSession, tenant: Tenant
) -> dict:
    """Declare the environment, criticality or data sensitivity of a subscription.

    A full replacement rather than a patch: a field left out is one the customer
    is no longer claiming, and a body claiming nothing at all clears the
    declaration entirely.

    Applied by the next evaluation of this subscription -- the next scan, or a
    replay of its latest capture. Deliberately not rescored here: a risk score
    is what a scan concluded, and rewriting stored scores from an API call would
    leave findings carrying numbers no observation ever produced.
    """
    tenant.require_write()
    record = await context_service.declare(
        session,
        tenant,
        account_id,
        environment=payload.environment,
        criticality=payload.criticality,
        data_sensitivity=payload.data_sensitivity,
        note=payload.note,
    )
    await session.commit()
    return envelope(_declaration(record))


@router.delete("/{account_id}/context")
async def clear_account_context(
    account_id: UUID, session: DbSession, tenant: Tenant
) -> dict:
    """Withdraw the declaration, leaving CloudGuard to infer as it did before."""
    tenant.require_write()
    await context_service.declare(
        session,
        tenant,
        account_id,
        environment=None,
        criticality=None,
        data_sensitivity=None,
        note=None,
    )
    await session.commit()
    return envelope(None)
