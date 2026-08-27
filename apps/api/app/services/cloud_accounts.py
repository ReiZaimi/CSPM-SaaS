"""Reading cloud accounts.

Creating, consenting and validating moved to
:mod:`app.services.cloud_connections` when a connection became the thing a
customer grants and a cloud account became a *discovered* subscription beneath
it. What is left here is what still has callers: resolving one account for the
scan routes, and describing the permissions CloudGuard asks for.
"""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.azure.connector import AzureConnector
from app.core.deps import TenantContext
from app.core.errors import CloudAccountNotFound
from app.core.logging import get_logger
from app.models.cloud_account import CloudAccount

log = get_logger(__name__)


async def get_cloud_account(
    session: AsyncSession, tenant: TenantContext, account_id: UUID
) -> CloudAccount:
    account = (
        await session.execute(
            select(CloudAccount).where(
                CloudAccount.id == account_id,
                CloudAccount.organization_id == tenant.organization_id,
            )
        )
    ).scalar_one_or_none()
    if account is None:
        raise CloudAccountNotFound()
    return account


def required_permissions() -> dict:
    return AzureConnector.required_permissions()
