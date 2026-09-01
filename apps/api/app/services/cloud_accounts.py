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

from app.connectors.registry import get_connector_class
from app.core.deps import TenantContext
from app.core.enums import Provider
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


async def first_scannable_account(
    session: AsyncSession, tenant: TenantContext, connection_id: UUID | None
) -> CloudAccount | None:
    """Any subscription under this connection that a scan could run against.

    Needed because some assets have no subscription at all. A directory user
    belongs to the tenant, so verifying a finding about one means running a scan
    *through* the connection -- and a scan is still scoped to a subscription,
    which resolves the connection back and reads the directory once.

    Ordered by name only so the choice is stable between calls; any scannable
    subscription reads the same directory.

    ``is_scannable`` is a property over four columns rather than a column, so
    it is applied here rather than in the query -- the same way the scan
    pipeline resolves its own scope.
    """
    if connection_id is None:
        return None
    rows = (
        (
            await session.execute(
                select(CloudAccount)
                .where(
                    CloudAccount.organization_id == tenant.organization_id,
                    CloudAccount.connection_id == connection_id,
                )
                .order_by(CloudAccount.display_name)
            )
        )
        .scalars()
        .all()
    )
    return next((account for account in rows if account.is_scannable), None)


def required_permissions(provider: Provider = Provider.AZURE) -> dict:
    """What the named provider asks a customer to grant.

    Dispatched through the registry rather than answered by importing one
    connector, which is what it did: every provider would have been shown
    Azure's permissions, and the first customer to see that would have been
    told CloudGuard wanted admin consent for an AWS account.
    """
    return get_connector_class(provider).required_permissions()
