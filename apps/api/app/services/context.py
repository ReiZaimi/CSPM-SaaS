"""Reading and writing what a customer has declared about a subscription.

The one write path in CloudGuard where the customer, rather than the customer's
cloud, is the source of truth. Everything else in the product is an observation;
this is a statement, and it is stored, attributed and audited as one.
"""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import TenantContext
from app.core.enums import Level
from app.core.logging import get_logger
from app.models.context import ContextDeclarationRecord
from app.services import cloud_accounts as accounts_service
from app.services.findings import record_audit

log = get_logger(__name__)


async def get_declaration(
    session: AsyncSession, tenant: TenantContext, account_id: UUID
) -> ContextDeclarationRecord | None:
    """What has been declared about one subscription, if anything.

    Resolves the subscription first rather than querying declarations directly.
    A declaration for an account in another organization would not be returned
    either way -- both tables are tenant-scoped -- but "that subscription is not
    yours" and "nothing has been declared about it" are different answers, and
    only the first should be a 404.
    """
    await accounts_service.get_cloud_account(session, tenant, account_id)
    return (
        await session.execute(
            select(ContextDeclarationRecord).where(
                ContextDeclarationRecord.organization_id == tenant.organization_id,
                ContextDeclarationRecord.cloud_account_id == account_id,
            )
        )
    ).scalar_one_or_none()


async def declare(
    session: AsyncSession,
    tenant: TenantContext,
    account_id: UUID,
    *,
    environment: str | None,
    criticality: Level | None,
    data_sensitivity: Level | None,
    note: str | None,
) -> ContextDeclarationRecord | None:
    """Record what the customer says about a subscription, replacing any prior.

    A declaration that says nothing is a deletion rather than an empty row. The
    customer clearing every field means "go back to what you can work out
    yourself", and a row of NULLs would answer that question with a record of
    somebody having declined to answer it.

    Takes effect on the next evaluation of the subscription -- the next scan, or
    a replay of its most recent capture. Nothing is rescored here on purpose:
    a risk score is what a *scan* concluded, and rewriting stored scores from an
    API call would leave findings whose numbers no observation ever produced.
    """
    account = await accounts_service.get_cloud_account(session, tenant, account_id)
    existing = (
        await session.execute(
            select(ContextDeclarationRecord).where(
                ContextDeclarationRecord.organization_id == tenant.organization_id,
                ContextDeclarationRecord.cloud_account_id == account_id,
            )
        )
    ).scalar_one_or_none()

    declared = {
        "environment": environment,
        "criticality": criticality,
        "data_sensitivity": data_sensitivity,
    }
    if not any(value is not None for value in declared.values()):
        if existing is not None:
            await session.delete(existing)
        await record_audit(
            session,
            tenant,
            action="context.cleared",
            resource_type="cloud_account",
            resource_id=account.id,
            metadata={},
        )
        return None

    if existing is None:
        existing = ContextDeclarationRecord(
            organization_id=tenant.organization_id,
            cloud_account_id=account.id,
        )
        session.add(existing)

    existing.environment = environment
    existing.criticality = criticality
    existing.data_sensitivity = data_sensitivity
    existing.note = note
    existing.declared_by_user_id = tenant.user.id

    await record_audit(
        session,
        tenant,
        action="context.declared",
        resource_type="cloud_account",
        resource_id=account.id,
        # The values themselves, because this is the audit entry somebody reads
        # when a subscription's risk ranking changed and nobody remembers why.
        metadata={
            key: value.value if isinstance(value, Level) else value
            for key, value in declared.items()
            if value is not None
        },
    )
    log.info(
        "context.declared",
        organization_id=str(tenant.organization_id),
        cloud_account_id=str(account.id),
        environment=environment,
        criticality=criticality.value if criticality else None,
        data_sensitivity=data_sensitivity.value if data_sensitivity else None,
    )
    return existing
