"""Connecting a customer's Azure environment.

The flow, and why it is shaped this way:

1. The org registers a tenant. Nothing secret changes hands.
2. CloudGuard hands back a signed admin-consent link.
3. The customer's Global Administrator clicks it; Entra creates a service
   principal for CloudGuard's app in their tenant and calls our callback.
4. Someone assigns the Reader role on the subscription. Consent does not do
   this, and this is the step customers most often miss.
5. Validation proves both grants by using them.
"""

import time
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.azure.auth import build_consent_url, sign_state
from app.connectors.azure.connector import AzureConnector
from app.connectors.base import ConnectionCheck
from app.connectors.registry import get_connector
from app.core.deps import TenantContext
from app.core.enums import CloudAccountStatus, ConsentStatus
from app.core.errors import CloudAccountNotFound, ConflictError
from app.core.logging import get_logger
from app.models.cloud_account import CloudAccount
from app.schemas.cloud_account import CloudAccountCreate

log = get_logger(__name__)

CONSENT_LINK_TTL_SECONDS = 1800


async def create_cloud_account(
    session: AsyncSession, tenant: TenantContext, payload: CloudAccountCreate
) -> CloudAccount:
    existing = (
        await session.execute(
            select(CloudAccount).where(
                CloudAccount.organization_id == tenant.organization_id,
                CloudAccount.tenant_id == payload.tenant_id,
                CloudAccount.subscription_id == payload.subscription_id,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError("This Azure subscription is already connected")

    account = CloudAccount(
        # Server-derived. A client-supplied organization_id is never read.
        organization_id=tenant.organization_id,
        provider=payload.provider,
        account_name=payload.account_name,
        tenant_id=payload.tenant_id,
        subscription_id=payload.subscription_id,
        consent_status=ConsentStatus.PENDING,
        status=CloudAccountStatus.PENDING,
    )
    session.add(account)
    await session.flush()
    return account


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


def consent_url_for(account: CloudAccount) -> tuple[str, int]:
    """Build the signed admin-consent link.

    The state carries the account id and is HMAC-signed: the callback arrives
    from the customer's browser, so an unsigned state would let anyone bind a
    tenant to an account id of their choosing.
    """
    state = sign_state(
        {
            "cloud_account_id": str(account.id),
            "organization_id": str(account.organization_id),
            "issued_at": time.time(),
        }
    )
    return build_consent_url(state, tenant_hint=account.tenant_id), CONSENT_LINK_TTL_SECONDS


async def record_consent(
    session: AsyncSession, account_id: UUID, tenant_id: str, user_id: UUID | None
) -> CloudAccount:
    """Mark consent granted after Entra's callback.

    Consent alone does not make an account scannable -- the RBAC Reader grant is
    separate, and ``is_scannable`` stays False until validation proves it.
    """
    account = await session.get(CloudAccount, account_id)
    if account is None:
        raise CloudAccountNotFound()

    account.consent_status = ConsentStatus.GRANTED
    account.consented_at = datetime.now(UTC)
    account.consented_by_user_id = user_id
    account.consented_scopes = {"granted_for_tenant": tenant_id}
    account.status_detail = "Admin consent granted. Assign the Reader role next."
    await session.commit()
    return account


async def validate_cloud_account(
    session: AsyncSession, tenant: TenantContext, account_id: UUID
) -> ConnectionCheck:
    """Prove read access by using it, then record the result."""
    account = await get_cloud_account(session, tenant, account_id)

    connector = get_connector(
        account.provider,
        tenant_id=account.tenant_id,
        subscription_id=account.subscription_id,
    )
    check = await connector.validate_connection()

    if check.ok:
        account.status = CloudAccountStatus.ACTIVE
        account.rbac_verified_at = datetime.now(UTC)
        account.consent_status = ConsentStatus.GRANTED
        if check.subscription_id and not account.subscription_id:
            account.subscription_id = check.subscription_id
    else:
        account.status = CloudAccountStatus.ERROR
        account.rbac_verified_at = None

    account.status_detail = check.detail[:2000]
    await session.commit()
    return check


def required_permissions() -> dict:
    return AzureConnector.required_permissions()
