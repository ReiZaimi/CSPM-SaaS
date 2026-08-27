"""Connecting a customer's Azure environment, at a scope they choose.

The flow, and why it is shaped this way:

1. The customer names a connection and picks a scope. **No GUIDs are typed** --
   not the tenant, not the subscription. Nothing secret changes hands, and
   nothing unverifiable is accepted.
2. CloudGuard hands back a signed admin-consent link. Because the link targets
   ``organizations`` rather than a named tenant, the admin simply signs in.
3. Entra creates a service principal for CloudGuard's app in their tenant and
   calls the callback -- reporting which tenant that was. **That report is where
   ``tenant_id`` comes from.**
4. CloudGuard reads the new principal's object id back from Graph and generates
   a deployment artifact with every parameter already filled in.
5. Someone with Owner or User Access Administrator runs it. Consent does not
   grant RBAC, and this is the step customers most often miss -- so the artifact
   is a single paste rather than a portal walkthrough.
6. Validation proves both grants by using them, then discovers every
   subscription the grant can see.

**Why the tenant id is not a request field.** It used to be, and that was a
tenant-claiming hole: CloudGuard's service principal exists in every tenant that
has ever consented, so naming one of those tenants on a fresh connection and
clicking verify would succeed -- the probe passes because the principal really
does have access -- and the caller would be scanning an environment belonging to
someone else. Validation now refuses any connection whose own consent callback
has not run, and the tenant it checks is the one Entra named in that callback.
"""

import secrets
import time
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.azure.auth import build_consent_url, sign_state
from app.connectors.azure.client import ArmClient, GraphClient
from app.connectors.azure.rbac import ARTIFACT_FORMATS, ROLE_VERSION, ArtifactContext
from app.connectors.base import ConnectionCheck
from app.core.config import settings
from app.core.deps import TenantContext
from app.core.enums import (
    CloudAccountStatus,
    ConnectionScope,
    ConsentStatus,
    PermissionMode,
    Provider,
)
from app.core.errors import CloudAccountNotFound, ConflictError, NotConfigured, ValidationFailed
from app.core.logging import get_logger
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.schemas.cloud_connection import CloudConnectionCreate

log = get_logger(__name__)

CONSENT_LINK_TTL_SECONDS = 1800
# Far longer than the consent link: the artifact is frequently handed to a
# different colleague, and an expiry measured in minutes would mean the common
# case -- "send this to whoever owns the subscription" -- fails by design.
ARTIFACT_TTL_SECONDS = 7 * 24 * 3600


async def create_connection(
    session: AsyncSession, tenant: TenantContext, payload: CloudConnectionCreate
) -> CloudConnection:
    if payload.scope_type != ConnectionScope.TENANT_ROOT and not payload.scope_id:
        raise ValidationFailed(
            "A management group or subscription id is required for this scope"
        )

    connection = CloudConnection(
        # Server-derived. A client-supplied organization_id is never read.
        organization_id=tenant.organization_id,
        provider=payload.provider,
        name=payload.name,
        scope_type=payload.scope_type,
        scope_id=payload.scope_id,
        permission_mode=payload.permission_mode,
        role_version=ROLE_VERSION,
        # Carried into the artifact and read back at validation.
        external_id=secrets.token_hex(16),
        consent_status=ConsentStatus.PENDING,
        status=CloudAccountStatus.PENDING,
        status_detail="Grant admin consent to continue.",
    )
    session.add(connection)
    await session.flush()
    return connection


async def get_connection(
    session: AsyncSession, tenant: TenantContext, connection_id: UUID
) -> CloudConnection:
    connection = (
        await session.execute(
            select(CloudConnection).where(
                CloudConnection.id == connection_id,
                CloudConnection.organization_id == tenant.organization_id,
            )
        )
    ).scalar_one_or_none()
    if connection is None:
        raise CloudAccountNotFound("Connection not found")
    return connection


def consent_url_for(connection: CloudConnection) -> tuple[str, int]:
    """The signed admin-consent link.

    The state carries the connection id and is HMAC-signed: the callback arrives
    from the customer's browser, so an unsigned state would let anyone bind a
    tenant to a connection id of their choosing.

    ``tenant_hint`` is deliberately left at its default of ``organizations``.
    Naming a tenant here would mean having asked the customer for it, and the
    whole point is that Entra tells us instead.
    """
    state = sign_state(
        {
            "cloud_connection_id": str(connection.id),
            "organization_id": str(connection.organization_id),
            "issued_at": time.time(),
        }
    )
    return build_consent_url(state), CONSENT_LINK_TTL_SECONDS


def artifact_token(connection: CloudConnection) -> str:
    """Signs the unauthenticated artifact URL.

    Unauthenticated because the customer's Cloud Shell, Terraform run, or portal
    deployment fetches it, and none of those carry a CloudGuard session. Signed
    because the alternative -- a URL keyed on a connection id -- would be
    enumerable. Nothing in an artifact is secret: it names a principal object id
    the customer's own directory already lists, and a set of read permissions
    they are about to inspect.
    """
    return sign_state(
        {
            "cloud_connection_id": str(connection.id),
            "purpose": "artifact",
            "issued_at": time.time(),
        }
    )


def render_artifact(connection: CloudConnection, fmt: str) -> tuple[str, str, str]:
    """Return ``(content_type, filename, body)`` for one deployment format."""
    entry = ARTIFACT_FORMATS.get(fmt)
    if entry is None:
        raise ValidationFailed(
            f"Unknown format '{fmt}'. Expected one of: {', '.join(ARTIFACT_FORMATS)}"
        )
    if not connection.service_principal_object_id or not connection.scope_path:
        raise ValidationFailed(
            "Admin consent has not completed yet, so there is no service "
            "principal to grant access to."
        )

    content_type, filename, render = entry
    context = ArtifactContext(
        principal_id=connection.service_principal_object_id,
        scope_path=connection.scope_path,
        scope_type=connection.scope_type,
        permission_mode=connection.permission_mode,
        external_id=connection.external_id,
        role_version=connection.role_version,
    )
    return content_type, filename, render(context)


async def record_consent(
    session: AsyncSession, connection_id: UUID, tenant_id: str, user_id: UUID | None
) -> CloudConnection:
    """Mark consent granted after Entra's callback.

    ``tenant_id`` arrives from Entra, not from the customer, and this is the
    only place it is ever written. Consent alone does not make a connection
    usable -- the RBAC grant is separate, and ``is_verified`` stays False until
    validation proves it.
    """
    connection = await session.get(CloudConnection, connection_id)
    if connection is None:
        raise CloudAccountNotFound("Connection not found")

    connection.consent_status = ConsentStatus.GRANTED
    connection.consented_at = datetime.now(UTC)
    connection.consented_by_user_id = user_id
    connection.tenant_id = tenant_id or connection.tenant_id
    connection.consented_scopes = {"granted_for_tenant": tenant_id}
    connection.status_detail = "Admin consent granted. Grant read access next."

    # Best effort: the principal may take a moment to appear in the directory
    # after consent. Validation retries this, so a miss here delays the artifact
    # rather than breaking the flow.
    if connection.tenant_id:
        await _resolve_service_principal(connection)

    await session.commit()
    return connection


async def _resolve_service_principal(connection: CloudConnection) -> None:
    from app.connectors.azure.auth import TokenProvider

    if not connection.tenant_id:
        return
    try:
        tokens = TokenProvider(connection.tenant_id)
        async with GraphClient(tokens) as graph:
            principal = await graph.find_service_principal(settings.azure_client_id)
        if principal and principal.get("id"):
            connection.service_principal_object_id = str(principal["id"])
    except Exception as exc:  # pragma: no cover -- network path
        log.warning(
            "azure.service_principal_lookup_failed",
            connection_id=str(connection.id),
            error=str(exc),
        )


async def validate_connection(
    session: AsyncSession, tenant: TenantContext, connection_id: UUID
) -> ConnectionCheck:
    """Prove read access by using it, then record the result.

    The consent gate below is the tenant binding, and it is not a formality:
    without it, a connection naming a tenant that some *other* customer had
    consented for would validate successfully, because CloudGuard's principal
    genuinely does hold access there.
    """
    connection = await get_connection(session, tenant, connection_id)

    if connection.consent_status != ConsentStatus.GRANTED or not connection.tenant_id:
        raise ValidationFailed(
            "Admin consent has not been granted for this connection yet. "
            "Complete the consent step first."
        )

    if problem := settings.azure_consent_problem:
        raise NotConfigured(problem)

    if not connection.service_principal_object_id:
        await _resolve_service_principal(connection)

    check = await _probe(connection)

    if check.ok:
        connection.status = CloudAccountStatus.ACTIVE
        connection.rbac_verified_at = datetime.now(UTC)
    else:
        connection.status = CloudAccountStatus.ERROR
        connection.rbac_verified_at = None

    connection.status_detail = check.detail[:2000]
    await session.commit()
    return check


async def _probe(connection: CloudConnection) -> ConnectionCheck:
    """Verify both grants by using them, not by asking whether they exist."""
    from app.connectors.azure.auth import TokenProvider

    tenant_id = connection.tenant_id or ""
    check = ConnectionCheck(ok=False, tenant_id=tenant_id)

    try:
        tokens = TokenProvider(tenant_id)
    except Exception as exc:
        check.problems.append(f"Could not authenticate to tenant {tenant_id}: {exc}")
        check.detail = "Authentication failed"
        return check

    async with GraphClient(tokens) as graph:
        try:
            await graph.get_organization()
            check.permissions_verified.append("Microsoft Graph: directory readable")
        except Exception as exc:
            check.problems.append(
                "Microsoft Graph directory data is not readable. Admin consent may "
                f"have been revoked. ({exc})"
            )

    async with ArmClient(tokens) as arm:
        try:
            subscriptions = await arm.list_subscriptions()
            if not subscriptions:
                check.problems.append(
                    "No subscriptions are visible. Run the access script at the scope "
                    "you chose, or check that it completed."
                )
            else:
                check.permissions_verified.append(
                    f"Azure Resource Manager: {len(subscriptions)} subscription(s) readable"
                )
                check.subscription_id = str(subscriptions[0].get("subscriptionId") or "")
        except Exception as exc:
            check.problems.append(f"Azure Resource Manager is not readable: {exc}")

        # Opportunistic, never a gate. Confirming the nonce evidences control of
        # the scope itself; failing to read assignments at a management group is
        # common and benign, and the tenant binding above is what actually
        # protects the connection.
        await _check_external_id(arm, connection)

    check.ok = not check.problems
    check.detail = (
        "Connection verified" if check.ok else "; ".join(check.problems)[:2000]
    )
    return check


async def _check_external_id(arm: ArmClient, connection: CloudConnection) -> None:
    scope = connection.scope_path
    if not scope:
        return
    try:
        assignments = await arm.list_role_assignments_at_scope(scope)
    except Exception:
        return
    marker = f"CloudGuardExternalId={connection.external_id}"
    connection.external_id_verified = any(
        marker in str((a.get("properties") or {}).get("description") or "")
        for a in assignments
    )


async def discover_subscriptions(
    session: AsyncSession, tenant: TenantContext, connection_id: UUID
) -> list[CloudAccount]:
    """Turn everything the grant can see into scannable child accounts.

    This is what the whole scope choice buys. A subscription created after
    onboarding appears here on the next run rather than going unscanned
    indefinitely, which is the failure a posture product can least afford: an
    environment nobody mentioned reads as no findings, and no findings reads
    as safe.
    """
    from app.connectors.azure.auth import TokenProvider

    connection = await get_connection(session, tenant, connection_id)
    if not connection.is_verified:
        raise ValidationFailed("Verify the connection before discovering subscriptions")

    tokens = TokenProvider(connection.tenant_id or "")
    async with ArmClient(tokens) as arm:
        subscriptions = await arm.list_subscriptions()

    existing: dict[str, CloudAccount] = {
        account.subscription_id: account
        for account in (
            await session.execute(
                select(CloudAccount).where(CloudAccount.connection_id == connection.id)
            )
        )
        .scalars()
        .all()
        if account.subscription_id
    }

    now = datetime.now(UTC)
    accounts: list[CloudAccount] = []

    for subscription in subscriptions:
        subscription_id = str(subscription.get("subscriptionId") or "")
        if not subscription_id:
            continue
        display_name = str(subscription.get("displayName") or subscription_id)

        account = existing.get(subscription_id)
        if account is None:
            account = CloudAccount(
                organization_id=connection.organization_id,
                connection_id=connection.id,
                provider=connection.provider,
                account_name=display_name,
                display_name=display_name,
                tenant_id=connection.tenant_id or "",
                subscription_id=subscription_id,
                discovered_at=now,
                in_scope=True,
            )
            session.add(account)
        else:
            account.display_name = display_name

        # The proof lives on the connection; children mirror it so the scan
        # pipeline keeps working off CloudAccount alone.
        account.consent_status = connection.consent_status
        account.rbac_verified_at = connection.rbac_verified_at
        account.status = (
            CloudAccountStatus.ACTIVE if account.in_scope else CloudAccountStatus.DISABLED
        )
        accounts.append(account)

    # A subscription that has vanished from Azure is disabled, never deleted --
    # its findings and scan history still reference it.
    seen = {a.subscription_id for a in accounts}
    for subscription_id, account in existing.items():
        if subscription_id not in seen:
            account.status = CloudAccountStatus.DISABLED
            account.status_detail = "No longer visible to this connection"

    connection.last_discovery_at = now
    await session.commit()
    return accounts


async def set_subscription_scope(
    session: AsyncSession, tenant: TenantContext, connection_id: UUID, in_scope: dict[str, bool]
) -> list[CloudAccount]:
    """Include or exclude discovered subscriptions.

    Excluding is a real choice -- a sandbox nobody wants scored -- and it has to
    survive rediscovery, which is why the row stays rather than being removed.
    """
    connection = await get_connection(session, tenant, connection_id)
    accounts = list(
        (
            await session.execute(
                select(CloudAccount).where(CloudAccount.connection_id == connection.id)
            )
        )
        .scalars()
        .all()
    )

    for account in accounts:
        if account.subscription_id in in_scope:
            account.in_scope = in_scope[account.subscription_id]
            account.status = (
                CloudAccountStatus.ACTIVE
                if account.in_scope
                else CloudAccountStatus.DISABLED
            )

    await session.commit()
    return accounts


def connection_options() -> dict:
    """What the first screen offers, described rather than hardcoded in the UI."""
    from app.connectors.azure.auth import REQUIRED_GRAPH_PERMISSIONS
    from app.connectors.azure.rbac import ARM_READ_ACTIONS

    return {
        # Whether this deployment can actually start a consent flow. Reported
        # up front rather than discovered on the button: a customer who has
        # named a connection and chosen a scope has already spent the attention
        # this screen was asking for, and telling them then is telling them too
        # late. It is also not their problem to fix.
        "azure_configured": settings.azure_consent_ready,
        # The specific reason, so the wizard can name the variable at fault
        # instead of repeating a generic "not set up yet".
        "azure_problem": settings.azure_consent_problem,
        "scopes": [
            {
                "value": ConnectionScope.TENANT_ROOT.value,
                "label": "Entire tenant",
                "detail": (
                    "Every subscription that exists now or is created later. One "
                    "grant, broadest access."
                ),
                "requires_scope_id": False,
            },
            {
                "value": ConnectionScope.MANAGEMENT_GROUP.value,
                "label": "One management group",
                "detail": "Every subscription beneath a management group you name.",
                "requires_scope_id": True,
            },
            {
                "value": ConnectionScope.SUBSCRIPTION.value,
                "label": "A single subscription",
                "detail": "The narrowest grant. New subscriptions are not picked up.",
                "requires_scope_id": True,
            },
        ],
        "permission_modes": [
            {
                "value": PermissionMode.READER.value,
                "label": "Built-in Reader",
                "detail": (
                    "Azure's standard read-only role. One line to grant and it "
                    "never needs revisiting."
                ),
                "action_count": None,
            },
            {
                "value": PermissionMode.CUSTOM_ROLE.value,
                "label": "CloudGuard custom role",
                "detail": (
                    f"Exactly the {len(ARM_READ_ACTIONS)} read operations CloudGuard "
                    "performs, and no write actions at all. Needs redeploying when "
                    "CloudGuard adds a check that reads something new."
                ),
                "action_count": len(ARM_READ_ACTIONS),
            },
        ],
        "formats": sorted(ARTIFACT_FORMATS),
        "graph_permissions": REQUIRED_GRAPH_PERMISSIONS,
        "arm_actions": list(ARM_READ_ACTIONS),
        "role_version": ROLE_VERSION,
        "provider": Provider.AZURE.value,
    }


def already_connected(existing: CloudConnection | None) -> None:
    if existing is not None:
        raise ConflictError("This scope is already connected")
