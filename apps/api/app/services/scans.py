"""Scan detail, and removing scan history.

The pipeline itself lives in ``app.services.scanner``. This is what the scans
page needs *around* a run: where it pointed, who asked for it, what it found,
and how to get rid of it afterwards.
"""

from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import commit_unless_externally_managed
from app.core.deps import TenantContext
from app.core.enums import FindingStatus, ScanStatus
from app.core.errors import ScanNotFound
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.models.finding import Finding
from app.models.scan import Scan

OPEN_STATUSES = [FindingStatus.OPEN, FindingStatus.IN_PROGRESS]

# A scan already in flight for the same target. Shared by every route that
# starts one, so they cannot drift into disagreeing about what "already
# running" means.
ACTIVE_SCAN_STATUSES = [
    ScanStatus.QUEUED,
    ScanStatus.DISCOVERING,
    ScanStatus.NORMALIZING,
    ScanStatus.EVALUATING,
    ScanStatus.CALCULATING_RISK,
]


async def scan_in_flight(
    session: AsyncSession,
    organization_id: UUID,
    connection_id: UUID | None,
    account_id: UUID | None,
) -> bool:
    """Whether anything is already scanning this target.

    Matches either scoping form, because they cover the same subscriptions: a
    tenant-wide scan and a single-subscription rescan running at once would
    both write findings for the same resources, and the later commit would
    decide which one was right.
    """
    conditions = []
    if connection_id is not None:
        conditions.append(Scan.connection_id == connection_id)
    if account_id is not None:
        conditions.append(Scan.cloud_account_id == account_id)
    if not conditions:
        return False

    running = (
        await session.execute(
            select(Scan)
            .where(
                Scan.organization_id == organization_id,
                Scan.status.in_(ACTIVE_SCAN_STATUSES),
                or_(*conditions),
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    return running is not None




async def get_scan(session: AsyncSession, tenant: TenantContext, scan_id: UUID) -> Scan:
    scan = (
        await session.execute(
            select(Scan).where(
                Scan.id == scan_id,
                Scan.organization_id == tenant.organization_id,
            )
        )
    ).scalar_one_or_none()
    if scan is None:
        raise ScanNotFound()
    return scan


async def scan_context(session: AsyncSession, scan: Scan) -> dict:
    """What this scan pointed at, and which identity read it.

    Answers the question a disputed finding always raises first: *what exactly
    was scanned, by whom, using what?* The identity is CloudGuard's service
    principal in the customer's own tenant -- the object id they can look up in
    their directory and revoke, not an opaque internal reference.

    A scan now covers either one subscription or every in-scope subscription
    under a connection, so the answer is a list. It stays a list of one for the
    single-subscription case rather than collapsing, because "which
    subscriptions" is the question and a bare name reads like the only one.
    """
    accounts: list[CloudAccount] = []
    connection: CloudConnection | None = None

    if scan.connection_id is not None:
        connection = await session.get(CloudConnection, scan.connection_id)
        accounts = list(
            (
                await session.execute(
                    select(CloudAccount)
                    .where(CloudAccount.connection_id == scan.connection_id)
                    .order_by(CloudAccount.display_name)
                )
            )
            .scalars()
            .all()
        )
    elif scan.cloud_account_id is not None:
        account = await session.get(CloudAccount, scan.cloud_account_id)
        if account is not None:
            accounts = [account]
            if account.connection_id:
                connection = await session.get(CloudConnection, account.connection_id)

    first = accounts[0] if accounts else None
    return {
        "subscriptions": [
            {
                "subscription_id": a.subscription_id,
                "subscription_name": a.display_name,
                "in_scope": a.in_scope,
            }
            for a in accounts
        ],
        "subscription_count": len(accounts),
        # Kept for the single-subscription case the detail panel still renders.
        "subscription_id": first.subscription_id if first else None,
        "subscription_name": first.display_name if first else None,
        "tenant_id": first.tenant_id if first else None,
        "connection_name": connection.name if connection else None,
        "scope_type": connection.scope_type.value if connection else None,
        "scope_path": connection.scope_path if connection else None,
        # The identity that did the reading, named the way the customer sees it.
        "service_principal_object_id": (
            connection.service_principal_object_id if connection else None
        ),
        "role_version": connection.role_version if connection else None,
    }


async def severity_breakdown(session: AsyncSession, scan: Scan) -> dict[str, int]:
    """Open findings this scan most recently detected, by severity.

    Counted from findings rather than stored on the scan: a finding is
    identified by (organization, rule, resource) and re-detected each run, so
    the honest question is "what does this scan currently account for", which
    only the findings table can answer.
    """
    rows = (
        await session.execute(
            select(Finding.severity, func.count())
            .where(
                Finding.organization_id == scan.organization_id,
                Finding.scan_id == scan.id,
                Finding.status.in_(OPEN_STATUSES),
            )
            .group_by(Finding.severity)
        )
    ).all()
    return {str(severity): int(count) for severity, count in rows}


async def findings_attributable_to(session: AsyncSession, scan: Scan) -> int:
    """How many unresolved findings would go if this scan's were purged."""
    return int(
        (
            await session.execute(
                select(func.count()).where(
                    Finding.organization_id == scan.organization_id,
                    Finding.scan_id == scan.id,
                    Finding.status.in_(OPEN_STATUSES),
                )
            )
        ).scalar_one()
    )


async def delete_scan(
    session: AsyncSession,
    tenant: TenantContext,
    scan_id: UUID,
    *,
    purge_findings: bool,
) -> dict:
    """Delete a scan record, and optionally the findings it last detected.

    Two outcomes because they mean different things. Deleting the *record*
    removes an execution log; the findings it raised stay, because they are
    statements about the environment rather than about the run -- their
    ``scan_id`` is ``ON DELETE SET NULL`` precisely so history can be pruned
    without discarding what was found.

    Purging as well is for a scan that produced results the user considers
    wrong. Only unresolved findings go: a resolved one is the record of a fix
    that was verified, and deleting it would erase the evidence that the
    remediation loop worked.
    """
    scan = await get_scan(session, tenant, scan_id)
    purged = 0

    if purge_findings:
        findings = (
            (
                await session.execute(
                    select(Finding).where(
                        Finding.organization_id == scan.organization_id,
                        Finding.scan_id == scan.id,
                        Finding.status.in_(OPEN_STATUSES),
                    )
                )
            )
            .scalars()
            .all()
        )
        for finding in findings:
            await session.delete(finding)
            purged += 1

    await session.delete(scan)
    await commit_unless_externally_managed(session)
    return {"deleted": str(scan_id), "findings_purged": purged}
