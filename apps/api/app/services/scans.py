"""Scan detail, and removing scan history.

The pipeline itself lives in ``app.services.scanner``. This is what the scans
page needs *around* a run: where it pointed, who asked for it, what it found,
and how to get rid of it afterwards.
"""

from collections import Counter
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import commit_unless_externally_managed
from app.core.deps import TenantContext
from app.core.enums import FindingStatus, ScanStatus, ScanStepStatus, TaskOutcome
from app.core.errors import ScanNotFound
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.models.finding import Finding
from app.models.scan import Evidence, Scan, ScanStep

OPEN_STATUSES = [FindingStatus.OPEN, FindingStatus.IN_PROGRESS]

# What the collection report calls a task that read the tenant rather than a
# subscription. One label, so the API and any screen reading it agree.
DIRECTORY_LABEL = "Tenant directory"

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


async def lock_scan_target(
    session: AsyncSession,
    organization_id: UUID,
    connection_id: UUID | None,
    account_id: UUID | None,
) -> None:
    """Serialize everything that decides whether to start a scan on this target.

    ``scan_in_flight`` reads, and the caller then inserts. Between those two
    statements a second request can read the same "nothing running" and insert
    as well, and both scans then write findings for the same resources: the
    later commit decides which one was right, and the unique index on
    (organization, rule, resource) turns the overlap into an IntegrityError
    reported to the customer as a scan that failed for no stated reason.

    A transaction-scoped advisory lock closes it. It is held until the request's
    transaction ends, which is exactly the window the check-then-insert spans,
    and it costs nothing when uncontended. Keyed on the target rather than the
    organization, so two different connections in one tenant still start
    concurrently.

    ``hashtextextended`` rather than Python's ``hash``: the value has to be the
    same in every process, and PYTHONHASHSEED makes Python's is not.
    """
    key = f"scan:{organization_id}:{connection_id or ''}:{account_id or ''}"
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"), {"key": key}
    )


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




ABANDONED_MESSAGE = (
    "This scan stopped reporting and was closed automatically. The worker "
    "running it went away mid-scan -- usually a redeploy or a restart. Nothing "
    "was written from the part that did not finish. Run the scan again."
)

NEVER_CLAIMED_MESSAGE = (
    "This scan was never picked up by a worker and was closed automatically. "
    "The task broker accepted it but nothing collected it, which normally means "
    "the Celery worker service is not running. Check the worker, then run the "
    "scan again."
)


async def reap_abandoned_scans(session: AsyncSession) -> list[tuple[UUID, str]]:
    """Close scans that nothing is working on any more.

    The reason this matters is not tidiness. ``scan_in_flight`` treats every
    non-terminal scan as one in progress, so a scan whose worker died left its
    connection unscannable for ever, answering 409 to every attempt with no
    timeout and no way out short of editing the database.

    Steps changed what this is for. A scan now runs as leased steps that are
    reclaimed individually, so a worker dying costs the step in flight rather
    than the scan -- and a scan with any live step is explicitly excluded here,
    because it has work waiting for a worker rather than work nobody is doing.

    What is left is the case steps cannot fix: a scan that never got steps at
    all, because the message that would have created them was lost. That one
    is judged on how long it has waited, with a long grace period -- a deep
    queue is normal and reaping a scan that was about to start would be its own
    bug.

    Returns what it closed, so the caller can log it. Runs with the owner
    session from a periodic task, so it scopes nothing by organization on
    purpose: every tenant's abandoned work is abandoned.
    """
    now = datetime.now(UTC)
    queued_cutoff = now - timedelta(seconds=Scan.QUEUE_GRACE_SECONDS)

    # Scans with a step that is still live. A step reaper runs before this and
    # returns expired steps to PENDING, so anything still here has work waiting
    # for a worker rather than work nobody is doing -- and closing it would be
    # closing a scan that is about to continue.
    alive = (
        select(ScanStep.scan_id)
        .where(
            or_(
                ScanStep.status == ScanStepStatus.PENDING,
                and_(
                    ScanStep.status == ScanStepStatus.RUNNING,
                    ScanStep.lease_until > now,
                ),
            )
        )
        .scalar_subquery()
    )

    stale = (
        (
            await session.execute(
                select(Scan).where(
                    Scan.status.in_(ACTIVE_SCAN_STATUSES),
                    Scan.id.not_in(alive),
                    or_(
                        Scan.lease_until < now,
                        and_(
                            Scan.lease_until.is_(None),
                            Scan.created_at < queued_cutoff,
                        ),
                    ),
                )
            )
        )
        .scalars()
        .all()
    )

    closed: list[tuple[UUID, str]] = []
    for scan in stale:
        message = (
            NEVER_CLAIMED_MESSAGE if scan.lease_until is None else ABANDONED_MESSAGE
        )
        scan.status = ScanStatus.FAILED
        scan.error_message = message
        scan.completed_at = now
        scan.lease_until = None
        closed.append((scan.id, message))

    if closed:
        await session.commit()
    return closed


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


async def scan_stages(session: AsyncSession, scan: Scan) -> list[dict]:
    """What each stage of this scan did, and how long it took.

    "Why is this scan slow?" had no answer: a scan was one task, and the only
    timings recorded were its own start and end. Steps changed that as a side
    effect of being durable -- every stage already records when it was claimed
    and when it settled -- so the question is answerable from rows that are
    being written anyway.

    Named for the scope rather than the row: a customer reading this wants to
    know which subscription was slow, not which UUID.
    """
    rows = list(
        (
            await session.execute(
                select(ScanStep, CloudAccount.display_name)
                .outerjoin(CloudAccount, CloudAccount.id == ScanStep.cloud_account_id)
                .where(
                    ScanStep.scan_id == scan.id,
                    ScanStep.organization_id == scan.organization_id,
                )
                .order_by(ScanStep.kind, ScanStep.created_at)
            )
        ).all()
    )

    stages = []
    for step, account_name in rows:
        # Elapsed rather than stored: a step that is still running has a
        # duration too, and it is the one somebody watching a slow scan
        # actually wants.
        end = step.finished_at or (datetime.now(UTC) if step.started_at else None)
        seconds = (
            max(0.0, (end - step.started_at).total_seconds())
            if step.started_at and end
            else None
        )
        stages.append(
            {
                "stage": step.kind.value,
                "scope": account_name
                or (DIRECTORY_LABEL if step.is_directory else None),
                "status": step.status.value,
                # A step on its second attempt is a step that was interrupted,
                # which is the first thing to know about a scan that took twice
                # as long as usual.
                "attempt": step.attempt,
                "duration_seconds": round(seconds, 1) if seconds is not None else None,
                "error": step.error,
            }
        )
    return stages


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


async def collection_status(session: AsyncSession, scan: Scan) -> dict:
    """What this scan managed to read, per subscription and per task.

    Reported apart from the rule coverage next door, because they answer
    different questions and conflating them is how "we could not look" became
    "we looked and it was fine" in the first place. Rule coverage says what the
    checks concluded; this says whether they were entitled to conclude it.
    """
    # Outer join, because a directory task belongs to no subscription. An inner
    # join silently dropped those rows, which would leave the identity category
    # missing from the very report that exists to say what could not be read.
    rows = list(
        (
            await session.execute(
                select(Evidence, CloudAccount.display_name)
                .outerjoin(
                    CloudAccount,
                    CloudAccount.id == Evidence.cloud_account_id,
                )
                .where(
                    Evidence.scan_id == scan.id,
                    Evidence.organization_id == scan.organization_id,
                )
                .order_by(CloudAccount.display_name, Evidence.evidence_key)
            )
        ).all()
    )

    tasks = [
        {
            # Named for what it is a reading of. "Tenant directory" rather than
            # a blank or a borrowed subscription name: the customer needs to
            # know a failure there is not a failure in any one subscription.
            "subscription": name or DIRECTORY_LABEL,
            "cloud_account_id": (
                str(row.cloud_account_id) if row.cloud_account_id else None
            ),
            # Named "task" for the reader rather than "evidence_key" for the
            # schema. This is the report that answers "what could you not
            # read", and a task is the thing a person pictures failing.
            "task": row.evidence_key,
            "category": row.category,
            "outcome": row.outcome.value,
            "detail": row.detail,
            "item_count": row.item_count,
        }
        for row, name in rows
    ]

    counts = Counter(t["outcome"] for t in tasks)
    return {
        "tasks": tasks,
        "total": len(tasks),
        "complete": counts.get(TaskOutcome.COMPLETE.value, 0),
        "partial": counts.get(TaskOutcome.PARTIAL.value, 0),
        "failed": counts.get(TaskOutcome.FAILED.value, 0),
        "skipped": counts.get(TaskOutcome.SKIPPED.value, 0),
        # The distinction the flat error map could not make: a category may be
        # unreliable because nothing came back, or because not all of it did.
        # One is an outage; the other is a tenant larger than one scan reads,
        # and they call for different actions.
        "degraded_categories": sorted(
            {t["category"] for t in tasks if t["outcome"] != TaskOutcome.COMPLETE.value}
        ),
    }
