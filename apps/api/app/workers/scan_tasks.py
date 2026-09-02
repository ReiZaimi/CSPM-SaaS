"""Scan tasks.

Every task takes ids and nothing else. Organization, cloud account and
subscription are read from the records inside the worker, so a queue message can
never be the source of a tenant boundary decision.

A scan is driven by two tasks rather than performed by one. ``advance_scan``
asks what may run now and claims it; ``run_scan_step`` performs one claimed step
and asks again. That is the whole loop, and it is what makes a scan survive the
worker it started on -- the state lives in ``scan_steps``, not in a Python
frame.
"""

import asyncio
from datetime import UTC, datetime
from functools import lru_cache
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import dispose_engines, scan_session, service_session
from app.core.enums import ScanStatus, ScanStepKind, ScanTrigger
from app.core.logging import configure_logging, get_logger, log_context
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.models.organization import Organization
from app.models.scan import Scan
from app.services import change_events as change_service
from app.services import notifications as notifications_service
from app.services import orchestrator
from app.services import retention as retention_service
from app.services import scans as scans_service
from app.services import verification as verification_service
from app.services.scanner import ScanPipeline
from app.workers.celery_app import (
    ANALYZE_QUEUE,
    COLLECT_QUEUE,
    DEFAULT_QUEUE,
    celery_app,
)

log = get_logger(__name__)


@lru_cache(maxsize=1)
def _announce_tenancy() -> None:
    """Say once, out loud, whether the database is enforcing tenant isolation.

    The fallback is deliberate -- a deployment without the worker role keeps
    working exactly as it did -- and that is precisely why it needs saying. A
    silent fallback would leave an operator believing PostgreSQL was holding a
    boundary that in fact only the pipeline's own filters were holding.
    """
    if settings.worker_is_constrained:
        log.info("worker.tenancy_enforced_by_database")
    else:
        log.warning(
            "worker.tenancy_enforced_by_code_only",
            detail=(
                "DATABASE_WORKER_URL is not set, so scans run on the owner "
                "connection, which row-level security does not constrain. The "
                "pipeline still scopes every query by organization; nothing "
                "below it checks. Create cloudguard_worker "
                "(infrastructure/supabase/roles.sql) and set the variable to "
                "have PostgreSQL enforce it."
            ),
        )


@celery_app.task(name="cloudguard.run_scan", bind=True, max_retries=0)
def run_scan(self: object, scan_id: str) -> dict:
    """Start a scan: give it its steps, then set the loop going.

    Still the only thing the API enqueues, and still takes only an id. What
    changed is what it does with it -- rather than performing the whole scan in
    this one task, it records the stages and hands off to ``advance_scan``.

    ``max_retries=0`` remains right, and now for a better reason than before.
    Retrying is what steps do; retrying *this* would only re-create rows the
    unique index already refuses.
    """
    configure_logging()
    _announce_tenancy()
    with log_context(scan_id=scan_id, task="run_scan"):
        log.info("scan.task_received")
        asyncio.run(_start(UUID(scan_id)))
    return {"scan_id": scan_id}


@celery_app.task(name="cloudguard.advance_scan", bind=True, max_retries=0)
def advance_scan(self: object, scan_id: str) -> dict:
    """Claim whatever this scan may run now, and queue it.

    Safe to run twice. The claim is an ``UPDATE ... WHERE status = 'PENDING'``,
    so a second advance arriving at the same moment finds the steps already
    taken and queues nothing -- which is what lets a step enqueue its successor
    without coordinating with anyone.
    """
    configure_logging()
    with log_context(scan_id=scan_id, task="advance_scan"):
        claimed = asyncio.run(_advance(UUID(scan_id)))
    for step_id, kind in claimed:
        # Routed by what the step costs rather than by what it is called.
        # Collection waits on Azure and wants many in flight; analysis holds a
        # whole tenant in memory and wants few, and one pool sized for either
        # is sized wrongly for the other.
        run_scan_step.apply_async(
            args=[scan_id, str(step_id)], queue=queue_for(kind)
        )
    return {"scan_id": scan_id, "claimed": len(claimed)}


@celery_app.task(name="cloudguard.run_scan_step", bind=True, max_retries=0)
def run_scan_step(self: object, scan_id: str, step_id: str) -> dict:
    """Perform one claimed step, then ask what is next.

    No Celery retry, deliberately, and this is the one place the distinction
    matters. Celery would retry the *message*, which says nothing about whether
    the step is still owned -- two workers could end up collecting the same
    subscription. A failed step goes back to PENDING with its attempt count
    raised, and the next advance gives it to whichever worker is free.
    """
    configure_logging()
    # The whole point of the binding: a step's lines are the ones interleaved
    # with every other tenant's, on the queue that does the slow work.
    with log_context(scan_id=scan_id, step_id=step_id, task="run_scan_step"):
        outcome = asyncio.run(_run_step(UUID(scan_id), UUID(step_id)))
    # Always, whatever happened. A step that failed is still progress: it may
    # have unblocked ANALYZE, or been the last one outstanding.
    advance_scan.delay(scan_id)
    return {"scan_id": scan_id, "step_id": step_id, "outcome": outcome}


@celery_app.task(name="cloudguard.replay_scan", bind=True, max_retries=0)
def replay_scan(self: object, scan_id: str) -> dict:
    """Re-evaluate a stored snapshot against today's rules.

    Still one task rather than a set of steps, and deliberately so: a replay
    collects nothing, so there is no fan-out to spread and no provider call to
    lose halfway. It is one evaluation over captures already in the database.
    """
    configure_logging()
    with log_context(scan_id=scan_id, task="replay_scan"):
        log.info("scan.replay_task_received")
        asyncio.run(_replay_and_release(UUID(scan_id)))
    return {"scan_id": scan_id}


@celery_app.task(name="cloudguard.reap_abandoned_scans", bind=True, max_retries=0)
def reap_abandoned_scans(self: object) -> dict:
    """Reclaim work nobody is doing. Runs on the beat schedule.

    Two levels, because they mean different things. A step whose lease expired
    goes back to PENDING and is simply run again -- a redeploy costs the step in
    flight rather than the scan. A *scan* is only closed when it has no live
    steps left to reclaim, which is the case migration 0009 was written for: a
    scan that never reaches a terminal status counts as in flight for ever, and
    a connection with one of those cannot be scanned at all.
    """
    configure_logging()
    reclaimed, closed = asyncio.run(_reap_and_release())
    if reclaimed:
        log.warning("scan.reclaimed_steps", count=len(reclaimed))
    if closed:
        log.warning("scan.reaped_abandoned", count=len(closed))
    for scan_id in reclaimed:
        advance_scan.delay(str(scan_id))
    return {"reclaimed": len(reclaimed), "closed": len(closed)}


@celery_app.task(name="cloudguard.scan_changed_environments", bind=True, max_retries=0)
def scan_changed_environments(self: object) -> dict:
    """Read the environments that have just told us they changed.

    The other half of the Event Grid path, and the half that decides whether it
    is useful or a denial of service. The webhook records that something moved
    and returns; this starts one scan once the movement has stopped, so a
    template deployment emitting forty events becomes one reading rather than
    forty.
    """
    configure_logging()
    started = asyncio.run(_start_changed())
    if started:
        log.info("scan.change_triggered_starts", count=len(started))
    for scan_id in started:
        run_scan.delay(str(scan_id))
    return {"started": len(started)}


@celery_app.task(name="cloudguard.verify_due_remediations", bind=True, max_retries=0)
def verify_due_remediations(self: object) -> dict:
    """Look again at the fixes customers have reported.

    The half of verification that used to be the customer's job. Marking work
    done told them to run a rescan; if they forgot, or ran one too early and
    saw the old state, the finding stayed open and nothing said why.

    One scan per scope rather than one per verification, because a scan of a
    subscription settles every claim in it at once -- and a scan already running
    over that scope is left to do the job rather than queued behind.
    """
    configure_logging()
    started = asyncio.run(_start_verification_scans())
    if started:
        log.info("verification.scans_started", count=len(started))
    for scan_id in started:
        run_scan.delay(str(scan_id))
    return {"started": len(started)}


@celery_app.task(name="cloudguard.prune_evidence", bind=True, max_retries=0)
def prune_evidence(self: object) -> dict:
    """Let go of captures and payloads nobody can still need.

    The two largest things in the schema and the only two that grew without
    bound. Kept for real reasons -- a capture is what lets a scan be
    re-evaluated against improved rules, a payload is what a citation points at
    -- and neither reason survives indefinitely.

    Never the newest capture of a scope, whatever the window says: that one is
    what an applied replay reads, and losing it would turn "did the fix work"
    into an answer nobody can act on, silently.
    """
    configure_logging()
    totals = asyncio.run(_prune_all_evidence())
    if totals["snapshots"] or totals["blobs"]:
        log.info(
            "retention.pruned",
            snapshots=totals["snapshots"],
            blobs=totals["blobs"],
        )
    return totals


@celery_app.task(name="cloudguard.derive_notifications", bind=True, max_retries=0)
def derive_notifications(self: object) -> dict:
    """Turn what the scans recorded into what is worth telling somebody.

    A sweep rather than a hook inside the pipeline, and the separation is the
    point: the scanner stays the one thing that says what happened, and this
    reads those rows. A notification can then never disagree with the finding it
    is about, and a replay -- which writes no finding events -- produces none of
    these without anyone having to remember that it should not.

    Per organization, because the graph is loaded once per sweep and a tenant's
    reachability is a fact about that tenant. One failing organization is logged
    and skipped rather than taking the others' notifications with it.
    """
    configure_logging()
    written = asyncio.run(_derive_all_notifications())
    if written:
        log.info("notifications.derived", count=written)
    return {"written": written}


@celery_app.task(name="cloudguard.start_due_scans", bind=True, max_retries=0)
def start_due_scans(self: object) -> dict:
    """Start scans for connections whose environment is overdue a reading.

    The product's first claim is continuous posture assessment, and until this
    existed every scan was a button press: a customer who connected Azure,
    scanned once and got on with their week had a report that aged silently
    while the environment moved.

    Runs on the beat schedule beside the reaper, and starts scans the same way
    the API does -- same advisory lock, same in-flight check, same task. A
    scheduled scan is a scan; the only thing that differs is who asked for it.
    """
    configure_logging()
    _announce_tenancy()
    started = asyncio.run(_start_due())
    if started:
        log.info("scan.scheduled_starts", count=len(started))
    for scan_id in started:
        run_scan.delay(str(scan_id))
    return {"started": len(started)}


# ------------------------------------------------------------------ internals
#
# Every one of these disposes its engines before its loop ends. ``asyncio.run``
# gives each task its own event loop while the engine pool is cached for the
# life of the process, so without disposal the second task in a worker inherits
# connections bound to a loop that has closed -- the first succeeds and every
# later one fails with "got Future attached to a different loop". Prefork makes
# that especially confusing: each child gets exactly one working task.


async def _start(scan_id: UUID) -> None:
    try:
        async with service_session() as session:
            scan = await session.get(Scan, scan_id)
            if scan is None:
                log.error("scan.missing", scan_id=str(scan_id))
                return
            await orchestrator.create_initial_steps(session, scan)
            await session.commit()
    finally:
        await dispose_engines()
    advance_scan.delay(str(scan_id))


def queue_for(kind: ScanStepKind) -> str:
    """Which pool should run this step.

    PLAN sits on the default queue with the other short database-only tasks:
    it resolves a scope and writes a few rows, and giving it a pool of its own
    would be a queue for work that never queues.
    """
    if kind == ScanStepKind.COLLECT:
        return COLLECT_QUEUE
    if kind == ScanStepKind.ANALYZE:
        return ANALYZE_QUEUE
    return DEFAULT_QUEUE


async def _advance(scan_id: UUID) -> list[tuple[UUID, ScanStepKind]]:
    try:
        async with service_session() as session:
            scan = await session.get(Scan, scan_id)
            if scan is None:
                return []
            steps = await orchestrator.sync_scan_state(session, scan)
            if scan.status == ScanStatus.CANCELLED:
                return []
            ready = orchestrator.runnable(steps)
            return await orchestrator.claim(session, [s.id for s in ready])
    finally:
        await dispose_engines()


async def _run_step(scan_id: UUID, step_id: UUID) -> str:
    """Hand one step to the pipeline, releasing connections whatever happens.

    Thin on purpose. Which step to run, and whether a failure is worth another
    attempt, are decisions about the scan rather than about Celery -- so they
    live in the pipeline, where the tests can reach them without a broker.
    """
    try:
        return (await ScanPipeline(scan_id).run_step(step_id)).value
    finally:
        await dispose_engines()


async def _start_changed() -> list[UUID]:
    """Queue a scan for each connection whose burst of changes has settled.

    Locked and checked per connection, exactly as the scheduled sweep is: a
    connection already being read is skipped rather than waited for, and the
    pending marker is cleared either way. Clearing it on a skip is deliberate --
    the scan already running will see the change, and leaving the marker would
    start a second scan for a change the first one covered.
    """
    started: list[UUID] = []
    try:
        async with service_session() as session:
            ready = await change_service.connections_ready(session)
            targets = [(c.organization_id, c.id) for c in ready]

        for org_id, connection_id in targets:
            async with service_session() as session:
                connection = await session.get(CloudConnection, connection_id)
                if connection is None:
                    continue

                await scans_service.lock_scan_target(session, org_id, connection_id, None)
                in_flight = await scans_service.scan_in_flight(
                    session, org_id, connection_id, None
                )
                recent = await scans_service.scanned_since(
                    session,
                    org_id,
                    connection_id,
                    since=datetime.now(UTC) - change_service.MIN_INTERVAL,
                    trigger=ScanTrigger.CHANGE,
                )
                if in_flight or recent:
                    # Either it is being read now, or it was read for a change
                    # very recently. A team deploying all afternoon gets a scan
                    # on a floor rather than one every quiet period.
                    change_service.clear_pending(connection)
                    await session.commit()
                    continue

                scan = Scan(
                    organization_id=org_id,
                    connection_id=connection_id,
                    status=ScanStatus.QUEUED,
                    trigger=ScanTrigger.CHANGE,
                )
                session.add(scan)
                change_service.clear_pending(connection)
                await session.commit()
                started.append(scan.id)
        return started
    finally:
        await dispose_engines()


async def _start_verification_scans() -> list[UUID]:
    """Queue the cheapest scan that could settle each due verification.

    Grouped by scope first. A tenant with eight claimed fixes in one
    subscription is one scan, not eight -- and every one of those claims is
    settled by it, because a scan settles every verification whose scope it
    read rather than the one it was started for.

    A verification with no scope at all is skipped rather than served: nothing
    can be read to settle it, and a scan started anyway would spend an attempt
    without looking at the right thing.
    """
    started: list[UUID] = []
    try:
        async with service_session() as session:
            due = await verification_service.due(session)
            scopes: list[tuple[UUID, UUID | None, UUID | None]] = []
            for verification in due:
                account_id = verification.cloud_account_id
                connection_id = verification.connection_id
                if account_id is None and connection_id is None:
                    continue
                scope = (verification.organization_id, connection_id, account_id)
                if scope not in scopes:
                    scopes.append(scope)

        for org_id, connection_id, account_id in scopes:
            async with service_session() as session:
                if account_id is None:
                    # A directory finding belongs to the tenant. Any scannable
                    # subscription under the connection reads the directory
                    # once through it, so the cheapest scan available still
                    # looks at the thing being verified.
                    account_id = await _any_scannable_account(
                        session, org_id, connection_id
                    )
                    if account_id is None:
                        continue
                    account = await session.get(CloudAccount, account_id)
                    connection_id = account.connection_id if account else connection_id

                await scans_service.lock_scan_target(
                    session, org_id, connection_id, account_id
                )
                if await scans_service.scan_in_flight(
                    session, org_id, connection_id, account_id
                ):
                    # Already being read. That scan settles these claims when it
                    # analyzes, so starting another would spend an attempt on a
                    # duplicate reading of the same environment.
                    continue

                scan = Scan(
                    organization_id=org_id,
                    cloud_account_id=account_id,
                    status=ScanStatus.QUEUED,
                    trigger=ScanTrigger.VERIFICATION,
                )
                session.add(scan)
                await session.commit()
                started.append(scan.id)
        return started
    finally:
        await dispose_engines()


async def _any_scannable_account(
    session: AsyncSession, org_id: UUID, connection_id: UUID | None
) -> UUID | None:
    """Any subscription under this connection a scan could run against.

    ``is_scannable`` is a property over four columns rather than a column, so it
    is applied here rather than in the query -- the same way the API and the
    pipeline resolve their own scopes.
    """
    if connection_id is None:
        return None
    rows = (
        (
            await session.execute(
                select(CloudAccount)
                .where(
                    CloudAccount.organization_id == org_id,
                    CloudAccount.connection_id == connection_id,
                )
                .order_by(CloudAccount.display_name)
            )
        )
        .scalars()
        .all()
    )
    account = next((a for a in rows if a.is_scannable), None)
    return account.id if account else None


async def _start_due() -> list[UUID]:
    """Queue a scan for each connection that is due one.

    Each connection is locked and checked individually rather than in one
    sweep. A connection whose scan is already running must be skipped, not
    waited for, and a lock held across the whole batch would serialize every
    tenant behind whichever one happened to be first.
    """
    started: list[UUID] = []
    try:
        async with service_session() as session:
            due = await scans_service.connections_due(
                session, limit=scans_service.SCHEDULED_START_LIMIT
            )

        for connection in due:
            async with service_session() as session:
                await scans_service.lock_scan_target(
                    session, connection.organization_id, connection.id, None
                )
                if await scans_service.scan_in_flight(
                    session, connection.organization_id, connection.id, None
                ):
                    # Still working through the last one. The schedule is a
                    # floor on how often the environment is read, not an
                    # instruction to pile scans on top of each other.
                    continue

                scan = Scan(
                    organization_id=connection.organization_id,
                    connection_id=connection.id,
                    status=ScanStatus.QUEUED,
                    # Nobody asked for it, and saying so is the point of the
                    # column: a NULL user alone could not distinguish this from
                    # a manual scan whose user record had gone.
                    trigger=ScanTrigger.SCHEDULED,
                )
                session.add(scan)
                await session.commit()
                started.append(scan.id)
        return started
    finally:
        await dispose_engines()


async def _reap_and_release() -> tuple[list[UUID], list[UUID]]:
    try:
        async with service_session() as session:
            reclaimed = await orchestrator.reap_expired_steps(session)
            closed = await scans_service.reap_abandoned_scans(session)
        for scan_id, reason in closed:
            log.warning("scan.abandoned", scan_id=str(scan_id), reason=reason)
        return reclaimed, [scan_id for scan_id, _ in closed]
    finally:
        await dispose_engines()


async def _replay_and_release(scan_id: UUID) -> None:
    try:
        await ScanPipeline(scan_id).replay()
    finally:
        await dispose_engines()


async def _derive_all_notifications() -> int:
    """Every organization, each in its own transaction.

    Committed per organization rather than once at the end: a sweep that failed
    halfway would otherwise discard the notifications it had correctly derived
    for everybody before the one that broke.
    """
    total = 0
    async with service_session() as session:
        org_ids = list(
            (await session.execute(select(Organization.id))).scalars().all()
        )

    for org_id in org_ids:
        try:
            async with scan_session(org_id) as session:
                total += await notifications_service.derive(session, org_id)
                await session.commit()
        except Exception:  # pragma: no cover - one tenant must not stop the rest
            log.exception("notifications.derive_failed", organization_id=str(org_id))
    return total


async def _prune_all_evidence() -> dict[str, int]:
    """Every organization, each in its own transaction.

    Committed per organization rather than once at the end, matching the
    notification sweep: a run that failed halfway would otherwise give back the
    space it had correctly reclaimed for everybody before the one that broke.
    """
    totals = {"snapshots": 0, "blobs": 0}
    async with service_session() as session:
        org_ids = list(
            (await session.execute(select(Organization.id))).scalars().all()
        )

    for org_id in org_ids:
        try:
            async with scan_session(org_id) as session:
                result = await retention_service.prune(
                    session,
                    org_id,
                    snapshot_days=settings.snapshot_retention_days,
                    evidence_days=settings.evidence_retention_days,
                )
                await session.commit()
            totals["snapshots"] += result["snapshots"]
            totals["blobs"] += result["blobs"]
        except Exception:  # pragma: no cover - one tenant must not stop the rest
            log.exception("retention.prune_failed", organization_id=str(org_id))
    return totals
