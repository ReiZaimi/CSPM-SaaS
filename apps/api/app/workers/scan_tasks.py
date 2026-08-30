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
from functools import lru_cache
from uuid import UUID

from app.core.config import settings
from app.core.db import dispose_engines, service_session
from app.core.enums import ScanStatus, ScanStepKind, ScanTrigger
from app.core.logging import configure_logging, get_logger
from app.models.scan import Scan
from app.services import orchestrator
from app.services import scans as scans_service
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
    log.info("scan.task_received", scan_id=scan_id)
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
    log.info("scan.replay_task_received", scan_id=scan_id)
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
