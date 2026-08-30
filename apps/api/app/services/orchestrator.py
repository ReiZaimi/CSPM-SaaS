"""The scan state machine: what may run now, who is running it, what is left.

A scan was one Celery task that had to survive every subscription it covered.
Here it is a set of durable steps that a worker claims, runs and settles one at
a time -- so a redeploy costs the step in flight rather than the whole scan, a
tenant of fifty subscriptions is fifty retryable units, and one unreadable
subscription no longer takes the other forty-nine with it.

Three things live here and nothing else does. What is *runnable* -- a question
about dependencies. What is *claimed* -- the concurrency control. And what a
scan's steps *add up to* -- whether it has finished, and how it finished. The
work each step performs lives in the pipeline; this module never touches Azure,
a rule or a finding.

**Why not Celery Canvas, or Temporal.** Canvas holds chord state in the Redis
result backend, which is not durable and whose semantics are all-or-nothing --
the opposite of a scan, where a subscription that could not be read is a gap in
the report rather than a reason to withhold it. Temporal supplies everything
below and costs a cluster to run plus a second source of truth for workflow
state, outside the database whose row-level security is the tenant boundary.
For a pipeline with three stages, PostgreSQL is the smaller correct answer.
"""

import os
import socket
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import ScanStatus, ScanStepKind, ScanStepStatus
from app.core.logging import get_logger
from app.models.cloud_account import CloudAccount
from app.models.scan import Scan, ScanStep

log = get_logger(__name__)

# Recorded on a claim so an abandoned step can be traced to the process that
# abandoned it. Diagnostic only -- nothing is authorized by it, and the lease is
# what actually decides who owns a step.
WORKER_ID = f"{socket.gethostname()}:{os.getpid()}"

# Steps whose lease expired this many times are given up on. Three attempts
# distinguishes a transient failure -- a redeploy, a throttled API, a worker
# killed under memory pressure -- from work that will fail every time it is
# tried, which is worth reporting rather than retrying forever.
DEFAULT_MAX_ATTEMPTS = 3


async def create_initial_steps(session: AsyncSession, scan: Scan) -> None:
    """The two steps every scan has before it knows its own scope.

    COLLECT steps are not created here, because what a scan covers is resolved
    when it runs rather than when it is queued: a subscription discovered or
    excluded while the scan sat in the queue should be picked up or left out
    accordingly, and a queue that can be minutes deep makes that a real
    difference. PLAN is the step that decides.
    """
    for kind in (ScanStepKind.PLAN, ScanStepKind.ANALYZE):
        session.add(
            ScanStep(
                organization_id=scan.organization_id,
                scan_id=scan.id,
                kind=kind,
                max_attempts=DEFAULT_MAX_ATTEMPTS,
            )
        )


async def create_collect_steps(
    session: AsyncSession, scan: Scan, accounts: Sequence[CloudAccount], *, directory: bool
) -> list[ScanStep]:
    """One step per scope this scan will read. Written by PLAN.

    Idempotent by constraint rather than by checking first: a PLAN that is
    retried after a crash re-creates the same set, and the unique index on
    (scan, kind, scope) is what stops the second attempt doubling the
    collection. Existing rows are left exactly as they are, including their
    attempt counts -- a retried PLAN must not quietly grant fresh attempts to a
    COLLECT step that has been failing.
    """
    wanted: list[tuple[UUID | None, bool]] = [(account.id, False) for account in accounts]
    if directory:
        # NULL scope: the directory belongs to the tenant, not to any
        # subscription beneath it.
        wanted.append((None, True))

    existing = {
        step.cloud_account_id
        for step in (
            await session.execute(
                select(ScanStep).where(
                    ScanStep.scan_id == scan.id,
                    ScanStep.kind == ScanStepKind.COLLECT,
                )
            )
        )
        .scalars()
        .all()
    }

    created: list[ScanStep] = []
    for account_id, _is_directory in wanted:
        if account_id in existing:
            continue
        step = ScanStep(
            organization_id=scan.organization_id,
            scan_id=scan.id,
            kind=ScanStepKind.COLLECT,
            cloud_account_id=account_id,
            max_attempts=DEFAULT_MAX_ATTEMPTS,
        )
        session.add(step)
        created.append(step)
    await session.flush()
    return created


async def steps_for(session: AsyncSession, scan_id: UUID) -> list[ScanStep]:
    return list(
        (
            await session.execute(
                select(ScanStep)
                .where(ScanStep.scan_id == scan_id)
                .order_by(ScanStep.kind, ScanStep.created_at)
            )
        )
        .scalars()
        .all()
    )


def runnable(steps: Sequence[ScanStep]) -> list[ScanStep]:
    """Which pending steps have everything they need.

    The dependency rules, stated once:

    * PLAN needs nothing.
    * COLLECT needs PLAN to have succeeded -- it is PLAN that creates it, so in
      practice this is already true, and the check is what makes a COLLECT step
      left behind by a half-finished PLAN wait rather than run against a scope
      nothing resolved.
    * ANALYZE needs every COLLECT to have **settled**, which is not the same as
      succeeded. A subscription CloudGuard could not read is a gap in the
      report; holding the whole report back over it would turn a partial answer
      into no answer.
    """
    by_kind: dict[ScanStepKind, list[ScanStep]] = {}
    for step in steps:
        by_kind.setdefault(step.kind, []).append(step)

    plan_done = all(
        s.status == ScanStepStatus.SUCCEEDED for s in by_kind.get(ScanStepKind.PLAN, [])
    )
    collects = by_kind.get(ScanStepKind.COLLECT, [])
    collection_settled = plan_done and all(s.status.is_settled for s in collects)

    satisfied = {
        ScanStepKind.PLAN: True,
        ScanStepKind.COLLECT: plan_done,
        ScanStepKind.ANALYZE: collection_settled,
    }
    return [
        step
        for step in steps
        if step.status == ScanStepStatus.PENDING and satisfied[step.kind]
    ]


async def claim(session: AsyncSession, step_ids: Sequence[UUID]) -> list[UUID]:
    """Take ownership of these steps, and report which were actually won.

    The whole concurrency story is this statement. ``status = 'PENDING'`` in the
    WHERE clause means a step already claimed by another worker matches nothing
    and is simply absent from the result -- so two workers advancing the same
    scan at the same moment split the work rather than duplicating it, with no
    lock held between the read and the write.
    """
    if not step_ids:
        return []
    now = datetime.now(UTC)
    claimed = (
        await session.execute(
            update(ScanStep)
            .where(
                ScanStep.id.in_(step_ids),
                ScanStep.status == ScanStepStatus.PENDING,
            )
            .values(
                status=ScanStepStatus.RUNNING,
                attempt=ScanStep.attempt + 1,
                lease_until=now + timedelta(seconds=ScanStep.LEASE_SECONDS),
                worker_id=WORKER_ID,
                # Kept from the first attempt: it records when work on this step
                # began, and a retry is a continuation of that rather than a new
                # thing.
                started_at=func.coalesce(ScanStep.started_at, now),
            )
            .returning(ScanStep.id)
        )
    ).scalars().all()
    await session.commit()
    return list(claimed)


async def renew(session: AsyncSession, step_id: UUID) -> None:
    """Extend a running step's lease. Called as it reports progress.

    A step that stops renewing is a step whose worker is gone, which is the only
    evidence available: a process that died did not get to say so.
    """
    await session.execute(
        update(ScanStep)
        .where(ScanStep.id == step_id)
        .values(
            lease_until=datetime.now(UTC) + timedelta(seconds=ScanStep.LEASE_SECONDS)
        )
    )
    await session.commit()


async def finish(
    session: AsyncSession,
    step: ScanStep,
    status: ScanStepStatus,
    error: str | None = None,
) -> None:
    step.status = status
    step.error = error[:2000] if error else None
    step.finished_at = datetime.now(UTC)
    step.lease_until = None  # settled; nothing left to reclaim
    await session.commit()


async def fail_or_retry(
    session: AsyncSession, step: ScanStep, error: str
) -> ScanStepStatus:
    """Put a failed step back in the queue, or give up on it.

    Returns what was decided, so the caller can log the difference between "this
    will be tried again" and "this is as far as it got".
    """
    if step.attempt < step.max_attempts:
        step.status = ScanStepStatus.PENDING
        step.error = error[:2000]
        step.lease_until = None
        step.worker_id = None
        await session.commit()
        return ScanStepStatus.PENDING

    await finish(session, step, ScanStepStatus.FAILED, error)
    return ScanStepStatus.FAILED


async def reap_expired_steps(session: AsyncSession) -> list[UUID]:
    """Reclaim steps whose worker stopped reporting.

    The step-level counterpart of the scan reaper, and the reason a redeploy is
    now survivable rather than merely detectable: an expired lease returns the
    step to PENDING and the next advance runs it again, on whichever worker is
    free. Only past its attempt ceiling does it become a failure the customer is
    told about.
    """
    now = datetime.now(UTC)
    expired = (
        (
            await session.execute(
                select(ScanStep).where(
                    ScanStep.status == ScanStepStatus.RUNNING,
                    ScanStep.lease_until < now,
                )
            )
        )
        .scalars()
        .all()
    )

    # Returns the *scans* to nudge rather than the steps reclaimed: a step
    # returned to PENDING does nothing until something advances its scan, and
    # the caller has no other way to know which scans those are.
    reclaimed: set[UUID] = set()
    for step in expired:
        await fail_or_retry(
            session,
            step,
            "The worker running this step stopped reporting -- usually a "
            "redeploy or a restart.",
        )
        reclaimed.add(step.scan_id)
    return sorted(reclaimed)


def summarize(steps: Sequence[ScanStep]) -> tuple[bool, bool, list[str]]:
    """Whether the scan is finished, whether it is degraded, and why.

    Degraded rather than failed is the important distinction and the one the
    four-state rule algebra already takes elsewhere: a scan that read nine
    subscriptions out of ten has nine subscriptions' worth of findings and one
    recorded gap. Only a scan that could not analyze anything has actually
    failed.
    """
    if not steps:
        return False, False, []

    finished = all(step.status.is_settled for step in steps)
    problems = [
        f"{step.describe()}: {step.error or 'failed'}"
        for step in steps
        if step.status in (ScanStepStatus.FAILED, ScanStepStatus.SKIPPED)
    ]
    return finished, bool(problems), problems


def progress(steps: Sequence[ScanStep]) -> tuple[int, int]:
    """Steps settled, steps total.

    Coarser than the per-listing count it replaces, and correct where that was
    not: a scan now runs across several workers, and a counter accumulated in
    one process could only ever describe the part of the scan that process
    happened to run.
    """
    return sum(1 for step in steps if step.status.is_settled), len(steps)


def status_for(steps: Sequence[ScanStep]) -> ScanStatus:
    """The scan status these steps add up to.

    Mapped onto the statuses that already exist rather than inventing a
    parallel vocabulary: the frontend, the scans list and the stuck-scan
    diagnostics all read ``ScanStatus``, and a step is an implementation detail
    of how a scan runs rather than a new thing for a customer to learn.
    """
    finished, degraded, _problems = summarize(steps)
    if finished:
        if all(
            step.status in (ScanStepStatus.FAILED, ScanStepStatus.SKIPPED)
            for step in steps
        ):
            return ScanStatus.FAILED
        return ScanStatus.PARTIAL if degraded else ScanStatus.COMPLETED

    running = {step.kind for step in steps if step.status == ScanStepStatus.RUNNING}
    if ScanStepKind.ANALYZE in running:
        return ScanStatus.EVALUATING
    if running:
        return ScanStatus.DISCOVERING
    return ScanStatus.QUEUED


async def skip_unreachable(session: AsyncSession, steps: Sequence[ScanStep]) -> bool:
    """Settle steps whose dependency can never be satisfied.

    Without this a scan whose PLAN failed would hang for ever rather than fail:
    ANALYZE waits on collection, collection waits on a PLAN that has given up,
    and nothing is left to move. The step is SKIPPED rather than FAILED for the
    reason the collection executor draws that same line -- nothing is wrong with
    ANALYZE, and calling it a failure sends someone looking one hop away from
    the real problem.

    Only PLAN is treated this way. A scan whose collection all failed still runs
    ANALYZE, which reports having nothing to interpret in terms the customer can
    read; skipping it would replace that sentence with silence.
    """
    plan_failed = any(
        step.kind == ScanStepKind.PLAN and step.status == ScanStepStatus.FAILED
        for step in steps
    )
    if not plan_failed:
        return False

    skipped = False
    for step in steps:
        if step.kind == ScanStepKind.PLAN or step.status != ScanStepStatus.PENDING:
            continue
        step.status = ScanStepStatus.SKIPPED
        step.error = "the scan could not work out what to read"
        step.finished_at = datetime.now(UTC)
        step.lease_until = None
        skipped = True

    if skipped:
        await session.commit()
    return skipped


async def sync_scan_state(session: AsyncSession, scan: Scan) -> list[ScanStep]:
    """Write back what the steps say about the scan, and return them.

    The scan row stays the thing every screen reads. It is derived from the
    steps rather than maintained alongside them, so the two cannot disagree
    about whether a scan is running.
    """
    steps = await steps_for(session, scan.id)
    if not steps:
        return []

    await skip_unreachable(session, steps)
    done, total = progress(steps)
    scan.progress_done, scan.progress_total = done, total

    # A cancelled scan stays cancelled. The steps may still be settling -- a
    # worker mid-collection finds out when it next checks -- and letting a
    # late-arriving step re-derive the status would undo the cancellation.
    if scan.status == ScanStatus.CANCELLED:
        await session.commit()
        return steps

    finished, _degraded, problems = summarize(steps)
    scan.status = status_for(steps)
    if finished:
        scan.completed_at = scan.completed_at or datetime.now(UTC)
        scan.lease_until = None
        if problems and not scan.error_message:
            scan.error_message = "; ".join(problems)[:2000]
    await session.commit()
    return steps


async def unfinished_scan_ids(session: AsyncSession) -> list[UUID]:
    """Scans with work outstanding, for the dispatcher to nudge.

    A safety net rather than the normal path: a step finishing enqueues the next
    advance itself, and this exists for the case where that message was lost --
    the broker refused it, or the worker died between committing the step and
    publishing.
    """
    rows = (
        (
            await session.execute(
                select(ScanStep.scan_id)
                .join(Scan, Scan.id == ScanStep.scan_id)
                .where(
                    ScanStep.status.in_(
                        [ScanStepStatus.PENDING, ScanStepStatus.RUNNING]
                    ),
                    Scan.status != ScanStatus.CANCELLED,
                    or_(
                        ScanStep.status == ScanStepStatus.PENDING,
                        and_(
                            ScanStep.status == ScanStepStatus.RUNNING,
                            ScanStep.lease_until < datetime.now(UTC),
                        ),
                    ),
                )
                .distinct()
            )
        )
        .scalars()
        .all()
    )
    return list(rows)
