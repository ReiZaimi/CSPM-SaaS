"""An abandoned scan must not block its connection for ever.

A scan ran as one Celery task with no retries and no supervision, so a worker
that was redeployed mid-scan left the row in ``DISCOVERING`` permanently. Every
non-terminal status counts as a scan in flight, so that connection then answered
409 to every attempt to scan it again -- with no timeout, no operator endpoint,
and no way out short of editing the database.

These pin the parts of the fix that hold without one: the lease is declared, the
reaper is registered and scheduled, and the two grace periods stand in the right
relation to each other. What the reaper actually closes is exercised against
PostgreSQL in ``tests/integration/test_scan_pipeline.py``.
"""

from app.models.scan import Scan


def test_a_scan_declares_a_lease() -> None:
    columns = {c.name: c for c in Scan.__table__.columns}
    assert "lease_until" in columns
    # Nullable because a queued scan holds no lease: nothing has claimed it.
    assert columns["lease_until"].nullable


def test_a_queued_scan_gets_far_more_patience_than_a_running_one() -> None:
    """The two populations mean different things, so they are judged differently.

    An expired lease means a worker stopped reporting, which is a fault. A long
    queue means a queue, which is not -- and reaping a scan that was about to
    start would be a bug of its own, so the queue grace has to be the larger of
    the two by a wide margin.
    """
    assert Scan.QUEUE_GRACE_SECONDS > Scan.LEASE_SECONDS * 2


def test_the_lease_outlasts_the_task_time_limit() -> None:
    """Otherwise the reaper would close scans that are still legitimately running.

    Celery's soft limit is what actually bounds a scan; a lease shorter than it
    would declare a working scan abandoned while its worker was still on it.
    """
    from app.workers.celery_app import celery_app

    assert celery_app.conf.task_soft_time_limit / 2 <= Scan.LEASE_SECONDS


def test_the_reaper_is_scheduled() -> None:
    """Registered *and* on the beat schedule.

    Worth pinning together: a task that exists but nothing runs clears nothing,
    and the failure looks exactly like the bug it was written to fix.
    """
    from app.workers.celery_app import celery_app
    from app.workers.scan_tasks import reap_abandoned_scans  # noqa: F401

    schedule = celery_app.conf.beat_schedule
    entry = schedule["reap-abandoned-scans"]
    assert entry["task"] == "cloudguard.reap_abandoned_scans"
    # Frequent, because what it clears is a lockout rather than clutter.
    assert entry["schedule"] <= 300


def test_the_reaper_only_considers_non_terminal_scans() -> None:
    """A finished scan is not abandoned, however old its lease column is."""
    from app.services.scans import ACTIVE_SCAN_STATUSES

    assert all(not status.is_terminal for status in ACTIVE_SCAN_STATUSES)


# ------------------------------------------------------------------ queues
def test_steps_are_routed_by_what_they_cost() -> None:
    """Collection waits on Azure and wants many in flight; analysis holds a
    whole tenant in memory and wants few. One pool sized for either is sized
    wrongly for the other."""
    from app.core.enums import ScanStepKind
    from app.workers.celery_app import ANALYZE_QUEUE, COLLECT_QUEUE, DEFAULT_QUEUE
    from app.workers.scan_tasks import queue_for

    assert queue_for(ScanStepKind.COLLECT) == COLLECT_QUEUE
    assert queue_for(ScanStepKind.ANALYZE) == ANALYZE_QUEUE
    # PLAN resolves a scope and writes a few rows. A pool of its own would be a
    # queue for work that never queues.
    assert queue_for(ScanStepKind.PLAN) == DEFAULT_QUEUE


def test_every_queue_a_step_is_routed_to_is_actually_consumed() -> None:
    """A queue no worker consumes is a scan that queues into a void: it never
    starts, and nothing says why.

    Pinned against the deployment file rather than described in prose, because
    the failure is silent and the fix is one flag.
    """
    import json
    from pathlib import Path

    from app.core.enums import ScanStepKind
    from app.workers.scan_tasks import queue_for

    config = json.loads(
        (
            Path(__file__).resolve().parents[4]
            / "infrastructure"
            / "railway"
            / "worker.json"
        ).read_text()
    )
    command = config["deploy"]["startCommand"]
    consumed = next(
        part.split("=", 1)[1] for part in command.split() if part.startswith("--queues=")
    ).split(",")

    for kind in ScanStepKind:
        assert queue_for(kind) in consumed, (
            f"{kind.value} is routed to a queue no worker consumes"
        )


# --------------------------------------------------------- one lock per target
def test_every_way_of_naming_one_target_takes_the_same_lock() -> None:
    """The lock and the in-flight check have to agree on what "the same target"
    means, or neither is doing anything.

    Callers hold different halves of the answer. The API and the rescan button
    resolve a subscription and pass it alongside its connection; the scheduler,
    the change trigger and the verification sweep pass the connection alone.
    Built from both ids, those were two different locks over one connection --
    so a customer pressing "Scan now" as the scheduler started the same
    connection got two scans writing findings for the same resources, and the
    unique index turned the overlap into a failure with nothing to read.
    """
    import asyncio
    import uuid

    from app.services.scans import lock_scan_target

    class Recorder:
        def __init__(self) -> None:
            self.keys: list[str] = []

        async def execute(self, _statement: object, params: dict) -> None:
            self.keys.append(params["key"])

    org = uuid.uuid4()
    connection = uuid.uuid4()
    recorder = Recorder()

    asyncio.run(lock_scan_target(recorder, org, connection, uuid.uuid4()))
    asyncio.run(lock_scan_target(recorder, org, connection, None))

    assert recorder.keys[0] == recorder.keys[1]


def test_two_connections_in_one_tenant_still_scan_at_once() -> None:
    """The lock is per target on purpose. Keyed on the organization it would
    serialize every environment a customer owns behind whichever one started."""
    import asyncio
    import uuid

    from app.services.scans import lock_scan_target

    class Recorder:
        def __init__(self) -> None:
            self.keys: list[str] = []

        async def execute(self, _statement: object, params: dict) -> None:
            self.keys.append(params["key"])

    org = uuid.uuid4()
    recorder = Recorder()

    asyncio.run(lock_scan_target(recorder, org, uuid.uuid4(), None))
    asyncio.run(lock_scan_target(recorder, org, uuid.uuid4(), None))

    assert recorder.keys[0] != recorder.keys[1]


def test_a_subscription_with_no_connection_is_still_a_target() -> None:
    """Accounts predating connections have no connection to key on, and a scan
    of one still has to exclude a second scan of the same subscription."""
    import asyncio
    import uuid

    from app.services.scans import lock_scan_target

    class Recorder:
        def __init__(self) -> None:
            self.keys: list[str] = []

        async def execute(self, _statement: object, params: dict) -> None:
            self.keys.append(params["key"])

    org = uuid.uuid4()
    account = uuid.uuid4()
    recorder = Recorder()

    asyncio.run(lock_scan_target(recorder, org, None, account))
    asyncio.run(lock_scan_target(recorder, org, None, account))
    asyncio.run(lock_scan_target(recorder, org, None, uuid.uuid4()))

    assert recorder.keys[0] == recorder.keys[1] != recorder.keys[2]


# ------------------------------------------------------- what bounds a step
def test_a_step_may_run_far_longer_than_a_short_task() -> None:
    """ANALYZE is one evaluation of a whole tenant. Cut at the general ceiling,
    a large tenant's scan became a killed worker the reaper then retried at the
    same size -- three attempts, three kills, and a failure whose only cause was
    the size of the estate."""
    from app.workers.celery_app import (
        STEP_SOFT_TIME_LIMIT,
        STEP_TIME_LIMIT,
        celery_app,
    )

    assert celery_app.conf.task_soft_time_limit < STEP_SOFT_TIME_LIMIT
    assert STEP_TIME_LIMIT > STEP_SOFT_TIME_LIMIT


def test_the_step_task_carries_those_limits() -> None:
    """Declared on the task rather than raised globally: the short tasks are
    still bounded at a minute-scale ceiling, where anything longer is a fault."""
    from app.workers.celery_app import STEP_SOFT_TIME_LIMIT, STEP_TIME_LIMIT
    from app.workers.scan_tasks import run_scan_step

    assert run_scan_step.soft_time_limit == STEP_SOFT_TIME_LIMIT
    assert run_scan_step.time_limit == STEP_TIME_LIMIT


def test_a_worker_reserves_one_step_at_a_time() -> None:
    """Celery's default reserves four. A reserved message is invisible to every
    other worker, so three tenant-sized steps would sit idle inside one process
    while the queue looked empty to the rest of the pool."""
    from app.workers.celery_app import celery_app

    assert celery_app.conf.worker_prefetch_multiplier == 1
