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
