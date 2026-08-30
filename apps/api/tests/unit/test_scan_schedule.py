"""Scanning on a schedule, rather than when somebody remembers.

The product's first claim is continuous posture assessment, and every scan was
a button press: a customer who connected Azure, scanned once and got on with
their week had a report that aged silently while the environment moved.

What needs PostgreSQL is deciding which connections are overdue, and that is
exercised in the integration suite. These pin the parts that do not: the
bounds, the default, and the scheduler being registered to run at all.
"""

from app.core.enums import ScanTrigger
from app.models.cloud_connection import CloudConnection
from app.models.scan import Scan


def test_a_connection_starts_unscheduled() -> None:
    """Turning a customer's cloud into a recurring API cost without being asked
    would be a surprise on their Azure bill as much as on ours."""
    assert CloudConnection().scan_interval_hours is None
    assert not CloudConnection().is_scheduled


def test_a_scan_is_manual_unless_it_says_otherwise() -> None:
    """The column exists because a NULL user stopped being able to carry this:
    a manual scan whose user record had gone looked exactly like a scheduled
    one."""
    column = Scan.__table__.columns["trigger"]
    assert column.default.arg == ScanTrigger.MANUAL
    assert not column.nullable


def test_the_interval_is_bounded_at_both_ends() -> None:
    """For different reasons. Below an hour a scan would still be running when
    the next was due; beyond a month, "continuous" is a claim CloudGuard cannot
    support."""
    assert CloudConnection.MIN_INTERVAL_HOURS == 1
    assert CloudConnection.MAX_INTERVAL_HOURS == 24 * 30


def test_the_schedule_request_refuses_an_interval_outside_the_bounds() -> None:
    import pytest
    from pydantic import ValidationError

    from app.schemas.cloud_connection import ScheduleUpdate

    assert ScheduleUpdate().scan_interval_hours is None
    assert ScheduleUpdate(scan_interval_hours=24).scan_interval_hours == 24

    for bad in (0, -1, CloudConnection.MAX_INTERVAL_HOURS + 1):
        with pytest.raises(ValidationError):
            ScheduleUpdate(scan_interval_hours=bad)


def test_the_scheduler_is_registered_and_runs_often_enough() -> None:
    """A coarse tick would quietly add to every customer's interval: a daily
    scan becomes daily plus whenever the scheduler next happens to look."""
    from app.workers.celery_app import celery_app
    from app.workers.scan_tasks import start_due_scans  # noqa: F401

    entry = celery_app.conf.beat_schedule["start-due-scans"]
    assert entry["task"] == "cloudguard.start_due_scans"
    assert entry["schedule"] <= 600


def test_a_scheduled_scan_starts_the_same_way_a_manual_one_does() -> None:
    """A scheduled scan is a scan. Sharing the lock and the in-flight check is
    what stops the scheduler queueing one on top of a run already in progress.
    """
    import inspect

    from app.workers import scan_tasks

    source = inspect.getsource(scan_tasks._start_due)
    assert "lock_scan_target" in source
    assert "scan_in_flight" in source
    assert "ScanTrigger.SCHEDULED" in source
