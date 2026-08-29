"""Collection status as queryable facts.

What a scan managed to read was a map of category to a sentence: assembled for
a person and answerable by nothing else. It could not say whether a category
had failed outright or merely come back truncated -- an outage and a tenant
larger than one scan reads, reported identically -- nor which subscription it
happened in, which is the first question a tenant-wide scan raises.

These cover the shape of the record and the summary drawn from it. The write
path needs a database and is exercised in the integration suite.
"""

from app.core.enums import TaskOutcome


def test_only_a_complete_reading_is_trustworthy() -> None:
    """The distinction the whole record exists to carry."""
    assert TaskOutcome.COMPLETE.is_trustworthy

    for outcome in (TaskOutcome.PARTIAL, TaskOutcome.FAILED, TaskOutcome.SKIPPED):
        assert not outcome.is_trustworthy, f"{outcome} must not support a pass"


def test_partial_is_untrustworthy_despite_holding_data() -> None:
    """The one that is easy to get wrong. PARTIAL came back with real results,
    and a list missing an unknown number of entries still cannot support "none
    of them are public"."""
    assert not TaskOutcome.PARTIAL.is_trustworthy


def test_the_outcomes_are_stable_strings() -> None:
    """Stored in a varchar column and rendered by the frontend, so renaming one
    is a migration and a UI change, not a refactor."""
    assert {o.value for o in TaskOutcome} == {
        "COMPLETE",
        "PARTIAL",
        "FAILED",
        "SKIPPED",
    }


def test_the_model_keys_a_reading_to_its_subscription() -> None:
    """A tenant-wide scan reads each subscription separately and they fail
    separately, so an outcome that did not name its subscription would be
    unactionable in exactly the case tenant-wide scans were built for."""
    from app.models.scan import ScanCollectionResult

    constraint = next(
        c
        for c in ScanCollectionResult.__table_args__
        if getattr(c, "name", "") == "uq_scan_collection_scan_account_task"
    )
    assert [c.name for c in constraint.columns] == [
        "scan_id",
        "cloud_account_id",
        "task_key",
    ]


def test_a_reading_carries_the_category_the_rules_degrade_on() -> None:
    """``task_key`` is what was read; ``category`` is the bucket
    ``requires_collection`` keys on. Both are needed: one names the listing,
    the other names the checks that lose their verdict over it."""
    from app.models.scan import ScanCollectionResult

    columns = {c.name for c in ScanCollectionResult.__table__.columns}
    assert {"task_key", "category", "outcome", "detail", "item_count"} <= columns


# ------------------------------------------------------------ schema shape
def test_a_snapshot_belongs_to_exactly_one_subscription() -> None:
    """A snapshot is a capture of one provider account, which is why a
    tenant-wide scan holds several rather than one wide one.

    Pinned because it was briefly broken by accident: an edit making
    ``Scan.cloud_account_id`` nullable matched the identical block in
    ``CloudSnapshot`` too, and gave it a ``connection_id`` the database has no
    column for. Every snapshot insert would have failed, and nothing that runs
    without a database would have noticed.
    """
    from app.models.scan import CloudSnapshot

    columns = {c.name: c for c in CloudSnapshot.__table__.columns}

    assert "connection_id" not in columns, (
        "cloud_snapshots has no such column; a scan is scoped to a connection, "
        "a snapshot is not"
    )
    assert not columns["cloud_account_id"].nullable
    assert not columns["scan_id"].nullable


def test_a_scan_is_scoped_to_a_connection_or_a_subscription() -> None:
    """Both nullable, because a scan carries one or the other."""
    from app.models.scan import Scan

    columns = {c.name: c for c in Scan.__table__.columns}
    assert columns["cloud_account_id"].nullable
    assert columns["connection_id"].nullable
