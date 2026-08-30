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
    from app.models.scan import Evidence

    constraint = next(
        c
        for c in Evidence.__table_args__
        if getattr(c, "name", "") == "uq_evidence_scan_account_key"
    )
    assert [c.name for c in constraint.columns] == [
        "scan_id",
        "cloud_account_id",
        "evidence_key",
    ]


def test_a_reading_carries_the_category_the_rules_degrade_on() -> None:
    """``evidence_key`` is what was read; ``category`` is the bucket
    the customer's role is granted on. Both are needed: one names the listing,
    the other names the checks that lose their verdict over it."""
    from app.models.scan import Evidence

    columns = {c.name for c in Evidence.__table__.columns}
    assert {"evidence_key", "category", "outcome", "detail", "item_count"} <= columns


# ------------------------------------------------------------ schema shape
def test_a_snapshot_is_a_capture_of_one_scope() -> None:
    """A snapshot captures one subscription or the tenant directory, never both.

    This test previously pinned the opposite of half of it -- that
    ``cloud_snapshots`` had no ``connection_id`` at all -- because an edit had
    once added the column to the model without adding it to the database, and
    every snapshot insert failed. Migration 0008 adds it for real, and for a
    reason the old shape could not express: the directory is not a reading of
    any subscription, so its capture has no account to point at.

    What is worth pinning is unchanged in spirit: a snapshot names exactly one
    scope, and both columns exist in the database.
    """
    from app.models.scan import CloudSnapshot

    columns = {c.name: c for c in CloudSnapshot.__table__.columns}

    # Nullable in tandem: an account capture has no connection requirement, a
    # directory capture has no account. The CHECK constraint in migration 0008
    # is what forbids a row with neither.
    assert columns["cloud_account_id"].nullable
    assert columns["connection_id"].nullable
    assert not columns["scan_id"].nullable


def test_a_reading_names_the_scope_it_came_from() -> None:
    """The coverage ledger follows the same split as the snapshot.

    A directory task that failed did not fail in any subscription, and
    recording it against one would send a customer to check a subscription that
    is working.
    """
    from app.models.scan import Evidence

    columns = {c.name: c for c in Evidence.__table__.columns}
    assert columns["cloud_account_id"].nullable
    assert columns["connection_id"].nullable


def test_a_directory_asset_has_no_subscription() -> None:
    """Assets carry the same distinction, and it is the one that mattered most.

    Keyed per subscription, one directory user became one asset row per
    subscription -- and findings are identified by (organization, rule,
    resource), so one administrator without MFA raised one CRITICAL finding for
    every subscription in the tenant.
    """
    from app.models.resource import ResourceRecord

    columns = {c.name: c for c in ResourceRecord.__table__.columns}
    assert columns["cloud_account_id"].nullable
    assert columns["connection_id"].nullable


def test_a_scan_is_scoped_to_a_connection_or_a_subscription() -> None:
    """Both nullable, because a scan carries one or the other."""
    from app.models.scan import Scan

    columns = {c.name: c for c in Scan.__table__.columns}
    assert columns["cloud_account_id"].nullable
    assert columns["connection_id"].nullable
