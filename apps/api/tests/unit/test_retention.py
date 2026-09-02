"""Which captures survive a prune.

The deletes themselves are SQL and are held against a real database in
``tests/integration/test_scan_pipeline.py``. What lives here is the part that is
Python and is the part that decides: a capture is deleted if it is outside the
window *and* is not the newest of its scope, and getting that composition wrong
loses the one capture an applied replay reads.

Worth a unit test as well as an integration one because the failure is silent.
Pruning a newest capture raises nothing; it turns "did the fix work" into an
advisory answer, months later, on the path the north-star metric runs through.
"""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.dialects import postgresql

from app.services import retention

ORG = uuid.uuid4()
NEWEST_ACCOUNT = uuid.uuid4()
NEWEST_DIRECTORY = uuid.uuid4()
OLD_ONE = uuid.uuid4()
OLD_TWO = uuid.uuid4()


class Result:
    def __init__(self, rows: list) -> None:
        self._rows = rows
        self.rowcount = len(rows)

    def scalars(self):
        return self

    def all(self) -> list:
        return self._rows


class FakeSession:
    """Answers the three reads by shape, and records what would be deleted."""

    def __init__(self, *, stale: list, newest_accounts: list, newest_dirs: list):
        self.stale = stale
        self.newest_accounts = newest_accounts
        self.newest_dirs = newest_dirs
        self.deleted: list[str] = []
        self.doomed: list[uuid.UUID] = []

    async def execute(self, statement: object) -> Result:
        # Compiled as PostgreSQL, which is what the application sends. Against
        # SQLAlchemy's default dialect `DISTINCT ON` renders as a bare
        # `DISTINCT`, so a matcher written on `str(statement)` silently fails to
        # recognise either lookup, both fall through to the stale list, and the
        # test passes by keeping everything -- proving the opposite of what it
        # says.
        text = str(statement.compile(dialect=postgresql.dialect()))  # type: ignore[attr-defined]
        if text.lstrip().upper().startswith("DELETE"):
            self.deleted.append(text)
            params = statement.compile().params  # type: ignore[attr-defined]
            # The tenant scope is a bound parameter too, and counting it as a
            # doomed id would make every assertion here off by one in a way that
            # looks like the exclusion having failed.
            # SQLAlchemy binds an `IN` list as one expanding parameter, so the
            # ids arrive as a list under a single key rather than as id_1,
            # id_2. Flattened here; the tenant scope is skipped, because
            # counting it as a doomed id would make every assertion off by one
            # in a way that reads as the exclusion having failed.
            self.doomed = []
            for key, value in params.items():
                if "organization" in key:
                    continue
                if isinstance(value, list):
                    self.doomed.extend(v for v in value if isinstance(v, uuid.UUID))
                elif isinstance(value, uuid.UUID):
                    self.doomed.append(value)
            return Result([])
        if "DISTINCT ON (cloud_snapshots.cloud_account_id)" in text:
            return Result(self.newest_accounts)
        if "DISTINCT ON (cloud_snapshots.connection_id)" in text:
            return Result(self.newest_dirs)
        return Result(self.stale)


async def test_the_newest_capture_is_excluded_even_when_it_is_ancient() -> None:
    """An estate nobody has scanned for a year still has a current picture.

    The window is about how much history to keep, not about whether to keep the
    present. A tenant whose last scan was in January must still be replayable in
    December, or its findings become unverifiable by anything except a new scan
    it may not be able to run.
    """
    session = FakeSession(
        stale=[OLD_ONE, NEWEST_ACCOUNT, OLD_TWO, NEWEST_DIRECTORY],
        newest_accounts=[NEWEST_ACCOUNT],
        newest_dirs=[NEWEST_DIRECTORY],
    )

    pruned = await retention.prune_snapshots(session, ORG, keep_days=30)  # type: ignore[arg-type]

    assert pruned == 2
    assert set(session.doomed) == {OLD_ONE, OLD_TWO}


async def test_the_directory_capture_is_protected_separately() -> None:
    """Two scopes, not one coalesced key.

    A tenant-wide replay restores the directory beside each subscription. If
    only the account scope were protected, the directory would be pruned out
    from under it and the identity rules would read nothing while the
    subscription rules carried on -- a replay that half worked.
    """
    session = FakeSession(
        stale=[NEWEST_DIRECTORY, OLD_ONE],
        newest_accounts=[],
        newest_dirs=[NEWEST_DIRECTORY],
    )

    pruned = await retention.prune_snapshots(session, ORG, keep_days=30)  # type: ignore[arg-type]

    assert pruned == 1
    assert session.doomed == [OLD_ONE]


async def test_nothing_outside_the_window_means_no_delete_at_all() -> None:
    """A quiet night must not issue a DELETE that matches every row.

    ``id.in_([])`` is valid SQL and matches nothing, so this is belt and braces
    -- but a retention job is the one place where an empty list turning into a
    missing predicate is unrecoverable.
    """
    session = FakeSession(stale=[], newest_accounts=[NEWEST_ACCOUNT], newest_dirs=[])

    pruned = await retention.prune_snapshots(session, ORG, keep_days=30)  # type: ignore[arg-type]

    assert pruned == 0
    assert session.deleted == []


async def test_a_window_of_only_newest_captures_deletes_nothing() -> None:
    """Every stale row is also a newest row: one subscription, one capture."""
    session = FakeSession(
        stale=[NEWEST_ACCOUNT],
        newest_accounts=[NEWEST_ACCOUNT],
        newest_dirs=[],
    )

    pruned = await retention.prune_snapshots(session, ORG, keep_days=30)  # type: ignore[arg-type]

    assert pruned == 0
    assert session.deleted == []


async def test_the_cutoff_is_measured_backwards_from_now() -> None:
    """A guard on the arithmetic, which is the kind of thing that gets a sign
    wrong once and deletes everything current instead of everything old."""
    session = FakeSession(stale=[], newest_accounts=[], newest_dirs=[])

    await retention.prune_snapshots(session, ORG, keep_days=30)  # type: ignore[arg-type]

    expected = datetime.now(UTC) - timedelta(days=30)
    assert expected < datetime.now(UTC)
