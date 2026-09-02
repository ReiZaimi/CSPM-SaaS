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

    def __init__(
        self,
        *,
        stale: list,
        newest_accounts: list,
        newest_dirs: list,
        manifests: list | None = None,
        expired_blobs: list | None = None,
    ):
        self.manifests = manifests or []
        self.expired_blobs = expired_blobs or []
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
                    self.doomed.extend(
                        v for v in value if isinstance(v, uuid.UUID | str)
                    )
                elif isinstance(value, uuid.UUID | str):
                    self.doomed.append(value)
            # A DELETE reports how many rows it matched, and the service returns
            # that. A fake reporting zero would make every prune look like a
            # no-op regardless of what it actually named.
            result = Result([])
            result.rowcount = len(self.doomed)
            return result
            return Result([])
        if "DISTINCT ON (cloud_snapshots.cloud_account_id)" in text:
            return Result(self.newest_accounts)
        if "DISTINCT ON (cloud_snapshots.connection_id)" in text:
            return Result(self.newest_dirs)
        # Matched on the column, not on the key. `payload_hashes` is a bound
        # parameter of the `->` operator, so it never appears in the SQL text
        # and a matcher written on it silently falls through -- leaving the
        # interlock with nothing to protect and the test passing the wrong way.
        if "cloud_snapshots.manifest" in text:
            return Result(self.manifests)
        if "evidence_blobs" in text:
            return Result(self.expired_blobs)
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


# --------------------------------------------------------------- the interlock
HELD = "a" * 64
ORPHAN = "b" * 64


async def test_a_payload_a_capture_still_names_is_kept() -> None:
    """The dependency 0027 created, and the reason retention had to change.

    A capture used to be self-contained. It is now a manifest naming the hashes
    of its readings, so a blob can be the only copy of part of a capture that is
    well inside its own window.

    Deleting one raises nothing here. It fails months later, at the one moment
    somebody replays a capture to check whether a fix held -- and the replay is
    then of an estate missing whatever the pruned reading held, which is a
    resolution reached by omission.
    """
    session = FakeSession(
        stale=[],
        newest_accounts=[],
        newest_dirs=[],
        manifests=[({"storage_accounts": HELD},)],
        expired_blobs=[HELD, ORPHAN],
    )

    pruned = await retention.prune_blobs(session, ORG, keep_days=90)  # type: ignore[arg-type]

    assert pruned == 1, "the referenced payload should have been spared"
    assert session.doomed == [ORPHAN], (
        "the delete named the payload a surviving capture still points at"
    )


async def test_a_payload_nothing_names_is_pruned() -> None:
    """The interlock must not become a reason never to prune anything."""
    session = FakeSession(
        stale=[],
        newest_accounts=[],
        newest_dirs=[],
        manifests=[],
        expired_blobs=[ORPHAN],
    )

    pruned = await retention.prune_blobs(session, ORG, keep_days=90)  # type: ignore[arg-type]

    assert pruned == 1


async def test_nothing_expired_means_no_delete_at_all() -> None:
    session = FakeSession(
        stale=[], newest_accounts=[], newest_dirs=[], manifests=[], expired_blobs=[]
    )

    pruned = await retention.prune_blobs(session, ORG, keep_days=90)  # type: ignore[arg-type]

    assert pruned == 0
    assert session.deleted == []
