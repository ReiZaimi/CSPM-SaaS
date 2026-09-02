"""Not rebuilding the whole tenant on every click.

Four request handlers build this graph -- the attack-path list, choke points,
blast radius, and a finding's routes -- and each one read every present asset
and every edge the organization has. Somebody clicking between those screens
paid for it each time, on the one page where a tenant large enough to have
interesting paths is also large enough to be slow.

The two things a cache on a security page must not do, and what holds them:

* **Serve a route that has been closed.** Keyed on the version of the data
  rather than on a clock, so a scan invalidates it by happening. A TTL would
  make the page briefly wrong after every scan, and briefly wrong here means
  telling somebody an attacker can still reach their data.
* **Serve one tenant another's estate.** Keyed by organization, and asserted
  below rather than assumed from the key looking right.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.services import graph as service

ORG_A = uuid.uuid4()
ORG_B = uuid.uuid4()
NOW = datetime.now(UTC)


class Result:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def scalars(self):
        return self

    def all(self) -> list:
        return self._rows

    def one(self):
        return self._rows[0]

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


class FakeSession:
    """Reports a version this test controls, and counts full reads."""

    def __init__(self, *, updated_at: datetime, count: int) -> None:
        self.updated_at = updated_at
        self.count = count
        self.builds = 0

    async def execute(self, statement: object) -> Result:
        text = str(statement)
        if "max(" in text and "count(" in text:
            return Result([(self.updated_at, self.count)])
        if "max(" in text:
            return Result([self.updated_at])
        # Anything else is one of the two whole-tenant reads a build makes.
        self.builds += 1
        return Result([])


@pytest.fixture(autouse=True)
def clean_cache():
    """Held in a module-level dict, so one test must not seed the next."""
    service.forget_cached_graphs()
    yield
    service.forget_cached_graphs()


async def test_a_second_read_of_an_unchanged_tenant_builds_nothing() -> None:
    session = FakeSession(updated_at=NOW, count=12)

    first = await service.load_graph(session, ORG_A)  # type: ignore[arg-type]
    builds_after_first = session.builds
    second = await service.load_graph(session, ORG_A)  # type: ignore[arg-type]

    assert builds_after_first > 0, "the first read must actually build"
    assert session.builds == builds_after_first, "the second read rebuilt"
    # The same object, not an equal one: the whole point is that nothing was
    # constructed the second time.
    assert first is second


async def test_a_scan_invalidates_it_by_happening() -> None:
    """The property a TTL cannot give.

    A stale path is worse than no path -- it describes a route somebody may
    already have closed. Keyed on the data's own version, the moment a scan
    writes an asset the next read rebuilds, with no window in which the page is
    confidently wrong.
    """
    session = FakeSession(updated_at=NOW, count=12)
    first = await service.load_graph(session, ORG_A)  # type: ignore[arg-type]
    builds = session.builds

    session.updated_at = NOW + timedelta(minutes=1)
    second = await service.load_graph(session, ORG_A)  # type: ignore[arg-type]

    assert session.builds > builds
    assert first is not second


async def test_an_edge_removed_without_a_new_asset_still_invalidates() -> None:
    """Why the count is in the key.

    A scan that only removed an asset moves no timestamp: the rows that remain
    were not touched, and the one that went is not there to have a timestamp.
    Without the count, the graph would keep serving routes through something
    that is no longer in the estate.
    """
    session = FakeSession(updated_at=NOW, count=12)
    first = await service.load_graph(session, ORG_A)  # type: ignore[arg-type]

    session.count = 11
    second = await service.load_graph(session, ORG_A)  # type: ignore[arg-type]

    assert first is not second


async def test_one_tenant_never_receives_another_tenants_graph() -> None:
    """Asserted rather than assumed from the key looking right.

    This is a read cache in a process serving every customer, and the boundary
    it sits inside is the one thing this product cannot get wrong.
    """
    session = FakeSession(updated_at=NOW, count=12)

    a = await service.load_graph(session, ORG_A)  # type: ignore[arg-type]
    builds = session.builds
    b = await service.load_graph(session, ORG_B)  # type: ignore[arg-type]

    assert a is not b
    assert session.builds > builds, "the second tenant was served from the first"


async def test_it_holds_a_bounded_number_of_tenants() -> None:
    """A latency problem must not be traded for a memory one.

    An API process serves every tenant that asks. Holding a graph for each of
    them for as long as the process lives would make a busy day's memory a
    function of how many customers happened to open one page.
    """
    session = FakeSession(updated_at=NOW, count=1)

    for _ in range(service._MAX_CACHED + 4):
        await service.load_graph(session, uuid.uuid4())  # type: ignore[arg-type]

    assert len(service._cache) == service._MAX_CACHED


async def test_the_least_recently_used_tenant_is_the_one_dropped() -> None:
    """So a tenant reading the page constantly is not evicted by one that
    looked once."""
    session = FakeSession(updated_at=NOW, count=1)
    await service.load_graph(session, ORG_A)  # type: ignore[arg-type]

    for _ in range(service._MAX_CACHED - 1):
        await service.load_graph(session, uuid.uuid4())  # type: ignore[arg-type]

    # Kept warm, then one more tenant arrives and something has to go.
    await service.load_graph(session, ORG_A)  # type: ignore[arg-type]
    await service.load_graph(session, uuid.uuid4())  # type: ignore[arg-type]

    assert ORG_A in service._cache
