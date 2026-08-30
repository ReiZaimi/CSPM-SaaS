"""Who finishes a transaction.

Two session contracts exist and service code is reachable from both.
``rls_session`` wraps an entire request in ``session.begin()``; a plain
``service_session`` leaves committing to its caller. A service function cannot
tell them apart, so it asks.

Getting this wrong fails twice over. Everything after the stray commit raises
"Can't operate on closed transaction inside context manager" -- which is how it
was found, as a 500 on the connections page. The quieter half is worse:
``SET LOCAL ROLE authenticated`` and the JWT claims are transaction-scoped, so
committing tears down the settings RLS depends on, and any statement that did
run afterwards would run without them.
"""

from app.core.db import EXTERNAL_TRANSACTION, commit_unless_externally_managed


class FakeSession:
    def __init__(self, *, externally_managed: bool) -> None:
        self.info: dict = {EXTERNAL_TRANSACTION: True} if externally_managed else {}
        self.commits = 0

    async def commit(self) -> None:
        self.commits += 1


async def test_a_request_session_is_left_alone() -> None:
    """`rls_session` commits on exit. A service must not do it early."""
    session = FakeSession(externally_managed=True)

    for _ in range(3):
        await commit_unless_externally_managed(session)

    assert session.commits == 0


async def test_a_worker_session_is_committed() -> None:
    """`service_session` has no context manager to finish it."""
    session = FakeSession(externally_managed=False)

    await commit_unless_externally_managed(session)
    await commit_unless_externally_managed(session)

    assert session.commits == 2


async def test_the_rls_session_marks_itself() -> None:
    """The mark has to be set where the transaction is opened, or every
    service call reachable from a request commits early again."""
    import inspect

    from app.core import db

    source = inspect.getsource(db.rls_session)
    assert "EXTERNAL_TRANSACTION" in source
    assert "session.begin()" in source


# ------------------------------------------------------- worker tenancy
def test_a_scan_runs_on_the_worker_connection_when_one_is_configured() -> None:
    """The point of the role: PostgreSQL, not the pipeline, holds the boundary.

    Unset, the worker keeps using the owner connection -- which is what it did
    before and which RLS does not constrain -- so adopting the role is a
    deployment step rather than a flag day.
    """
    from app.core.config import Settings

    unset = Settings(
        database_url="postgresql+asyncpg://app@h/db",
        database_owner_url="postgresql+asyncpg://owner@h/db",
    )
    assert not unset.worker_is_constrained
    assert unset.scan_database_url == unset.database_owner_url

    configured = Settings(
        database_url="postgresql+asyncpg://app@h/db",
        database_owner_url="postgresql+asyncpg://owner@h/db",
        database_worker_url="postgresql+asyncpg://worker@h/db",
    )
    assert configured.worker_is_constrained
    assert configured.scan_database_url == configured.database_worker_url


def test_the_scan_session_declares_its_organization_transaction_locally() -> None:
    """``SET LOCAL``, so the claim is torn down on commit or rollback.

    A session-scoped setting would survive the transaction and leak to the next
    checkout of a pooled connection -- which for this particular setting means
    the next scan running under the previous scan's organization.
    """
    import inspect

    from app.core import db

    source = inspect.getsource(db.scan_session)
    assert "set_config('app.organization_id'" in source
    # The third argument to set_config is is_local; true confines it to the
    # transaction, exactly as rls_session does with the JWT claims.
    assert ":org, true" in source


def test_housekeeping_keeps_the_unconstrained_session() -> None:
    """The reaper looks for abandoned work across every organization, which is
    exactly what a per-organization session cannot see.

    Pinned so the constrained session is not applied to it by tidiness: doing
    so would either break the reaper or require a claim meaning "see
    everything", which is a bypass with a friendly name.
    """
    import inspect

    from app.workers import scan_tasks

    source = inspect.getsource(scan_tasks._reap_and_release)
    assert "service_session()" in source
    assert "scan_session(" not in source
