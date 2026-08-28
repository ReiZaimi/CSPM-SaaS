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
