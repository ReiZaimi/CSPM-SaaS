"""Database engines and the RLS-scoped session.

Two connections, deliberately:

* ``get_app_engine()``  -- logs in as ``cloudguard_app``, which owns nothing and is
  therefore fully subject to Row-Level Security. Every request-path query goes
  through here.
* ``get_owner_engine()`` -- the table owner. Used by migrations and by the Celery
  worker, which has no authenticated user to resolve policies against. Worker
  code must scope by ``organization_id`` explicitly, taken from the scan record
  it was handed -- never from client input.

The request session emulates exactly what Supabase's PostgREST does: it sets
``request.jwt.claims`` and switches to the ``authenticated`` role for the life
of the transaction. That means one set of RLS policies works identically
against local PostgreSQL and against a real Supabase project.
"""

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import lru_cache
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings


# Engines are built on first use rather than at import. Importing a module
# should not open a connection pool: it makes the whole package unimportable
# wherever a database is not reachable -- including test collection, which
# needs to read these files without touching PostgreSQL.
@lru_cache
def get_app_engine() -> AsyncEngine:
    return create_async_engine(
        settings.database_url,
        echo=settings.db_echo,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=5,
    )


@lru_cache
def get_owner_engine() -> AsyncEngine:
    return create_async_engine(
        settings.database_owner_url,
        echo=settings.db_echo,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
    )


@lru_cache
def _app_session_factory() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(get_app_engine(), expire_on_commit=False, class_=AsyncSession)


@lru_cache
def _owner_session_factory() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(get_owner_engine(), expire_on_commit=False, class_=AsyncSession)


async def dispose_engines() -> None:
    """Close every pooled connection, and do it inside the running loop.

    asyncpg binds a connection to the event loop that opened it, while the
    engines above are cached per *process*. That is fine for the API, which has
    one loop for its lifetime, and wrong for the Celery worker, which calls
    ``asyncio.run`` per task: the first scan fills the pool on loop one, that
    loop closes, and the second scan is handed a connection belonging to a loop
    that no longer exists --

        RuntimeError: got Future attached to a different loop
        RuntimeError: Event loop is closed

    So a task disposes before its loop ends. The engine objects survive in the
    cache -- they are not loop-bound, only their connections are -- and the next
    task opens fresh ones on its own loop.

    Must be awaited while the loop is still alive. Disposing afterwards would
    need a loop to close the connections on, which is the very thing that has
    gone.
    """
    for engine in (get_app_engine(), get_owner_engine()):
        await engine.dispose()


# Set on sessions whose transaction is owned by the context manager that
# created them, rather than by the code using them.
EXTERNAL_TRANSACTION = "externally_managed_transaction"


async def commit_unless_externally_managed(session: AsyncSession) -> None:
    """Commit, unless someone else owns this transaction.

    Two session contracts exist and service code is reachable from both.
    ``rls_session`` wraps a whole request in ``session.begin()``, so it commits
    on exit; ``service_session`` hands out a plain session that its caller must
    commit itself.

    Committing inside ``rls_session`` is not merely redundant, it is wrong
    twice over. Everything afterwards fails with "Can't operate on closed
    transaction inside context manager" -- and more quietly, ``SET LOCAL ROLE
    authenticated`` and the JWT claims are transaction-scoped, so a commit tears
    down the very settings RLS depends on. Any statement that did run after one
    would run without them.
    """
    if session.info.get(EXTERNAL_TRANSACTION):
        return
    await session.commit()


@asynccontextmanager
async def rls_session(user_id: UUID | str) -> AsyncIterator[AsyncSession]:
    """A session that PostgreSQL itself will constrain to ``user_id``'s tenants.

    ``SET LOCAL`` is transaction-scoped, so the role and claims are torn down on
    commit or rollback and cannot leak to the next checkout of a pooled
    connection.
    """
    claims = json.dumps({"sub": str(user_id), "role": "authenticated"})
    session = _app_session_factory()()
    # Marks the transaction as this context manager's to finish. Service code
    # is called from here *and* from `service_session`, and cannot otherwise
    # tell which -- see `commit_unless_externally_managed`.
    session.info[EXTERNAL_TRANSACTION] = True
    try:
        async with session.begin():
            await session.execute(
                text("SELECT set_config('request.jwt.claims', :claims, true)"),
                {"claims": claims},
            )
            await session.execute(text("SET LOCAL ROLE authenticated"))
            yield session
    finally:
        await session.close()


@asynccontextmanager
async def service_session() -> AsyncIterator[AsyncSession]:
    """Owner-level session. Bypasses RLS -- worker and migration use only.

    Anything called with this session is responsible for its own
    ``organization_id`` scoping.
    """
    session = _owner_session_factory()()
    try:
        yield session
    finally:
        await session.close()


async def ping() -> bool:
    async with get_app_engine().connect() as conn:
        await conn.execute(text("SELECT 1"))
    return True
