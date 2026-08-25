"""Database engines and the RLS-scoped session.

Two connections, deliberately:

* ``app_engine``  -- logs in as ``cloudguard_app``, which owns nothing and is
  therefore fully subject to Row-Level Security. Every request-path query goes
  through here.
* ``owner_engine`` -- the table owner. Used by migrations and by the Celery
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
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings

app_engine = create_async_engine(
    settings.database_url,
    echo=settings.db_echo,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=5,
)

owner_engine = create_async_engine(
    settings.database_owner_url,
    echo=settings.db_echo,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=5,
)

AppSessionFactory = async_sessionmaker(app_engine, expire_on_commit=False, class_=AsyncSession)
OwnerSessionFactory = async_sessionmaker(owner_engine, expire_on_commit=False, class_=AsyncSession)


@asynccontextmanager
async def rls_session(user_id: UUID | str) -> AsyncIterator[AsyncSession]:
    """A session that PostgreSQL itself will constrain to ``user_id``'s tenants.

    ``SET LOCAL`` is transaction-scoped, so the role and claims are torn down on
    commit or rollback and cannot leak to the next checkout of a pooled
    connection.
    """
    claims = json.dumps({"sub": str(user_id), "role": "authenticated"})
    session = AppSessionFactory()
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
    session = OwnerSessionFactory()
    try:
        yield session
    finally:
        await session.close()


async def ping() -> bool:
    async with app_engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    return True
