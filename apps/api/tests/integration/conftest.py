"""Integration fixtures. These need a live PostgreSQL with migrations applied."""

import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy import text

from app.core.db import app_engine, owner_engine, rls_session, service_session


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


@pytest_asyncio.fixture
async def cleanup_orgs() -> AsyncIterator[list[uuid.UUID]]:
    """Track organizations created by a test and cascade-delete them afterwards."""
    created: list[uuid.UUID] = []
    yield created
    async with service_session() as session:
        for org_id in created:
            await session.execute(
                text("DELETE FROM organizations WHERE id = :id"), {"id": org_id}
            )
        await session.commit()


async def create_org_as(user_id: uuid.UUID, name: str) -> uuid.UUID:
    """Create an organization through the same path the API uses."""
    async with rls_session(user_id) as session:
        result = await session.execute(
            text("SELECT app.create_organization(:name, :slug, NULL, NULL) AS id"),
            {"name": name, "slug": f"{name.lower().replace(' ', '-')}-{uuid.uuid4().hex[:6]}"},
        )
        return result.scalar_one()


@pytest_asyncio.fixture(autouse=True)
async def _reset_connection_pools() -> AsyncIterator[None]:
    """Dispose pooled connections between tests.

    The engines are module-level singletons, but pytest-asyncio gives each test
    its own event loop. A pooled asyncpg connection created under one loop
    explodes when reused under the next, so the pool is drained after every test.
    """
    yield
    await app_engine.dispose()
    await owner_engine.dispose()
