"""Integration fixtures. These need a live PostgreSQL with migrations applied."""

import uuid
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy import text

from app.core.db import dispose_engines, rls_session, service_session
from app.services.rule_sync import sync_rules_to_database


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

    ``dispose_engines`` rather than an enumerated list, and that is the point of
    the change: this fixture used to name the app and owner engines by hand, so
    adding a third -- the worker connection, whose row-level security holds a
    scan to one organization -- left its pool undrained and turned fifty-odd
    integration tests into "got Future attached to a different loop". The
    application already has one function that knows the whole set, and it is the
    same function the Celery worker calls for the same reason.
    """
    yield
    await dispose_engines()


@pytest_asyncio.fixture
async def rule_catalogue() -> None:
    """Populate the ``rules`` read-mirror from the Python registry.

    In a running deployment the app's lifespan does this at startup, but httpx's
    ASGITransport deliberately does not run lifespan events -- so a test that
    reads the catalogue has to sync it itself.

    Requested explicitly rather than made autouse: a test that depends on the
    table being populated should say so in its signature. Relying on a server
    having happened to start against the same database is how these two tests
    passed locally while failing in CI.
    """
    await sync_rules_to_database()
