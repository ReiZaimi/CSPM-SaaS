"""Putting a notification down, against real SQL and real policies.

Dismissal is per reader, and that is the whole point of testing it here: the
rows are shared by an organization, so "this one is gone" and "this one is gone
for me" look identical in a unit test with one user in it and are entirely
different products.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.core.db import service_session
from app.main import app
from tests.integration.conftest import create_org_as
from tests.integration.test_api import auth_header

pytestmark = pytest.mark.integration

NOW = datetime.now(UTC)


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def add_member(org_id: uuid.UUID, user_id: uuid.UUID) -> None:
    """A second reader in the same organization.

    No members API yet, so the row goes in directly on the owner connection --
    what a fixture needs and what the API must never do.
    """
    async with service_session() as session:
        await session.execute(
            text(
                "INSERT INTO organization_members (organization_id, user_id, role) "
                "VALUES (:org, :user, 'SECURITY_ANALYST')"
            ),
            {"org": org_id, "user": user_id},
        )
        await session.commit()


async def announce(org_id: uuid.UUID, subject: str, minutes_ago: int) -> uuid.UUID:
    async with service_session() as session:
        row = await session.execute(
            text(
                "INSERT INTO notifications "
                "(organization_id, kind, title, detail, subject_id, event_at) "
                "VALUES (:org, 'COVERAGE_DROP', :title, 'Checks that read it "
                "have no verdict until it is read again.', :subject, :at) "
                "RETURNING id"
            ),
            {
                "org": org_id,
                "title": f"{subject} could not be read",
                "subject": subject,
                "at": NOW - timedelta(minutes=minutes_ago),
            },
        )
        notification_id = row.scalar_one()
        await session.commit()
        return notification_id


async def listed(client: AsyncClient, user: uuid.UUID) -> list[dict]:
    response = await client.get("/api/v1/notifications", headers=auth_header(user))
    assert response.status_code == 200, response.text
    return response.json()["data"]


async def test_a_dismissed_notification_stops_being_listed(client, cleanup_orgs) -> None:
    user = uuid.uuid4()
    org_id = await create_org_as(user, "Bell Ltd")
    cleanup_orgs.append(org_id)
    first = await announce(org_id, "users", 10)
    await announce(org_id, "storage_accounts", 20)

    response = await client.delete(
        f"/api/v1/notifications/{first}", headers=auth_header(user)
    )

    assert response.status_code == 200, response.text
    remaining = await listed(client, user)
    assert [row["subject_id"] for row in remaining] == ["storage_accounts"]


async def test_dismissing_is_a_decision_about_one_reader(client, cleanup_orgs) -> None:
    """The reason this is a row and not a delete.

    What happened happened to the estate. One person being done with an item is
    not an argument that their colleagues should stop being told about it.
    """
    reader = uuid.uuid4()
    colleague = uuid.uuid4()
    org_id = await create_org_as(reader, "Shared Ltd")
    cleanup_orgs.append(org_id)
    await add_member(org_id, colleague)
    notification_id = await announce(org_id, "users", 10)

    await client.delete(
        f"/api/v1/notifications/{notification_id}", headers=auth_header(reader)
    )

    assert await listed(client, reader) == []
    assert [row["subject_id"] for row in await listed(client, colleague)] == ["users"]


async def test_clearing_empties_the_panel_for_the_person_asking(
    client, cleanup_orgs
) -> None:
    user = uuid.uuid4()
    org_id = await create_org_as(user, "Clear Ltd")
    cleanup_orgs.append(org_id)
    await announce(org_id, "users", 10)
    await announce(org_id, "storage_accounts", 20)

    response = await client.delete("/api/v1/notifications", headers=auth_header(user))

    assert response.status_code == 200, response.text
    assert response.json()["data"]["dismissed"] == 2
    assert await listed(client, user) == []


async def test_clearing_says_nothing_about_what_arrives_next(
    client, cleanup_orgs
) -> None:
    """Distinct from the read watermark, which is a boundary in time.

    Somebody who clears the panel and is then told about a new failure is being
    told about a new failure, not about the one they put down.
    """
    user = uuid.uuid4()
    org_id = await create_org_as(user, "Later Ltd")
    cleanup_orgs.append(org_id)
    await announce(org_id, "users", 30)
    await client.delete("/api/v1/notifications", headers=auth_header(user))

    await announce(org_id, "key_vaults", 1)

    assert [row["subject_id"] for row in await listed(client, user)] == ["key_vaults"]


async def test_dismissing_something_that_is_not_there_is_a_404(
    client, cleanup_orgs
) -> None:
    """Including another tenant's notification, which is the case that matters:
    recording a dismissal of a row this organization cannot see would answer a
    probe with a 200."""
    user = uuid.uuid4()
    org_id = await create_org_as(user, "Curious Ltd")
    cleanup_orgs.append(org_id)

    response = await client.delete(
        f"/api/v1/notifications/{uuid.uuid4()}", headers=auth_header(user)
    )

    assert response.status_code == 404
