"""Declaring what a subscription is worth, over the real API.

The one write path where the customer is the source of truth rather than the
customer's cloud, so the things worth proving are the things that make a
statement a statement: it round-trips, it can be withdrawn, it is attributed,
and it does not cross a tenant boundary.
"""

import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.core.db import service_session
from app.core.enums import (
    CloudAccountStatus,
    ConnectionScope,
    ConsentStatus,
    Provider,
)
from app.main import app
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from tests.integration.test_api import auth_header, make_org

pytestmark = pytest.mark.integration

TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def discovered_subscription(org_id: uuid.UUID) -> uuid.UUID:
    """A subscription as discovery leaves one.

    Inserted rather than posted, because there is no endpoint that creates one:
    a cloud account is something Azure told CloudGuard about, which is exactly
    the distinction a declaration is stored separately from.
    """
    async with service_session() as session:
        connection = CloudConnection(
            organization_id=org_id,
            provider=Provider.AZURE,
            name="tenant",
            scope_type=ConnectionScope.TENANT_ROOT,
            role_version="v1",
            tenant_id=TENANT,
            consent_status=ConsentStatus.GRANTED,
            status=CloudAccountStatus.ACTIVE,
        )
        session.add(connection)
        await session.flush()

        account = CloudAccount(
            organization_id=org_id,
            connection_id=connection.id,
            provider=Provider.AZURE,
            account_name="Production Subscription",
            tenant_id=TENANT,
            subscription_id="00000000-0000-0000-0000-000000000001",
            consent_status=ConsentStatus.GRANTED,
            status=CloudAccountStatus.ACTIVE,
        )
        session.add(account)
        await session.commit()
        return account.id


class TestDeclaringContext:
    async def test_a_declaration_round_trips(self, client, cleanup_orgs) -> None:
        user = uuid.uuid4()
        org_id = uuid.UUID(await make_org(client, user, "Context Ltd"))
        cleanup_orgs.append(org_id)
        account_id = await discovered_subscription(org_id)

        put = await client.put(
            f"/api/v1/cloud-accounts/{account_id}/context",
            json={
                "environment": "production",
                "criticality": "CRITICAL",
                "note": "holds the payroll export",
            },
            headers=auth_header(user),
        )
        assert put.status_code == 200, put.text

        got = await client.get(
            f"/api/v1/cloud-accounts/{account_id}/context", headers=auth_header(user)
        )
        declaration = got.json()["data"]
        assert declaration["environment"] == "production"
        assert declaration["criticality"] == "CRITICAL"
        assert declaration["note"] == "holds the payroll export"
        # Attributed, because "who says this is production" is a question people
        # ask of the label rather than of the audit log.
        assert declaration["declared_by_user_id"] == str(user)

    async def test_nothing_declared_is_null_rather_than_a_404(
        self, client, cleanup_orgs
    ) -> None:
        """A subscription nobody has described is a subscription, not a missing
        one. Only "that is not yours" earns a 404 here."""
        user = uuid.uuid4()
        org_id = uuid.UUID(await make_org(client, user, "Quiet Ltd"))
        cleanup_orgs.append(org_id)
        account_id = await discovered_subscription(org_id)

        response = await client.get(
            f"/api/v1/cloud-accounts/{account_id}/context", headers=auth_header(user)
        )
        assert response.status_code == 200
        assert response.json()["data"] is None

    async def test_a_put_replaces_rather_than_patches(
        self, client, cleanup_orgs
    ) -> None:
        """A statement is replaced entire. A field left out is one the customer
        is no longer claiming, and anything else leaves nobody able to say what
        the declaration currently says without diffing it."""
        user = uuid.uuid4()
        org_id = uuid.UUID(await make_org(client, user, "Replace Ltd"))
        cleanup_orgs.append(org_id)
        account_id = await discovered_subscription(org_id)

        await client.put(
            f"/api/v1/cloud-accounts/{account_id}/context",
            json={"environment": "production", "criticality": "HIGH"},
            headers=auth_header(user),
        )
        await client.put(
            f"/api/v1/cloud-accounts/{account_id}/context",
            json={"criticality": "HIGH"},
            headers=auth_header(user),
        )

        got = await client.get(
            f"/api/v1/cloud-accounts/{account_id}/context", headers=auth_header(user)
        )
        assert got.json()["data"]["environment"] is None
        assert got.json()["data"]["criticality"] == "HIGH"

    async def test_declaring_nothing_withdraws_the_declaration(
        self, client, cleanup_orgs
    ) -> None:
        """Cleared rather than kept as a row of NULLs.

        "Go back to what you can work out yourself" is a different answer from
        "somebody declined to say", and only one of them is what happened.
        """
        user = uuid.uuid4()
        org_id = uuid.UUID(await make_org(client, user, "Withdraw Ltd"))
        cleanup_orgs.append(org_id)
        account_id = await discovered_subscription(org_id)

        await client.put(
            f"/api/v1/cloud-accounts/{account_id}/context",
            json={"criticality": "CRITICAL"},
            headers=auth_header(user),
        )
        deleted = await client.delete(
            f"/api/v1/cloud-accounts/{account_id}/context", headers=auth_header(user)
        )
        assert deleted.status_code == 200

        rows = await _declaration_rows(account_id)
        assert rows == []

    async def test_unknown_cannot_be_declared(self, client, cleanup_orgs) -> None:
        """UNKNOWN is CloudGuard's own answer for "nothing said anything".

        A customer declaring it would be asserting an absence, which leaving the
        field out already does -- and more clearly, since it also withdraws.
        """
        user = uuid.uuid4()
        org_id = uuid.UUID(await make_org(client, user, "Unknown Ltd"))
        cleanup_orgs.append(org_id)
        account_id = await discovered_subscription(org_id)

        response = await client.put(
            f"/api/v1/cloud-accounts/{account_id}/context",
            json={"criticality": "UNKNOWN"},
            headers=auth_header(user),
        )
        assert response.status_code == 422

    async def test_another_tenant_cannot_declare_on_your_subscription(
        self, client, cleanup_orgs
    ) -> None:
        """A declaration changes how findings rank. Writing one into somebody
        else's tenant would be editing their security posture."""
        owner, outsider = uuid.uuid4(), uuid.uuid4()
        org_a = uuid.UUID(await make_org(client, owner, "Owner Ltd"))
        org_b = uuid.UUID(await make_org(client, outsider, "Outsider Ltd"))
        cleanup_orgs.extend([org_a, org_b])
        account_id = await discovered_subscription(org_a)

        response = await client.put(
            f"/api/v1/cloud-accounts/{account_id}/context",
            json={"criticality": "LOW"},
            headers=auth_header(outsider),
        )
        assert response.status_code == 404
        assert await _declaration_rows(account_id) == []


async def _declaration_rows(account_id: uuid.UUID) -> list:
    async with service_session() as session:
        return list(
            (
                await session.execute(
                    text(
                        "SELECT id FROM context_declarations "
                        "WHERE cloud_account_id = :a"
                    ),
                    {"a": account_id},
                )
            ).all()
        )
