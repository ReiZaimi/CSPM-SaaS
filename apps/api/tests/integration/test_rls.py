"""Row-Level Security: a required test category, not optional coverage.

Everything here runs through ``rls_session``, which is exactly what the API uses
for request handling: connect as the non-owner ``cloudguard_app`` role, set
``request.jwt.claims``, and let PostgreSQL decide what is visible. No test here
adds its own ``WHERE organization_id = ...`` -- that would be testing the
application layer, and the whole point is that the database enforces isolation
independently of it (SECURITY.md section 2).
"""

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from app.core.db import rls_session
from tests.integration.conftest import create_org_as

pytestmark = pytest.mark.integration

USER_A = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")
USER_B = uuid.UUID("bbbbbbbb-0000-0000-0000-00000000000b")


@pytest.fixture
async def two_orgs(cleanup_orgs):
    org_a = await create_org_as(USER_A, "Org A")
    org_b = await create_org_as(USER_B, "Org B")
    cleanup_orgs.extend([org_a, org_b])
    return org_a, org_b


class TestOrganizationIsolation:
    async def test_user_sees_only_their_own_organization(self, two_orgs) -> None:
        org_a, org_b = two_orgs
        async with rls_session(USER_A) as session:
            rows = (await session.execute(text("SELECT id FROM organizations"))).scalars().all()
        assert org_a in rows
        assert org_b not in rows

    async def test_direct_lookup_of_another_org_returns_nothing(self, two_orgs) -> None:
        """Even naming the id explicitly must not reveal the row."""
        _, org_b = two_orgs
        async with rls_session(USER_A) as session:
            row = (
                await session.execute(
                    text("SELECT id FROM organizations WHERE id = :id"), {"id": org_b}
                )
            ).scalar_one_or_none()
        assert row is None

    async def test_unauthenticated_session_sees_nothing(self, two_orgs) -> None:
        async with rls_session(uuid.uuid4()) as session:
            rows = (await session.execute(text("SELECT id FROM organizations"))).scalars().all()
        assert rows == []


class TestTenantDataIsolation:
    async def test_cloud_accounts_do_not_leak_across_tenants(self, two_orgs) -> None:
        org_a, org_b = two_orgs

        async with rls_session(USER_A) as session:
            await session.execute(
                text(
                    "INSERT INTO cloud_accounts (organization_id, account_name, tenant_id) "
                    "VALUES (:org, 'A Production', 'tenant-a')"
                ),
                {"org": org_a},
            )
        async with rls_session(USER_B) as session:
            await session.execute(
                text(
                    "INSERT INTO cloud_accounts (organization_id, account_name, tenant_id) "
                    "VALUES (:org, 'B Production', 'tenant-b')"
                ),
                {"org": org_b},
            )

        async with rls_session(USER_A) as session:
            names = (
                await session.execute(text("SELECT account_name FROM cloud_accounts"))
            ).scalars().all()

        assert "A Production" in names
        assert "B Production" not in names

    async def test_cannot_write_into_another_tenant(self, two_orgs) -> None:
        """The WITH CHECK clause: PostgreSQL refuses the row outright, so a bug
        in the service layer cannot create cross-tenant data."""
        _, org_b = two_orgs
        with pytest.raises((DBAPIError, ProgrammingError)) as exc:
            async with rls_session(USER_A) as session:
                await session.execute(
                    text(
                        "INSERT INTO cloud_accounts (organization_id, account_name, tenant_id) "
                        "VALUES (:org, 'Stolen', 'tenant-x')"
                    ),
                    {"org": org_b},
                )
        assert "row-level security" in str(exc.value).lower()

    async def test_cannot_update_another_tenants_row(self, two_orgs) -> None:
        org_a, org_b = two_orgs
        async with rls_session(USER_B) as session:
            await session.execute(
                text(
                    "INSERT INTO cloud_accounts (organization_id, account_name, tenant_id) "
                    "VALUES (:org, 'B Only', 'tenant-b2')"
                ),
                {"org": org_b},
            )

        async with rls_session(USER_A) as session:
            result = await session.execute(
                text(
                    "UPDATE cloud_accounts SET account_name = 'hijacked' "
                    "WHERE organization_id = :org"
                ),
                {"org": org_b},
            )
        # Not an error -- the row is simply invisible, so nothing is updated.
        assert result.rowcount == 0

        async with rls_session(USER_B) as session:
            names = (
                await session.execute(text("SELECT account_name FROM cloud_accounts"))
            ).scalars().all()
        assert "hijacked" not in names

    async def test_cannot_delete_another_tenants_row(self, two_orgs) -> None:
        org_a, _ = two_orgs
        async with rls_session(USER_A) as session:
            await session.execute(
                text(
                    "INSERT INTO cloud_accounts (organization_id, account_name, tenant_id) "
                    "VALUES (:org, 'A Keeper', 'tenant-a3')"
                ),
                {"org": org_a},
            )

        async with rls_session(USER_B) as session:
            result = await session.execute(
                text("DELETE FROM cloud_accounts WHERE organization_id = :org"),
                {"org": org_a},
            )
        assert result.rowcount == 0

        async with rls_session(USER_A) as session:
            count = (
                await session.execute(text("SELECT count(*) FROM cloud_accounts"))
            ).scalar_one()
        assert count >= 1


class TestMembershipEscalation:
    async def test_cannot_add_self_to_another_organization(self, two_orgs) -> None:
        """The obvious attack on a membership-resolved tenancy model."""
        _, org_b = two_orgs
        with pytest.raises((DBAPIError, ProgrammingError)) as exc:
            async with rls_session(USER_A) as session:
                await session.execute(
                    text(
                        "INSERT INTO organization_members (organization_id, user_id, role) "
                        "VALUES (:org, :user, 'OWNER')"
                    ),
                    {"org": org_b, "user": USER_A},
                )
        assert "row-level security" in str(exc.value).lower()

    async def test_cannot_see_another_organizations_members(self, two_orgs) -> None:
        async with rls_session(USER_A) as session:
            rows = (
                await session.execute(text("SELECT user_id FROM organization_members"))
            ).scalars().all()
        assert rows, "User A should see their own membership"
        assert set(rows) == {USER_A}


class TestRuleCatalogueIsReadOnly:
    async def test_rules_are_readable_by_everyone(self, two_orgs, rule_catalogue) -> None:
        async with rls_session(USER_A) as session:
            count = (await session.execute(text("SELECT count(*) FROM rules"))).scalar_one()
        assert count > 0

    async def test_rules_cannot_be_written_through_the_app_role(self, two_orgs) -> None:
        """The rules table is a read-mirror of the Python registry. Changing a
        rule means changing code (RULE_ENGINE.md section 4)."""
        with pytest.raises((DBAPIError, ProgrammingError)) as exc:
            async with rls_session(USER_A) as session:
                await session.execute(
                    text(
                        "INSERT INTO rules (rule_id, name, description, category, provider, "
                        "severity, version, scope, remediation) VALUES "
                        "('EVIL-001','evil','evil','network','azure','LOW','1.0',"
                        "'per_resource','none')"
                    )
                )
        assert "permission denied" in str(exc.value).lower()

    async def test_existing_rules_cannot_be_disabled_through_the_app_role(
        self, two_orgs
    ) -> None:
        with pytest.raises((DBAPIError, ProgrammingError)) as exc:
            async with rls_session(USER_A) as session:
                await session.execute(text("UPDATE rules SET enabled = false"))
        assert "permission denied" in str(exc.value).lower()


class TestConnectionRoleItself:
    async def test_application_role_is_not_the_table_owner(self) -> None:
        """The premise the entire RLS design rests on: an owner would be exempt
        from these policies, and the isolation would be theatre."""
        async with rls_session(USER_A) as session:
            is_owner = (
                await session.execute(
                    text(
                        "SELECT pg_catalog.pg_get_userbyid(relowner) = current_user "
                        "FROM pg_class WHERE relname = 'cloud_accounts'"
                    )
                )
            ).scalar_one()
        assert is_owner is False

    async def test_application_role_cannot_bypass_rls(self) -> None:
        async with rls_session(USER_A) as session:
            bypass = (
                await session.execute(
                    text("SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user")
                )
            ).scalar_one()
        assert bypass is False
