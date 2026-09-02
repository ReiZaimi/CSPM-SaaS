"""Row-Level Security: a required test category, not optional coverage.

Everything here runs through ``rls_session``, which is exactly what the API uses
for request handling: connect as the non-owner ``cloudguard_app`` role, set
``request.jwt.claims``, and let PostgreSQL decide what is visible. No test here
adds its own ``WHERE organization_id = ...`` -- that would be testing the
application layer, and the whole point is that the database enforces isolation
independently of it (SECURITY.md section 2).
"""

import uuid
from contextlib import asynccontextmanager
from typing import ClassVar

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from app.core.config import settings
from app.core.db import rls_session, scan_session, service_session
from app.core.payloads import canonical, compress
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


class TestCollectionStatusIsolation:
    """A new tenant-owned table is only isolated if someone wrote the policy.

    ``0001`` applied policies by iterating TENANT_TABLES, so every table added
    after it carries its own. That is a per-migration decision with no guard
    behind it, which makes this the guard: an unpolicied table reads as an
    ordinary table right up until one customer can enumerate another's
    infrastructure gaps.
    """

    async def _seed(self, session, org_id: uuid.UUID, task: str) -> None:
        """One scan, one subscription, one reading."""
        await session.execute(
            text(
                "INSERT INTO cloud_accounts (id, organization_id, account_name, tenant_id) "
                "VALUES (:aid, :org, 'Sub', 'tenant-x')"
            ),
            {"aid": (aid := uuid.uuid4()), "org": org_id},
        )
        await session.execute(
            text(
                "INSERT INTO scans (id, organization_id, cloud_account_id, status) "
                "VALUES (:sid, :org, :aid, 'COMPLETED')"
            ),
            {"sid": (sid := uuid.uuid4()), "org": org_id, "aid": aid},
        )
        await session.execute(
            text(
                "INSERT INTO evidence "
                "(organization_id, scan_id, cloud_account_id, evidence_key, category, outcome) "
                "VALUES (:org, :sid, :aid, :task, 'storage', 'PARTIAL')"
            ),
            {"org": org_id, "sid": sid, "aid": aid, "task": task},
        )

    async def test_collection_results_do_not_leak_across_tenants(
        self, two_orgs
    ) -> None:
        org_a, org_b = two_orgs

        async with rls_session(USER_A) as session:
            await self._seed(session, org_a, "a_storage")
        async with rls_session(USER_B) as session:
            await self._seed(session, org_b, "b_storage")

        async with rls_session(USER_A) as session:
            keys = (
                await session.execute(
                    text("SELECT evidence_key FROM evidence")
                )
            ).scalars().all()

        assert "a_storage" in keys
        assert "b_storage" not in keys, "one tenant read another's collection gaps"

    async def test_cannot_write_collection_results_into_another_tenant(
        self, two_orgs
    ) -> None:
        org_a, org_b = two_orgs
        async with rls_session(USER_A) as session:
            await self._seed(session, org_a, "mine")
            scan_id = (
                await session.execute(
                    text("SELECT id FROM scans WHERE organization_id = :org"),
                    {"org": org_a},
                )
            ).scalar_one()
            account_id = (
                await session.execute(
                    text("SELECT id FROM cloud_accounts WHERE organization_id = :org"),
                    {"org": org_a},
                )
            ).scalar_one()

        with pytest.raises((DBAPIError, ProgrammingError)) as exc:
            async with rls_session(USER_A) as session:
                await session.execute(
                    text(
                        "INSERT INTO evidence "
                        "(organization_id, scan_id, cloud_account_id, evidence_key, "
                        "category, outcome) "
                        "VALUES (:org, :sid, :aid, 'stolen', 'storage', 'FAILED')"
                    ),
                    {"org": org_b, "sid": scan_id, "aid": account_id},
                )
        assert "row-level security" in str(exc.value).lower()


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


class TestEvidenceBlobIsolation:
    """Content-addressed storage, scoped per tenant on purpose.

    A blob table shared across tenants would deduplicate correctly and still be
    wrong: whether a write finds an existing row is observable, so a shared
    table lets one tenant learn that another holds identical bytes. The
    organization is half the primary key, so there is no way to address a blob
    without naming whose it is.
    """

    PAYLOAD: ClassVar[dict] = {"storage_accounts": []}

    async def _seed(self, session, org_id: uuid.UUID, digest: str) -> None:
        stored = compress(self.PAYLOAD)
        await session.execute(
            text(
                "INSERT INTO evidence_blobs "
                "(organization_id, content_hash, payload_compressed, byte_size, "
                " stored_bytes) "
                "VALUES (:org, :hash, :payload, :size, :stored)"
            ),
            {
                "org": org_id,
                "hash": digest,
                "payload": stored,
                "size": len(canonical(self.PAYLOAD)),
                "stored": len(stored),
            },
        )

    async def test_identical_content_stays_two_rows_in_two_tenants(
        self, two_orgs
    ) -> None:
        """The same bytes in two tenants are two rows, not one shared row.

        Deduplication is a saving inside a tenant, never a structure spanning
        them.
        """
        org_a, org_b = two_orgs
        digest = "a" * 64

        async with rls_session(USER_A) as session:
            await self._seed(session, org_a, digest)
        async with rls_session(USER_B) as session:
            await self._seed(session, org_b, digest)

        async with rls_session(USER_A) as session:
            rows = (
                await session.execute(
                    text("SELECT organization_id FROM evidence_blobs")
                )
            ).scalars().all()

        assert rows == [org_a], "a tenant saw a payload row belonging to another"

    async def test_cannot_write_a_blob_into_another_tenant(self, two_orgs) -> None:
        _, org_b = two_orgs
        with pytest.raises((DBAPIError, ProgrammingError)) as exc:
            async with rls_session(USER_A) as session:
                await self._seed(session, org_b, "b" * 64)
        assert "row-level security" in str(exc.value).lower()


@asynccontextmanager
async def worker_engine_session():
    """A worker connection that declares no organization.

    Deliberately not exported from ``app.core.db``: the application has no use
    for one, and offering it would be offering the mistake this test exists to
    prove is harmless.
    """
    from app.core.db import _worker_session_factory

    session = _worker_session_factory()()
    try:
        async with session.begin():
            yield session
    finally:
        await session.close()


class TestWorkerTenancy:
    """The worker's isolation, enforced by PostgreSQL rather than by review.

    The API is tenant-isolated twice over: the service layer derives the
    organization from a verified JWT, and RLS re-checks it because requests
    connect as a role that owns nothing. The worker had only the first half --
    it connected as the table owner, so every ``organization_id`` filter in the
    scan pipeline was the whole of the boundary.

    These run against ``cloudguard_worker``, whose policy arm trusts the
    organization a scan declares. Running them on the owner connection would
    pass while proving nothing, which is the same trap the rest of this file
    describes.
    """

    async def _seed(self, org_id: uuid.UUID) -> uuid.UUID:
        async with service_session() as session:
            scan_id = uuid.uuid4()
            await session.execute(
                text(
                    "INSERT INTO scans (id, organization_id, status) "
                    "VALUES (:sid, :org, 'COMPLETED')"
                ),
                {"sid": scan_id, "org": org_id},
            )
            await session.commit()
        return scan_id

    async def test_a_scan_session_sees_only_its_own_organization(
        self, two_orgs
    ) -> None:
        org_a, org_b = two_orgs
        mine = await self._seed(org_a)
        theirs = await self._seed(org_b)

        async with scan_session(org_a) as session:
            visible = set(
                (await session.execute(text("SELECT id FROM scans"))).scalars().all()
            )

        assert mine in visible
        assert theirs not in visible, "a scan session reached another tenant's rows"

    async def test_a_scan_session_cannot_write_into_another_organization(
        self, two_orgs
    ) -> None:
        """The WITH CHECK half. A pipeline bug that carried the wrong
        organization onto a row is refused by the database rather than
        written."""
        org_a, org_b = two_orgs
        if not settings.worker_is_constrained:
            pytest.skip("worker role not configured; nothing below the code checks")

        with pytest.raises((DBAPIError, ProgrammingError)) as exc:
            async with scan_session(org_a) as session:
                await session.execute(
                    text(
                        "INSERT INTO scans (id, organization_id, status) "
                        "VALUES (:sid, :org, 'QUEUED')"
                    ),
                    {"sid": uuid.uuid4(), "org": org_b},
                )
        assert "row-level security" in str(exc.value).lower()

    async def test_a_session_that_declares_nothing_sees_nothing(self) -> None:
        """Failing closed is the only acceptable direction for this mistake.

        ``app.current_org()`` reads as NULL when unset, and ``NULL =
        organization_id`` is NULL rather than true -- so a worker session that
        forgot to declare its organization reads an empty database instead of
        every tenant's.
        """
        if not settings.worker_is_constrained:
            pytest.skip("worker role not configured; the owner connection sees all")

        async with worker_engine_session() as session:
            rows = (
                await session.execute(text("SELECT count(*) FROM scans"))
            ).scalar_one()
        assert rows == 0

    async def test_the_claim_survives_the_pipeline_committing(
        self, two_orgs
    ) -> None:
        """The regression that took thirty-two tests with it.

        ``SET LOCAL`` is transaction-scoped, which is what stops the claim
        leaking to the next checkout of a pooled connection -- and it also means
        it dies at the first ``commit``. The pipeline commits many times, so a
        claim declared once left every later statement running with no
        organization: no error, just a session that reads an empty database and
        cannot write.
        """
        org_a, _org_b = two_orgs
        mine = await self._seed(org_a)

        async with scan_session(org_a) as session:
            before = (
                await session.execute(text("SELECT count(*) FROM scans"))
            ).scalar_one()
            # Exactly what the pipeline does between phases.
            await session.commit()
            after = (
                await session.execute(text("SELECT count(*) FROM scans"))
            ).scalar_one()

        assert before >= 1, "the seeded scan should be visible"
        assert after == before, "the organization claim did not survive the commit"

        async with scan_session(org_a) as session:
            visible = set(
                (await session.execute(text("SELECT id FROM scans"))).scalars().all()
            )
        assert mine in visible

    async def test_a_write_after_a_commit_is_still_constrained(
        self, two_orgs
    ) -> None:
        """Re-declaring the claim must not become a way around the check.

        A listener that re-issued the wrong organization -- or issued nothing
        and left the session unconstrained -- would look identical from the
        read side and be a cross-tenant write on this one.
        """
        org_a, org_b = two_orgs
        if not settings.worker_is_constrained:
            pytest.skip("worker role not configured; nothing below the code checks")

        with pytest.raises((DBAPIError, ProgrammingError)) as exc:
            async with scan_session(org_a) as session:
                await session.commit()
                await session.execute(
                    text(
                        "INSERT INTO scans (id, organization_id, status) "
                        "VALUES (:sid, :org, 'QUEUED')"
                    ),
                    {"sid": uuid.uuid4(), "org": org_b},
                )
        assert "row-level security" in str(exc.value).lower()

    async def test_the_worker_role_does_not_inherit_the_membership_arm(
        self, two_orgs
    ) -> None:
        """The two roles resolve tenancy differently on purpose.

        Granting ``authenticated`` to the worker would give it the
        membership-based arm as well, and a scan running as a user who happens
        to belong to several organizations would quietly see all of them.
        """
        if not settings.worker_is_constrained:
            pytest.skip("worker role not configured")

        async with service_session() as session:
            inherited = (
                await session.execute(
                    text(
                        "SELECT pg_has_role('cloudguard_worker', 'authenticated', "
                        "'MEMBER')"
                    )
                )
            ).scalar_one()
        assert inherited is False
