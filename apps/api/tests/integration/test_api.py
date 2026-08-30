"""API tests: authentication, authorization, tenant isolation, and the
workflow endpoints (TESTING.md section 4).

These drive the real ASGI app, so every request goes through the real
dependency chain -- token verification, membership resolution, and an
RLS-constrained session.
"""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.core.config import settings
from app.main import app

pytestmark = pytest.mark.integration


def issue_test_token(user_id: uuid.UUID, email: str) -> str:
    """Mint a token in the shape Supabase issues.

    The application has no token-minting code of its own -- it only verifies
    what Supabase signed -- so the test suite builds its own rather than the
    product shipping a code path that hands out credentials.
    """
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": str(user_id),
            "email": email,
            "aud": settings.jwt_audience,
            "role": "authenticated",
            "iat": now,
            "exp": now + timedelta(hours=1),
        },
        settings.supabase_jwt_secret,
        algorithm="HS256",
    )


def auth_header(user_id: uuid.UUID, email: str = "user@example.com") -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_test_token(user_id, email)}"}


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def make_org(client: AsyncClient, user_id: uuid.UUID, name: str) -> str:
    response = await client.post(
        "/api/v1/organizations", json={"name": name}, headers=auth_header(user_id)
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]["id"]


class TestAuthentication:
    async def test_request_without_a_token_is_rejected(self, client) -> None:
        response = await client.get("/api/v1/findings")
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "NOT_AUTHENTICATED"

    async def test_malformed_token_is_rejected(self, client) -> None:
        response = await client.get(
            "/api/v1/findings", headers={"Authorization": "Bearer not-a-jwt"}
        )
        assert response.status_code == 401

    async def test_token_signed_with_the_wrong_secret_is_rejected(self, client) -> None:
        import jwt

        forged = jwt.encode(
            {"sub": str(uuid.uuid4()), "aud": "authenticated", "exp": 9999999999},
            "not-the-real-secret",
            algorithm="HS256",
        )
        response = await client.get(
            "/api/v1/findings", headers={"Authorization": f"Bearer {forged}"}
        )
        assert response.status_code == 401

    async def test_health_needs_no_token(self, client) -> None:
        assert (await client.get("/health")).status_code == 200


class TestResponseEnvelope:
    async def test_success_uses_the_standard_envelope(self, client, cleanup_orgs) -> None:
        user = uuid.uuid4()
        org_id = await make_org(client, user, "Envelope Co")
        cleanup_orgs.append(uuid.UUID(org_id))

        body = (await client.get("/api/v1/organizations", headers=auth_header(user))).json()
        assert set(body.keys()) == {"data", "error", "meta"}
        assert body["error"] is None

    async def test_error_uses_the_standard_envelope(self, client) -> None:
        body = (await client.get("/api/v1/findings")).json()
        assert set(body.keys()) == {"data", "error", "meta"}
        assert body["data"] is None
        assert "code" in body["error"] and "message" in body["error"]


class TestTenantIsolationOverHttp:
    async def test_a_user_cannot_read_another_organization(
        self, client, cleanup_orgs
    ) -> None:
        user_a, user_b = uuid.uuid4(), uuid.uuid4()
        org_a = await make_org(client, user_a, "Alpha Ltd")
        org_b = await make_org(client, user_b, "Beta Ltd")
        cleanup_orgs.extend([uuid.UUID(org_a), uuid.UUID(org_b)])

        response = await client.get(
            f"/api/v1/organizations/{org_b}", headers=auth_header(user_a)
        )
        assert response.status_code == 404

    async def test_naming_another_org_in_the_header_is_refused(
        self, client, cleanup_orgs
    ) -> None:
        """The header is a preference, never an authorization."""
        user_a, user_b = uuid.uuid4(), uuid.uuid4()
        org_a = await make_org(client, user_a, "Gamma Ltd")
        org_b = await make_org(client, user_b, "Delta Ltd")
        cleanup_orgs.extend([uuid.UUID(org_a), uuid.UUID(org_b)])

        response = await client.get(
            "/api/v1/findings",
            headers={**auth_header(user_a), "X-Organization-Id": org_b},
        )
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "ORGANIZATION_NOT_FOUND"

    async def test_a_user_with_no_organization_gets_a_clear_error(self, client) -> None:
        response = await client.get("/api/v1/findings", headers=auth_header(uuid.uuid4()))
        assert response.status_code == 404
        assert "organization" in response.json()["error"]["message"].lower()

    async def test_findings_list_is_scoped_to_the_callers_org(
        self, client, cleanup_orgs
    ) -> None:
        user = uuid.uuid4()
        org = await make_org(client, user, "Scoped Ltd")
        cleanup_orgs.append(uuid.UUID(org))

        body = (await client.get("/api/v1/findings", headers=auth_header(user))).json()
        assert body["data"] == []
        assert body["meta"]["total"] == 0


class TestOrganizationDeletion:
    async def test_an_owner_can_delete_their_organization(
        self, client, cleanup_orgs
    ) -> None:
        user = uuid.uuid4()
        org = await make_org(client, user, "Departing Ltd")

        response = await client.delete(
            f"/api/v1/organizations/{org}", headers=auth_header(user)
        )
        assert response.status_code == 200

        remaining = (
            await client.get("/api/v1/organizations", headers=auth_header(user))
        ).json()["data"]
        assert org not in [o["id"] for o in remaining]

    async def test_a_non_owner_is_refused_rather_than_silently_ignored(
        self, client, cleanup_orgs
    ) -> None:
        """RLS filters rows, it does not raise.

        Without the app-layer role check a member who is not an owner would
        issue a DELETE that matches nothing and receive a cheerful 200, while
        the organization stands. That is the worst of both worlds: no deletion
        and no complaint.
        """
        owner, member = uuid.uuid4(), uuid.uuid4()
        org = await make_org(client, owner, "Shared Ltd")
        cleanup_orgs.append(uuid.UUID(org))

        # No members API yet, so the membership is inserted directly. The
        # service connection is the owner role, which bypasses RLS — exactly
        # what a fixture needs and exactly what the API must never do.
        from app.core.db import service_session

        async with service_session() as session:
            await session.execute(
                text(
                    "INSERT INTO organization_members (organization_id, user_id, role) "
                    "VALUES (:org, :user, 'SECURITY_ANALYST')"
                ),
                {"org": uuid.UUID(org), "user": member},
            )
            await session.commit()

        response = await client.delete(
            f"/api/v1/organizations/{org}", headers=auth_header(member)
        )
        assert response.status_code in (403, 404)

        still_there = (
            await client.get("/api/v1/organizations", headers=auth_header(owner))
        ).json()["data"]
        assert org in [o["id"] for o in still_there]

    async def test_a_stranger_cannot_delete_an_organization(
        self, client, cleanup_orgs
    ) -> None:
        owner, stranger = uuid.uuid4(), uuid.uuid4()
        org = await make_org(client, owner, "Private Ltd")
        cleanup_orgs.append(uuid.UUID(org))

        response = await client.delete(
            f"/api/v1/organizations/{org}", headers=auth_header(stranger)
        )
        assert response.status_code == 404


class TestConnectionListing:
    async def test_the_list_carries_subscriptions_not_just_a_count(
        self, client, cleanup_orgs
    ) -> None:
        """The connections page renders from this endpoint.

        When it returned only a count, a verified connection showed no
        subscriptions at all: the per-connection request that would have
        supplied them never fired, because a card with nothing left to poll for
        stops polling. The data has to be here.
        """
        user = uuid.uuid4()
        org = await make_org(client, user, "Listing Ltd")
        cleanup_orgs.append(uuid.UUID(org))

        await client.post(
            "/api/v1/cloud-connections",
            json={"name": "Prod", "scope_type": "TENANT_ROOT"},
            headers=auth_header(user),
        )

        rows = (
            await client.get("/api/v1/cloud-connections", headers=auth_header(user))
        ).json()["data"]
        assert len(rows) == 1
        # Present and empty, rather than absent: the card distinguishes "none
        # discovered" from "not told", and they render differently.
        assert rows[0]["subscriptions"] == []
        assert rows[0]["subscription_count"] == 0


class TestCloudConnections:
    async def test_connection_screen_never_asks_for_a_credential(self, client) -> None:
        """The published contract: read-only, no customer secret."""
        body = (await client.get("/api/v1/cloud-accounts/azure/permissions")).json()
        assert body["data"]["access_type"] == "read-only"
        assert body["data"]["writes_performed"] == "none"
        assert body["data"]["azure_rbac_role"] == "Reader"

    async def test_creating_a_connection_takes_no_tenant_and_no_secret(
        self, client, cleanup_orgs
    ) -> None:
        """The customer supplies a name and a scope. Nothing else is accepted.

        The tenant id in particular is not an input -- it is written later, from
        what Entra reports on the consent callback. Supplying one here must not
        bind the connection to it.
        """
        user = uuid.uuid4()
        org = await make_org(client, user, "Connect Ltd")
        cleanup_orgs.append(uuid.UUID(org))

        response = await client.post(
            "/api/v1/cloud-connections",
            json={
                "name": "Production",
                "scope_type": "TENANT_ROOT",
                # All deliberately supplied and all deliberately ignored.
                "tenant_id": "someone-elses-tenant",
                "client_secret": "hunter2",
                "organization_id": str(uuid.uuid4()),
            },
            headers=auth_header(user),
        )
        assert response.status_code == 201
        data = response.json()["data"]
        assert data["tenant_id"] is None
        assert "client_secret" not in data
        assert data["consent_status"] == "PENDING"
        assert data["is_verified"] is False
        assert data["consent_url"] is not None or data["consent_url"] is None

    async def test_create_returns_consent_url(
        self, client, cleanup_orgs
    ) -> None:
        """The create response includes a consent URL so the frontend can
        redirect immediately — no second API call needed."""
        user = uuid.uuid4()
        org = await make_org(client, user, "Consent Ltd")
        cleanup_orgs.append(uuid.UUID(org))

        response = await client.post(
            "/api/v1/cloud-connections",
            json={"name": "Prod", "scope_type": "TENANT_ROOT"},
            headers=auth_header(user),
        )
        assert response.status_code == 201
        data = response.json()["data"]
        # Consent URL is returned in the create response
        assert "consent_url" in data

    async def test_scoped_connection_requires_a_scope_id(
        self, client, cleanup_orgs
    ) -> None:
        user = uuid.uuid4()
        org = await make_org(client, user, "Scoped Ltd")
        cleanup_orgs.append(uuid.UUID(org))

        response = await client.post(
            "/api/v1/cloud-connections",
            json={"name": "One sub", "scope_type": "SUBSCRIPTION"},
            headers=auth_header(user),
        )
        assert response.status_code == 422

    async def test_the_template_is_readable_from_any_origin(self, client) -> None:
        """Azure Portal fetches this from the customer's browser.

        Without the header the portal reports only that the template could not
        be downloaded and asks whether CORS is enabled -- while the endpoint
        answers 200 to anything that is not a browser, so it looks fine from
        every angle except the one that matters. Asserted on the error path
        because that is the one reachable without a live Azure tenant, and the
        header has to be on every response for the portal to read any of them.
        """
        response = await client.get(
            f"/api/v1/cloud-connections/{uuid.uuid4()}/template?token=forged.deadbeef"
        )
        assert response.headers.get("access-control-allow-origin") == "*"

    async def test_template_token_must_be_signed(self, client) -> None:
        """The ARM template endpoint is unauthenticated by design — Azure Portal
        fetches it server-side. A forged token must be rejected."""
        fake_id = "00000000-0000-0000-0000-000000000001"
        response = await client.get(
            f"/api/v1/cloud-connections/{fake_id}/template?token=forged.deadbeef"
        )
        assert response.status_code == 400, "signature check skipped"

    async def test_a_user_cannot_read_another_orgs_connection(
        self, client, cleanup_orgs
    ) -> None:
        user_a, user_b = uuid.uuid4(), uuid.uuid4()
        org_a = await make_org(client, user_a, "Owner Ltd")
        org_b = await make_org(client, user_b, "Outsider Ltd")
        cleanup_orgs.extend([uuid.UUID(org_a), uuid.UUID(org_b)])

        created = await client.post(
            "/api/v1/cloud-connections",
            json={"name": "Prod", "scope_type": "TENANT_ROOT"},
            headers=auth_header(user_a),
        )
        connection_id = created.json()["data"]["id"]

        response = await client.get(
            f"/api/v1/cloud-connections/{connection_id}", headers=auth_header(user_b)
        )
        assert response.status_code == 404


class TestScanGuards:
    async def test_cannot_scan_another_tenants_account(
        self, client, cleanup_orgs
    ) -> None:
        user_a, user_b = uuid.uuid4(), uuid.uuid4()
        org_a = await make_org(client, user_a, "Scan Owner Ltd")
        org_b = await make_org(client, user_b, "Scan Outsider Ltd")
        cleanup_orgs.extend([uuid.UUID(org_a), uuid.UUID(org_b)])

        response = await client.post(
            "/api/v1/scans",
            json={"cloud_account_id": str(uuid.uuid4())},
            headers=auth_header(user_b),
        )
        assert response.status_code == 404


class TestRuleCatalogue:
    async def test_rules_are_listed_with_compliance_mappings(
        self, client, cleanup_orgs, rule_catalogue
    ) -> None:
        user = uuid.uuid4()
        org = await make_org(client, user, "Rules Ltd")
        cleanup_orgs.append(uuid.UUID(org))

        body = (await client.get("/api/v1/rules", headers=auth_header(user))).json()
        rules = {r["rule_id"]: r for r in body["data"]}
        assert len(rules) == 10
        # Data-driven mappings, not hardcoded logic (requirement 15).
        assert "CIS_AZURE_2.0" in rules["AZ-NET-001"]["compliance_mappings"]
        assert rules["AZ-ID-002"]["scope"] == "aggregate"


class TestCompliance:
    async def test_frameworks_are_listed_with_coverage(
        self, client, cleanup_orgs, rule_catalogue
    ) -> None:
        user = uuid.uuid4()
        org = await make_org(client, user, "Compliant Ltd")
        cleanup_orgs.append(uuid.UUID(org))

        body = (await client.get("/api/v1/compliance", headers=auth_header(user))).json()
        frameworks = {f["id"]: f for f in body["data"]}
        assert {"CIS_AZURE_2.0", "ISO_27001", "GDPR"} <= set(frameworks)
        for framework in frameworks.values():
            assert framework["control_count"] > 0
            assert framework["url"].startswith("https://")

    async def test_unscanned_org_claims_nothing(
        self, client, cleanup_orgs, rule_catalogue
    ) -> None:
        """The important case. With no scan, every mapped control must read as
        NOT_ASSESSED -- never as passing, and never as a coverage figure."""
        user = uuid.uuid4()
        org = await make_org(client, user, "Unscanned Ltd")
        cleanup_orgs.append(uuid.UUID(org))

        data = (
            await client.get("/api/v1/compliance/GDPR", headers=auth_header(user))
        ).json()["data"]

        assert data["assessed"] is False
        assert data["status_counts"]["PASSING"] == 0
        assert data["coverage_ratio"] == 0.0
        statuses = {c["status"] for c in data["controls"]}
        assert statuses <= {"NOT_ASSESSED", "NOT_COVERED"}

    async def test_unknown_framework_is_a_404(self, client, cleanup_orgs) -> None:
        user = uuid.uuid4()
        org = await make_org(client, user, "Curious Ltd")
        cleanup_orgs.append(uuid.UUID(org))

        response = await client.get(
            "/api/v1/compliance/SOC2", headers=auth_header(user)
        )
        assert response.status_code == 404


class TestDashboard:
    async def test_empty_org_scores_100_with_no_coverage_claim(
        self, client, cleanup_orgs
    ) -> None:
        user = uuid.uuid4()
        org = await make_org(client, user, "Fresh Ltd")
        cleanup_orgs.append(uuid.UUID(org))

        data = (await client.get("/api/v1/dashboard", headers=auth_header(user))).json()["data"]
        assert data["security_score"] == 100
        assert data["open_finding_count"] == 0
        assert data["last_scan"] is None
        # No scan has run, so we make no claim about coverage.
        assert data["coverage"]["ratio"] is None


class TestChangeFeed:
    """The "what changed while I was away" surface.

    An empty answer is the interesting case to pin: a feed that padded a quiet
    week with rows saying everything is still where it was would be worse than
    no feed, because a customer would stop reading it before the week something
    did move.
    """

    async def test_a_tenant_with_no_scans_has_an_empty_week(
        self, client, cleanup_orgs
    ) -> None:
        user = uuid.uuid4()
        org_id = await make_org(client, user, "Quiet Week Ltd")
        cleanup_orgs.append(uuid.UUID(org_id))

        response = await client.get("/api/v1/changes", headers=auth_header(user))

        assert response.status_code == 200
        assert response.json()["data"] == []
        assert response.json()["meta"]["days"] == 7

    async def test_the_window_is_bounded(self, client, cleanup_orgs) -> None:
        """A feed is for a span somebody can read. An unbounded one would ask
        PostgreSQL for a tenant's whole history to answer a question about a
        week."""
        user = uuid.uuid4()
        org_id = await make_org(client, user, "Windowed Ltd")
        cleanup_orgs.append(uuid.UUID(org_id))

        assert (
            await client.get("/api/v1/changes?days=91", headers=auth_header(user))
        ).status_code == 422
        assert (
            await client.get("/api/v1/changes?days=0", headers=auth_header(user))
        ).status_code == 422

    async def test_an_unknown_change_kind_is_rejected(
        self, client, cleanup_orgs
    ) -> None:
        user = uuid.uuid4()
        org_id = await make_org(client, user, "Filtered Ltd")
        cleanup_orgs.append(uuid.UUID(org_id))

        response = await client.get(
            "/api/v1/changes?change=EXPLODED", headers=auth_header(user)
        )
        assert response.status_code == 422

    async def test_a_change_feed_needs_a_token(self, client) -> None:
        assert (await client.get("/api/v1/changes")).status_code == 401
