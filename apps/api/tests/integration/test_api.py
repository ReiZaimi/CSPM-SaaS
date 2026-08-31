"""API tests: authentication, authorization, tenant isolation, and the
workflow endpoints (TESTING.md section 4).

These drive the real ASGI app, so every request goes through the real
dependency chain -- token verification, membership resolution, and an
RLS-constrained session.
"""

import time
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
        # Nor about freshness. Nothing has been read, and reporting an age of
        # zero hours would read as "up to date" for an environment nobody has
        # looked at.
        assert data["evidence_freshness"]["readings"] == 0
        assert data["evidence_freshness"]["stale_hours"] is None


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


class TestChangeEventWebhook:
    """The endpoint Azure calls, which means the endpoint anyone can call.

    No session authenticates it -- Event Grid delivers from Microsoft's
    infrastructure and carries no CloudGuard user -- so the signed token is the
    whole of the guard, and these are the cases where getting it wrong hands a
    stranger the ability to make a tenant scan itself on demand.
    """

    def _token(self, connection_id: str, purpose: str = "event_grid") -> str:
        from app.core.signing import sign_state

        return sign_state(
            {
                "cloud_connection_id": connection_id,
                "purpose": purpose,
                "issued_at": time.time(),
            }
        )

    async def test_no_token_is_refused(self, client) -> None:
        response = await client.post(f"/api/v1/events/azure/{uuid.uuid4()}", json=[])
        assert response.status_code == 400

    async def test_a_forged_token_is_refused(self, client) -> None:
        response = await client.post(
            f"/api/v1/events/azure/{uuid.uuid4()}?token=forged.deadbeef", json=[]
        )
        assert response.status_code == 400

    async def test_a_template_token_does_not_open_the_webhook(self, client) -> None:
        """Both are signed with the same secret. The purpose is what separates
        them, which is why the webhook checks it rather than trusting the
        signature to mean what it hopes."""
        connection_id = str(uuid.uuid4())
        response = await client.post(
            f"/api/v1/events/azure/{connection_id}"
            f"?token={self._token(connection_id, purpose='template')}",
            json=[],
        )
        assert response.status_code == 400

    async def test_a_token_for_another_connection_is_refused(self, client) -> None:
        response = await client.post(
            f"/api/v1/events/azure/{uuid.uuid4()}"
            f"?token={self._token(str(uuid.uuid4()))}",
            json=[],
        )
        assert response.status_code == 400

    async def test_the_validation_handshake_is_answered(self, client) -> None:
        """Answered before any database work, and for a connection that need not
        exist yet: Event Grid validates the endpoint when the subscription is
        created, which is the moment the customer is watching."""
        connection_id = str(uuid.uuid4())
        response = await client.post(
            f"/api/v1/events/azure/{connection_id}?token={self._token(connection_id)}",
            json=[
                {
                    "eventType": "Microsoft.EventGrid.SubscriptionValidationEvent",
                    "data": {"validationCode": "code-123"},
                }
            ],
        )

        assert response.status_code == 200
        assert response.json() == {"validationResponse": "code-123"}

    async def test_an_irrelevant_event_is_accepted_and_dropped(self, client) -> None:
        """200, not an error. Event Grid retries a non-2xx for hours, and
        redelivering something CloudGuard has decided it cannot act on is load
        with no possible outcome."""
        connection_id = str(uuid.uuid4())
        response = await client.post(
            f"/api/v1/events/azure/{connection_id}?token={self._token(connection_id)}",
            json=[
                {
                    "eventType": "Microsoft.Resources.ResourceWriteSuccess",
                    "data": {"operationName": "Microsoft.Web/sites/write"},
                }
            ],
        )

        assert response.status_code == 200
        assert response.json()["relevant"] == 0

    async def test_an_event_for_a_connection_that_never_opted_in_is_dropped(
        self, client, cleanup_orgs
    ) -> None:
        """A connection with the feature off is treated exactly as one that does
        not exist -- otherwise turning it off would leave a webhook that keeps
        accepting, and quietly resumes when somebody turns it back on."""
        user = uuid.uuid4()
        org_id = await make_org(client, user, "No Events Ltd")
        cleanup_orgs.append(uuid.UUID(org_id))

        created = await client.post(
            "/api/v1/cloud-connections",
            json={"name": "Prod", "scope_type": "TENANT_ROOT"},
            headers=auth_header(user),
        )
        connection_id = created.json()["data"]["id"]

        response = await client.post(
            f"/api/v1/events/azure/{connection_id}?token={self._token(connection_id)}",
            json=[
                {
                    "eventType": "Microsoft.Resources.ResourceWriteSuccess",
                    "data": {
                        "operationName": "Microsoft.Network/networkSecurityGroups/write"
                    },
                }
            ],
        )

        assert response.status_code == 200
        rows = await _connection_change_state(uuid.UUID(connection_id))
        assert rows[0] is None, "an event was recorded against a connection that is off"


async def _connection_change_state(connection_id: uuid.UUID) -> tuple:
    from app.core.db import service_session

    async with service_session() as session:
        return (
            await session.execute(
                text(
                    "SELECT change_pending_since, last_change_event_at "
                    "FROM cloud_connections WHERE id = :id"
                ),
                {"id": connection_id},
            )
        ).one()


class TestSubscriptionDiscovery:
    """The escape hatch for a connection that found nothing.

    It returned 500 in staging, and the cause is the kind that only appears
    against a real session: newly discovered subscriptions were handed back to
    the serializer before their primary keys existed. ``commit_unless_externally
    _managed`` does nothing inside a request -- ``rls_session`` owns that
    transaction -- so nothing had assigned them, and the endpoint whose whole
    job is recovering a connection with no subscriptions was the one that broke.
    """

    async def _verified_connection(self, org_id: uuid.UUID) -> uuid.UUID:
        from datetime import UTC, datetime

        from app.core.db import service_session
        from app.core.enums import (
            CloudAccountStatus,
            ConnectionScope,
            ConsentStatus,
            Provider,
        )
        from app.models.cloud_connection import CloudConnection

        async with service_session() as session:
            connection = CloudConnection(
                organization_id=org_id,
                provider=Provider.AZURE,
                name="prod",
                scope_type=ConnectionScope.TENANT_ROOT,
                role_version="v2",
                tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                consent_status=ConsentStatus.GRANTED,
                rbac_verified_at=datetime.now(UTC),
                status=CloudAccountStatus.ACTIVE,
            )
            session.add(connection)
            await session.commit()
            return connection.id

    async def test_a_discovered_subscription_comes_back_with_an_id(
        self, client, cleanup_orgs, monkeypatch
    ) -> None:
        user = uuid.uuid4()
        org_id = uuid.UUID(await make_org(client, user, "Discovery Ltd"))
        cleanup_orgs.append(org_id)
        connection_id = await self._verified_connection(org_id)

        # Azure, reduced to the one call discovery makes. The bug is on this
        # side of it: what ARM said was never the problem.
        class FakeArm:
            def __init__(self, *args, **kwargs) -> None:
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc) -> None:
                return None

            async def list_subscriptions(self) -> list[dict]:
                return [
                    {
                        "subscriptionId": "00000000-0000-0000-0000-000000000001",
                        "displayName": "Production",
                    }
                ]

        from app.services import cloud_connections as service

        monkeypatch.setattr(service, "ArmClient", FakeArm)
        monkeypatch.setattr(
            "app.connectors.azure.auth.TokenProvider", lambda tenant_id: object()
        )

        response = await client.post(
            f"/api/v1/cloud-connections/{connection_id}/discover",
            headers=auth_header(user),
        )

        assert response.status_code == 200, response.text
        subscriptions = response.json()["data"]["subscriptions"]
        assert len(subscriptions) == 1
        # The assertion the 500 was: a row that exists in the session but has
        # no primary key yet cannot be serialized, and cannot be linked to by
        # anything the customer clicks next.
        assert uuid.UUID(subscriptions[0]["id"])
        assert subscriptions[0]["subscription_id"] == (
            "00000000-0000-0000-0000-000000000001"
        )


class TestAssetList:
    """What the inventory endpoint has to carry.

    The list is the only view of an estate a client gets in one request, and the
    field it was missing decided what could be built on it: an ARM id spells out
    its own subscription and resource group, so without it a client can render
    an inventory but cannot say where anything *sits* -- not without one request
    per row.
    """

    async def _asset_in_a_subscription(self, org_id: uuid.UUID, arm_id: str) -> None:
        """One asset, sitting where a real one sits.

        ``ck_cloud_resources_one_scope`` requires every resource to hang off an
        account or, for a directory-scoped one, a connection. Nothing may float
        free of both, so a fixture that skips them is not a lighter version of
        the real row -- it is a shape the estate cannot produce.
        """
        from datetime import UTC, datetime

        from app.core.db import service_session
        from app.core.enums import (
            CloudAccountStatus,
            ConnectionScope,
            ConsentStatus,
            Level,
            Provider,
            ResourceType,
        )
        from app.models.cloud_account import CloudAccount
        from app.models.cloud_connection import CloudConnection
        from app.models.resource import ResourceRecord

        tenant_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        async with service_session() as session:
            connection = CloudConnection(
                organization_id=org_id,
                provider=Provider.AZURE,
                name="prod",
                scope_type=ConnectionScope.TENANT_ROOT,
                role_version="v2",
                tenant_id=tenant_id,
                consent_status=ConsentStatus.GRANTED,
                rbac_verified_at=datetime.now(UTC),
                status=CloudAccountStatus.ACTIVE,
            )
            session.add(connection)
            await session.flush()

            account = CloudAccount(
                organization_id=org_id,
                connection_id=connection.id,
                provider=Provider.AZURE,
                account_name="Production",
                tenant_id=tenant_id,
                subscription_id="00000000-0000-0000-0000-000000000001",
                consent_status=ConsentStatus.GRANTED,
                rbac_verified_at=datetime.now(UTC),
                status=CloudAccountStatus.ACTIVE,
            )
            session.add(account)
            await session.flush()

            session.add(
                ResourceRecord(
                    organization_id=org_id,
                    cloud_account_id=account.id,
                    connection_id=connection.id,
                    provider=Provider.AZURE,
                    provider_resource_id=arm_id,
                    resource_type=ResourceType.STORAGE_ACCOUNT,
                    name="payroll",
                    criticality=Level.HIGH,
                    data_sensitivity=Level.HIGH,
                    public_exposure=Level.LOW,
                    first_seen_at=datetime.now(UTC),
                    last_seen_at=datetime.now(UTC),
                )
            )
            await session.commit()

    async def test_a_listed_asset_names_itself_in_the_provider(
        self, client, cleanup_orgs
    ) -> None:
        import uuid as uuid_module

        user = uuid.uuid4()
        org_id = uuid.UUID(await make_org(client, user, "Inventory Ltd"))
        cleanup_orgs.append(org_id)

        arm_id = (
            "/subscriptions/00000000-0000-0000-0000-000000000001"
            "/resourceGroups/prod/providers/Microsoft.Storage/storageAccounts/payroll"
        )
        await self._asset_in_a_subscription(org_id, arm_id)

        response = await client.get("/api/v1/assets", headers=auth_header(user))

        assert response.status_code == 200
        [asset] = response.json()["data"]
        assert asset["provider_resource_id"] == arm_id
        # The row id names nothing in the customer's cloud; the ARM id is what
        # they can search for in their own portal.
        assert asset["id"] != arm_id
        assert uuid_module.UUID(asset["id"])

    async def test_the_list_reports_the_true_total_not_the_page_size(
        self, client, cleanup_orgs
    ) -> None:
        """Pagination is only usable if the count is the whole set.

        A client that read `len(data)` would show a full page as the entire
        inventory, which is exactly what the assets page used to do.
        """
        user = uuid.uuid4()
        org_id = uuid.UUID(await make_org(client, user, "Paged Ltd"))
        cleanup_orgs.append(org_id)

        response = await client.get("/api/v1/assets?limit=1", headers=auth_header(user))

        assert response.status_code == 200
        assert "total" in response.json()["meta"]


class TestFindingSearchAndSort:
    """The two parameters a paginated list cannot do without.

    Both exist because the alternative is a page that filters and orders the
    hundred rows it happens to hold: a search that reports "nothing matches"
    over a hundredth of an estate, and a "worst first" that puts the CRITICAL on
    page four below the LOW on page one.
    """

    async def _findings(self, org_id: uuid.UUID) -> None:
        from datetime import UTC, datetime, timedelta

        from app.core.db import service_session
        from app.core.enums import FindingStatus, Severity
        from app.models.finding import Finding

        now = datetime.now(UTC)
        async with service_session() as session:
            session.add_all(
                [
                    Finding(
                        organization_id=org_id,
                        rule_id="AZ-STO-001",
                        severity=Severity.LOW,
                        status=FindingStatus.OPEN,
                        title="Storage account allows public blob access",
                        description="",
                        # The highest risk in the set despite the lowest
                        # severity -- which is the distinction the two sorts
                        # exist to keep apart.
                        risk_score=90,
                        first_detected_at=now,
                        last_detected_at=now,
                    ),
                    Finding(
                        organization_id=org_id,
                        rule_id="AZ-NET-002",
                        severity=Severity.CRITICAL,
                        status=FindingStatus.OPEN,
                        title="Network security group permits inbound SSH",
                        description="",
                        risk_score=10,
                        first_detected_at=now,
                        last_detected_at=now - timedelta(days=2),
                    ),
                ]
            )
            await session.commit()

    async def test_search_matches_a_finding_by_its_rule(self, client, cleanup_orgs) -> None:
        user = uuid.uuid4()
        org_id = uuid.UUID(await make_org(client, user, "Search Ltd"))
        cleanup_orgs.append(org_id)
        await self._findings(org_id)

        response = await client.get(
            "/api/v1/findings?search=AZ-NET", headers=auth_header(user)
        )

        assert response.status_code == 200, response.text
        [finding] = response.json()["data"]
        assert finding["rule_id"] == "AZ-NET-002"

    async def test_search_matches_a_finding_by_its_title(self, client, cleanup_orgs) -> None:
        user = uuid.uuid4()
        org_id = uuid.UUID(await make_org(client, user, "Title Ltd"))
        cleanup_orgs.append(org_id)
        await self._findings(org_id)

        # Mid-word and mid-case, because a person searching remembers a word
        # rather than the start of the sentence it is in.
        response = await client.get(
            "/api/v1/findings?search=public+blob", headers=auth_header(user)
        )

        assert response.status_code == 200
        [finding] = response.json()["data"]
        assert finding["rule_id"] == "AZ-STO-001"

    async def test_search_narrows_the_total_as_well_as_the_page(
        self, client, cleanup_orgs
    ) -> None:
        """The count has to describe the search, or pagination lies about it."""
        user = uuid.uuid4()
        org_id = uuid.UUID(await make_org(client, user, "Total Ltd"))
        cleanup_orgs.append(org_id)
        await self._findings(org_id)

        response = await client.get(
            "/api/v1/findings?search=AZ-NET", headers=auth_header(user)
        )

        assert response.json()["meta"]["total"] == 1

    async def test_risk_and_severity_are_different_orders(self, client, cleanup_orgs) -> None:
        user = uuid.uuid4()
        org_id = uuid.UUID(await make_org(client, user, "Order Ltd"))
        cleanup_orgs.append(org_id)
        await self._findings(org_id)

        by_risk = await client.get("/api/v1/findings?sort=risk", headers=auth_header(user))
        by_severity = await client.get(
            "/api/v1/findings?sort=severity", headers=auth_header(user)
        )

        # A LOW on an exposed asset outranks a CRITICAL on an isolated one, and
        # the product would have nothing to say if both sorts agreed.
        assert by_risk.json()["data"][0]["rule_id"] == "AZ-STO-001"
        assert by_severity.json()["data"][0]["rule_id"] == "AZ-NET-002"

    async def test_severity_ranks_worst_first_not_alphabetically(
        self, client, cleanup_orgs
    ) -> None:
        """CRITICAL before LOW; alphabetically it is the other way round."""
        user = uuid.uuid4()
        org_id = uuid.UUID(await make_org(client, user, "Rank Ltd"))
        cleanup_orgs.append(org_id)
        await self._findings(org_id)

        response = await client.get(
            "/api/v1/findings?sort=severity", headers=auth_header(user)
        )

        assert [f["severity"] for f in response.json()["data"]] == ["CRITICAL", "LOW"]

    async def test_recent_orders_by_when_it_was_last_seen(self, client, cleanup_orgs) -> None:
        user = uuid.uuid4()
        org_id = uuid.UUID(await make_org(client, user, "Recent Ltd"))
        cleanup_orgs.append(org_id)
        await self._findings(org_id)

        response = await client.get(
            "/api/v1/findings?sort=recent", headers=auth_header(user)
        )

        assert response.json()["data"][0]["rule_id"] == "AZ-STO-001"

    async def test_an_unknown_sort_is_refused_rather_than_ignored(
        self, client, cleanup_orgs
    ) -> None:
        """Silently falling back would order the list differently than asked."""
        user = uuid.uuid4()
        org_id = uuid.UUID(await make_org(client, user, "Bad Sort Ltd"))
        cleanup_orgs.append(org_id)

        response = await client.get(
            "/api/v1/findings?sort=alphabetical", headers=auth_header(user)
        )

        assert response.status_code == 422


class TestRiskSearch:
    async def test_search_matches_a_risk_by_title(self, client, cleanup_orgs) -> None:
        from app.core.db import service_session
        from app.core.enums import Level, RiskKind, RiskStatus
        from app.models.risk import Risk

        user = uuid.uuid4()
        org_id = uuid.UUID(await make_org(client, user, "Risk Search Ltd"))
        cleanup_orgs.append(org_id)

        async with service_session() as session:
            session.add_all(
                [
                    Risk(
                        organization_id=org_id,
                        kind=RiskKind.FINDING,
                        title="Payroll storage is reachable from the internet",
                        description="",
                        risk_score=80,
                        risk_level=Level.HIGH,
                        status=RiskStatus.OPEN,
                        severity="HIGH",
                        asset_criticality=Level.HIGH,
                        data_sensitivity=Level.HIGH,
                        internet_exposure=Level.HIGH,
                    ),
                    Risk(
                        organization_id=org_id,
                        kind=RiskKind.FINDING,
                        title="Sandbox virtual machine has an open management port",
                        description="",
                        risk_score=20,
                        risk_level=Level.LOW,
                        status=RiskStatus.OPEN,
                        severity="LOW",
                        asset_criticality=Level.LOW,
                        data_sensitivity=Level.LOW,
                        internet_exposure=Level.LOW,
                    ),
                ]
            )
            await session.commit()

        response = await client.get("/api/v1/risks?search=payroll", headers=auth_header(user))

        assert response.status_code == 200, response.text
        assert len(response.json()["data"]) == 1
        assert response.json()["meta"]["total"] == 1


class TestReports:
    """The report endpoints, over the real dependency chain.

    Unit tests pin what a report *says*; these pin the three things only a real
    request can prove: that a report is scoped to the caller's organization,
    that the PDF path actually produces a PDF on a machine with the native
    libraries, and that an unknown report name is refused rather than rendered
    as an empty document.
    """

    async def test_a_report_is_scoped_to_the_callers_organization(
        self, client, cleanup_orgs
    ) -> None:
        user_a, user_b = uuid.uuid4(), uuid.uuid4()
        org_a = await make_org(client, user_a, "Contoso")
        org_b = await make_org(client, user_b, "Fabrikam")
        cleanup_orgs.extend([uuid.UUID(org_a), uuid.UUID(org_b)])

        response = await client.get(
            "/api/v1/reports/executive?format=html", headers=auth_header(user_a)
        )

        assert response.status_code == 200, response.text
        assert "Contoso" in response.text
        # The name of another tenant appearing in a document that gets
        # forwarded outside the company is the worst version of a leak.
        assert "Fabrikam" not in response.text

    async def test_a_report_requires_a_token(self, client) -> None:
        response = await client.get("/api/v1/reports/executive?format=html")

        assert response.status_code == 401

    async def test_an_unknown_report_is_refused_rather_than_rendered_empty(
        self, client, cleanup_orgs
    ) -> None:
        user = uuid.uuid4()
        org = await make_org(client, user, "Contoso")
        cleanup_orgs.append(uuid.UUID(org))

        response = await client.get(
            "/api/v1/reports/quarterly?format=html", headers=auth_header(user)
        )

        assert response.status_code == 404

    async def test_the_pdf_path_produces_a_pdf(self, client, cleanup_orgs) -> None:
        # The one thing the unit tests cannot reach: WeasyPrint's native
        # libraries are installed in CI and in the API image, and this is what
        # would catch them going missing from either.
        user = uuid.uuid4()
        org = await make_org(client, user, "Contoso")
        cleanup_orgs.append(uuid.UUID(org))

        response = await client.get("/api/v1/reports/technical", headers=auth_header(user))

        assert response.status_code == 200, response.text
        assert response.headers["content-type"] == "application/pdf"
        assert response.content.startswith(b"%PDF-")
        assert "attachment" in response.headers["content-disposition"]
        assert "cloudguard-contoso-technical.pdf" in response.headers["content-disposition"]


class TestOrganizationProfile:
    """Correcting how an organization describes itself.

    A profile, not a statement: only the fields present are written, because a
    form that saves a name must not clear a country nobody touched. That is the
    opposite of a context declaration, and the difference is worth pinning.
    """

    async def test_a_name_can_be_corrected(self, client, cleanup_orgs) -> None:
        user = uuid.uuid4()
        org = await make_org(client, user, "Contso")
        cleanup_orgs.append(uuid.UUID(org))

        response = await client.patch(
            "/api/v1/organizations", json={"name": "Contoso"}, headers=auth_header(user)
        )

        assert response.status_code == 200, response.text
        assert response.json()["data"]["name"] == "Contoso"

    async def test_a_field_left_out_is_left_alone(self, client, cleanup_orgs) -> None:
        user = uuid.uuid4()
        org = await make_org(client, user, "Contoso")
        cleanup_orgs.append(uuid.UUID(org))

        await client.patch(
            "/api/v1/organizations",
            json={"industry": "Banking", "country": "al"},
            headers=auth_header(user),
        )
        response = await client.patch(
            "/api/v1/organizations", json={"name": "Contoso Group"}, headers=auth_header(user)
        )

        assert response.status_code == 200, response.text
        body = response.json()["data"]
        assert body["name"] == "Contoso Group"
        # Neither was in the second request, and neither may be cleared by it.
        assert body["industry"] == "Banking"
        assert body["country"] == "AL"

    async def test_the_slug_survives_a_rename(self, client, cleanup_orgs) -> None:
        # It is an identifier that already appears in stored references.
        # Changing it because somebody fixed a display name would be renaming
        # the thing rather than relabelling it.
        user = uuid.uuid4()
        org = await make_org(client, user, "Contoso")
        cleanup_orgs.append(uuid.UUID(org))

        before = await client.get(f"/api/v1/organizations/{org}", headers=auth_header(user))
        after = await client.patch(
            "/api/v1/organizations", json={"name": "Something Else"}, headers=auth_header(user)
        )

        assert after.json()["data"]["slug"] == before.json()["data"]["slug"]

    async def test_an_edit_cannot_reach_another_organization(
        self, client, cleanup_orgs
    ) -> None:
        user_a, user_b = uuid.uuid4(), uuid.uuid4()
        org_a = await make_org(client, user_a, "Contoso")
        org_b = await make_org(client, user_b, "Fabrikam")
        cleanup_orgs.extend([uuid.UUID(org_a), uuid.UUID(org_b)])

        # The target comes from the tenant context, so naming another
        # organization in the header is refused rather than honoured.
        response = await client.patch(
            "/api/v1/organizations",
            json={"name": "Taken over"},
            headers={**auth_header(user_a), "X-Organization-Id": org_b},
        )

        assert response.status_code == 404
        still = await client.get(f"/api/v1/organizations/{org_b}", headers=auth_header(user_b))
        assert still.json()["data"]["name"] == "Fabrikam"

    async def test_a_name_that_is_too_short_is_refused(self, client, cleanup_orgs) -> None:
        user = uuid.uuid4()
        org = await make_org(client, user, "Contoso")
        cleanup_orgs.append(uuid.UUID(org))

        response = await client.patch(
            "/api/v1/organizations", json={"name": "X"}, headers=auth_header(user)
        )

        assert response.status_code == 422
