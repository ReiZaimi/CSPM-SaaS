"""Finding out what consent granted, at consent time and at scan time.

The failure this closes was reported from a live tenant: a connection that
validated green, then a scan whose ``users`` and ``directory_roles`` tasks both
came back "Insufficient privileges to complete the operation" -- a sentence
naming neither the permission, nor who can grant it, nor that the subscription
half of the connection was fine.

Two places knew and neither said so. The consent callback recorded GRANTED on
Entra's redirect alone, and the collector had only a generic hint to offer. The
token carried the answer the whole time.
"""

import httpx
import jwt
import pytest

from app.connectors.azure.auth import REQUIRED_GRAPH_PERMISSIONS
from app.core.enums import CloudAccountStatus, ConnectionScope, ConsentStatus, Provider
from app.models.cloud_connection import CloudConnection
from app.services.cloud_connections import GRANT_INCOMPLETE_PREFIX, graph_grant_problem


def token_granting(*permissions: str) -> str:
    return jwt.encode({"roles": list(permissions)}, "irrelevant", algorithm="HS256")


class FakeTokens:
    """A TokenProvider whose Graph token carries a chosen set of app roles."""

    token: str = token_granting()
    fails: bool = False

    def __init__(self, tenant_id: str) -> None:
        if type(self).fails:
            raise RuntimeError("no token for this tenant")
        self.tenant_id = tenant_id

    def graph_token(self) -> str:
        return type(self).token

    def arm_token(self) -> str:
        return "arm"


def connection(tenant_id: str | None = "tenant-1") -> CloudConnection:
    return CloudConnection(
        provider=Provider.AZURE,
        name="test",
        scope_type=ConnectionScope.TENANT_ROOT,
        tenant_id=tenant_id,
        role_version="v2",
        consent_status=ConsentStatus.GRANTED,
        status=CloudAccountStatus.PENDING,
    )


@pytest.fixture
def tokens(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("app.connectors.azure.auth.TokenProvider", FakeTokens)
    monkeypatch.setattr(FakeTokens, "fails", False)
    return FakeTokens


# ------------------------------------------------------- at the consent callback
async def test_a_complete_grant_is_no_problem(tokens, monkeypatch) -> None:
    monkeypatch.setattr(tokens, "token", token_granting(*REQUIRED_GRAPH_PERMISSIONS))
    assert await graph_grant_problem(connection()) is None


async def test_a_grant_of_nothing_names_every_permission(tokens, monkeypatch) -> None:
    """The case actually seen. A registration whose permissions are declared as
    delegated rather than application produces a service token with no roles at
    all, and consent that looks entirely successful."""
    monkeypatch.setattr(tokens, "token", token_granting())

    problem = await graph_grant_problem(connection())

    assert problem is not None
    assert problem.startswith(GRANT_INCOMPLETE_PREFIX)
    for permission in REQUIRED_GRAPH_PERMISSIONS:
        assert permission in problem


async def test_the_message_says_what_still_works(tokens, monkeypatch) -> None:
    """Half a connection is not a broken one: the subscription grant is
    separate and unaffected, and a customer told only "consent failed" would go
    looking for the wrong thing."""
    monkeypatch.setattr(tokens, "token", token_granting())

    problem = await graph_grant_problem(connection()) or ""

    assert "Subscription scanning is unaffected" in problem
    assert "application" in problem, "and how the registration must declare them"
    assert "re-run admin consent" in problem


async def test_a_partial_grant_names_only_what_is_absent(tokens, monkeypatch) -> None:
    monkeypatch.setattr(
        tokens, "token", token_granting("Directory.Read.All", "User.Read.All")
    )

    problem = await graph_grant_problem(connection()) or ""

    assert "Directory.Read.All," not in problem
    assert "RoleManagement.Read.Directory" in problem


async def test_a_tenant_that_cannot_issue_a_token_is_not_a_missing_grant(
    tokens, monkeypatch
) -> None:
    """A different failure with a different fix, and the probes report it.
    Claiming nine missing permissions here would send an administrator to
    change a directory that is configured correctly."""
    monkeypatch.setattr(tokens, "fails", True)

    assert await graph_grant_problem(connection()) is None


async def test_no_tenant_yet_is_not_a_missing_grant(tokens) -> None:
    assert await graph_grant_problem(connection(tenant_id=None)) is None


# ------------------------------------------------------------- at scan time
def graph_denying() -> httpx.AsyncClient:
    """Graph as it answers a token with no directory permissions."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={
                "error": {
                    "message": "Insufficient privileges to complete the operation."
                }
            },
        )

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def run_identity(token: str, http: httpx.AsyncClient):
    from app.connectors.azure.plan import AzurePlanBuilder
    from app.connectors.collection import CollectionRun

    class Tokens:
        def graph_token(self) -> str:
            return token

        def arm_token(self) -> str:
            return "arm"

    tasks = AzurePlanBuilder(
        tokens=Tokens(), subscription_id=None, http_client=http
    ).build_directory_plan()
    return await CollectionRun(tasks).execute({})


async def test_a_denied_listing_names_the_permissions_it_needed() -> None:
    """What the scan page showed before this: "Insufficient privileges to
    complete the operation", for two tasks, with nine candidate permissions and
    no way to tell which."""
    report = await run_identity(token_granting(), graph_denying())

    detail = report.results["users"].detail
    assert "Insufficient privileges" in detail, "Azure's own words are kept"
    assert "Directory.Read.All" in detail
    assert "User.Read.All" in detail


async def test_a_denial_under_a_complete_grant_names_nothing_extra() -> None:
    """Every permission is granted and Graph still refused, so the grant is not
    the explanation and guessing at one would be noise."""
    report = await run_identity(
        token_granting(*REQUIRED_GRAPH_PERMISSIONS), graph_denying()
    )

    detail = report.results["users"].detail
    assert "Insufficient privileges" in detail
    assert "did not grant" not in detail


async def test_an_unreadable_token_adds_nothing() -> None:
    report = await run_identity("not-a-jwt", graph_denying())

    assert "did not grant" not in report.results["users"].detail
