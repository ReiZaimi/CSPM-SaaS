"""Losing directory access, and finding out when.

Two failures met here. A customer's connection validated green and then lost
its entire identity category to a 403 on the first scan, because validation
read ``/organization`` and concluded from it that ``Directory.Read.All`` was
granted -- an endpoint that answers with far less. And when the scan did fail,
one 403 on ``/directoryRoles`` discarded the user list that had already been
read successfully, because those two calls were the only ones in
``_collect_identity`` not defended individually.

Both are the same mistake in different places: treating one call's success, or
one call's failure, as a verdict on more than it covers.
"""

import httpx
import pytest

from app.connectors.azure.collector import AzureCollector
from app.connectors.azure.connector import GRAPH_PROBES, AzureConnector
from app.connectors.base import RawSnapshot
from app.core.enums import Provider


class FakeTokens:
    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id

    def arm_token(self) -> str:
        return "arm"

    def graph_token(self) -> str:
        return "graph"


# --------------------------------------------------------- collecting identity
class FakeGraph:
    """A Graph client where each call either answers or refuses."""

    def __init__(self, denied: set[str] | None = None) -> None:
        self.denied = denied or set()

    def _check(self, name: str) -> None:
        if name in self.denied:
            raise RuntimeError("Insufficient privileges to complete the operation.")

    async def list_users(self) -> list[dict]:
        self._check("list_users")
        return [{"id": "u1", "displayName": "Ada"}]

    async def list_directory_roles(self) -> list[dict]:
        self._check("list_directory_roles")
        return [{"id": "r1", "displayName": "Global Administrator"}]

    async def list_role_members(self, role_id: str) -> list[dict]:
        self._check("list_role_members")
        return [{"id": "u1"}]

    async def list_authentication_methods(self, user_id: str) -> list[dict]:
        self._check("list_authentication_methods")
        return []


@pytest.fixture(autouse=True)
def _no_real_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neither the collector nor the connector may reach for a real token."""
    monkeypatch.setattr("app.connectors.azure.collector.TokenProvider", FakeTokens)
    monkeypatch.setattr("app.connectors.azure.connector.TokenProvider", FakeTokens)


def collector() -> AzureCollector:
    return AzureCollector(tenant_id="t", subscription_id="s")


def snapshot() -> RawSnapshot:
    return RawSnapshot(provider=Provider.AZURE, tenant_id="t", subscription_id="s")


async def test_everything_readable_records_no_gap() -> None:
    snap = snapshot()
    data = await collector()._collect_identity(FakeGraph(), snap)

    assert snap.errors == {}
    assert data["users"] and data["directory_roles"]


async def test_losing_roles_keeps_the_users_already_read() -> None:
    """The reported failure. One permission the role rules needed took the
    asset inventory with it."""
    snap = snapshot()
    data = await collector()._collect_identity(
        FakeGraph(denied={"list_directory_roles"}), snap
    )

    assert data["users"], "a readable user list must survive a roles failure"
    assert data["directory_roles"] == []
    assert "directory roles could not be read" in snap.errors["identity"]


async def test_losing_users_keeps_the_roles_already_read() -> None:
    snap = snapshot()
    data = await collector()._collect_identity(FakeGraph(denied={"list_users"}), snap)

    assert data["directory_roles"]
    assert data["users"] == []
    assert "directory users could not be read" in snap.errors["identity"]


async def test_a_partial_directory_still_marks_the_category_failed() -> None:
    """Half a directory is not grounds for saying anyone's MFA is fine. The gap
    is recorded so every identity rule degrades to UNKNOWN, even though usable
    data came back."""
    snap = snapshot()
    await collector()._collect_identity(FakeGraph(denied={"list_users"}), snap)
    assert "identity" in snap.errors


async def test_both_failures_are_reported_together() -> None:
    snap = snapshot()
    await collector()._collect_identity(
        FakeGraph(denied={"list_users", "list_directory_roles"}), snap
    )
    assert "users" in snap.errors["identity"]
    assert "roles" in snap.errors["identity"]


# ------------------------------------------------------- validating a connection
GRAPH_PATHS = {
    "/organization": "get_organization",
    "/users": "list_users",
    "/directoryRoles": "list_directory_roles",
}


def azure_returning(denied_paths: set[str]):
    """An Azure where the named Graph paths refuse and everything else works."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.url.host.startswith("graph"):
            for prefix in denied_paths:
                if path.endswith(prefix) or f"{prefix}/" in path:
                    return httpx.Response(
                        403,
                        json={
                            "error": {
                                "message": "Insufficient privileges to complete "
                                "the operation."
                            }
                        },
                    )
            return httpx.Response(200, json={"value": []})
        # ARM: one visible subscription, readable.
        if path == "/subscriptions":
            return httpx.Response(200, json={"value": [{"subscriptionId": "sub-1"}]})
        return httpx.Response(200, json={"value": []})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def validate(denied_paths: set[str]):
    connector = AzureConnector(
        tenant_id="t", subscription_id="sub-1", http_client=azure_returning(denied_paths)
    )
    return await connector.validate_connection()


def test_every_probe_is_a_real_graph_method() -> None:
    """Probes hold the function, not its name.

    They were strings resolved with ``getattr`` inside the same ``try`` that
    catches a 403, so renaming a GraphClient method would have reported a
    missing Graph permission to every customer -- asking them to change their
    Entra configuration to fix a typo in ours. Holding the callable moves that
    failure to import time, and this asserts it stays that way.
    """
    from app.connectors.azure.client import GraphClient

    for probe, _subject, _permission in GRAPH_PROBES:
        assert callable(probe)
        assert getattr(GraphClient, probe.__name__, None) is probe


async def test_a_healthy_tenant_verifies_every_probe() -> None:
    check = await validate(set())

    for _probe, subject, _permission in GRAPH_PROBES:
        assert f"Microsoft Graph: {subject}" in check.permissions_verified
    assert check.ok


async def test_readable_organization_no_longer_vouches_for_the_rest() -> None:
    """The bug. ``/organization`` answers happily while ``/users`` refuses, and
    the old code called that a verified Directory.Read.All."""
    check = await validate({"/users"})

    assert not check.ok
    assert "Microsoft Graph: the tenant directory" in check.permissions_verified
    assert "Microsoft Graph: directory users" not in check.permissions_verified


async def test_a_denied_probe_names_the_permission_that_grants_it() -> None:
    problems = " ".join((await validate({"/users"})).problems)

    assert "directory users" in problems
    assert "User.Read.All or Directory.Read.All" in problems
    # Graph's own words, which describe the shape of the problem exactly.
    assert "Insufficient privileges" in problems


async def test_a_denied_probe_says_consent_must_be_run_again() -> None:
    """Consent resolves ``/.default`` at the moment it is granted, so a
    permission added to the registration afterwards is not covered by an
    existing grant. Nothing in Azure's UI hints at this."""
    problems = " ".join((await validate({"/directoryRoles"})).problems)

    assert "RoleManagement.Read.Directory" in problems
    assert "re-run admin consent" in problems
    assert "added" in problems and "consenting again" in problems


async def test_each_missing_permission_is_reported_separately() -> None:
    check = await validate({"/users", "/directoryRoles"})

    assert len(check.problems) == 2, "two missing permissions, two instructions"
    assert check.permissions_verified  # the tenant read still succeeded


async def test_a_later_failure_does_not_erase_the_per_call_diagnosis() -> None:
    """``_collect_category`` used to assign ``errors[category]``, so a second
    failure inside the same category replaced the specific instruction with
    whatever it happened to say. The two are joined instead."""
    collector_ = collector()
    snap = snapshot()

    async def explode() -> dict:
        await collector_._collect_identity(FakeGraph(denied={"list_users"}), snap)
        raise RuntimeError("the gather blew up")

    await collector_._collect_category(snap, "identity", explode)

    assert "directory users could not be read" in snap.errors["identity"]
    assert "the gather blew up" in snap.errors["identity"]
