"""The Azure plan, run end to end against a faked ARM and Graph.

Exercises what the old sequential collector could not express, on real plan
tasks rather than stand-ins: independent listings surviving each other, the
diagnostics task waiting for the ids it needs, and a truncated listing arriving
as PARTIAL instead of passing for the whole environment.
"""

import httpx
import pytest

from app.connectors.azure.collector import AzureCollector
from app.connectors.collection import TaskOutcome


class FakeTokens:
    def __init__(self, tenant_id: str = "t") -> None:
        self.tenant_id = tenant_id

    def arm_token(self) -> str:
        return "arm"

    def graph_token(self) -> str:
        return "graph"


def azure(
    *, fail: set[str] | None = None, truncate: set[str] | None = None
) -> httpx.AsyncClient:
    """An Azure that answers every listing with one item.

    ``fail`` and ``truncate`` match on a path fragment, so a test can break one
    listing and leave its neighbours working -- which is the behaviour under
    test.
    """
    fail = fail or set()
    truncate = truncate or set()

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        for fragment in fail:
            if fragment in path:
                return httpx.Response(403, json={"error": {"message": "denied"}})

        body: dict = {"value": [{"id": f"/x/{path.rsplit('/', 1)[-1]}", "name": "a"}]}
        # A listing that never stops offering another page is what hitting the
        # page cap looks like from the client's side.
        for fragment in truncate:
            if fragment in path:
                body["nextLink"] = f"https://management.azure.com{path}?page=next"
        return httpx.Response(200, json=body)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.fixture(autouse=True)
def _no_real_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.connectors.azure.collector.TokenProvider", FakeTokens
    )


async def collect(**kwargs):
    collector = AzureCollector(
        tenant_id="t", subscription_id="sub-1", http_client=azure(**kwargs)
    )
    return await collector.collect()


# ------------------------------------------------------------------- the plan
async def test_a_healthy_tenant_collects_everything_and_records_no_gap() -> None:
    snapshot = await collect()

    assert snapshot.errors == {}
    assert snapshot.data["network_security_groups"]
    assert snapshot.data["storage_accounts"]
    assert {c["outcome"] for c in snapshot.coverage.values()} == {"COMPLETE"}


async def test_the_coverage_report_travels_with_the_snapshot() -> None:
    """Stored rather than logged, because the rule engine is the only thing
    that can act on it."""
    snapshot = await collect()

    assert "storage_accounts" in snapshot.coverage
    entry = snapshot.coverage["storage_accounts"]
    assert entry["category"] == "storage"
    assert entry["outcome"] == TaskOutcome.COMPLETE.value


async def test_one_failed_listing_does_not_cost_its_siblings() -> None:
    """Network gathered NSGs, NICs and public IPs under one try, so a public IP
    failure discarded NSG data that had already arrived."""
    snapshot = await collect(fail={"publicIPAddresses"})

    assert snapshot.data["network_security_groups"], "NSGs still collected"
    assert snapshot.data["network_interfaces"], "NICs still collected"
    assert snapshot.coverage["public_ip_addresses"]["outcome"] == "FAILED"
    assert snapshot.coverage["network_security_groups"]["outcome"] == "COMPLETE"


async def test_a_failed_listing_still_degrades_its_category() -> None:
    """Finer collection must not mean a quieter failure: the rules that needed
    public IPs still have to report UNKNOWN."""
    snapshot = await collect(fail={"publicIPAddresses"})

    assert "network" in snapshot.errors
    assert "public_ip_addresses" in snapshot.errors["network"]


async def test_an_unrelated_category_is_untouched_by_a_failure() -> None:
    snapshot = await collect(fail={"publicIPAddresses"})
    assert "storage" not in snapshot.errors


# ------------------------------------------------------------ the truncation
async def test_a_truncated_listing_is_recorded_as_partial() -> None:
    """The defect this closes. Without it the rules would evaluate part of the
    environment and return PASS over the rest."""
    snapshot = await collect(truncate={"storageAccounts"})

    assert snapshot.data["storage_accounts"], "what was read is still kept"
    assert snapshot.coverage["storage_accounts"]["outcome"] == "PARTIAL"


async def test_a_truncated_listing_degrades_its_rules_like_a_failure() -> None:
    """A list missing an unknown number of entries cannot support "none of them
    are public", so it must reach the engine the way an outage does."""
    snapshot = await collect(truncate={"storageAccounts"})

    assert "storage" in snapshot.errors
    assert "incomplete" in snapshot.errors["storage"]


# ------------------------------------------------------------ the dependency
async def test_diagnostics_wait_for_the_ids_they_need() -> None:
    snapshot = await collect()
    assert snapshot.data["diagnostic_settings"], "ran after its inputs"


async def test_diagnostics_are_skipped_when_their_inputs_are_missing() -> None:
    """Nothing is wrong with the diagnostics task itself, and reporting it as
    failed would send someone looking for a second problem."""
    snapshot = await collect(fail={"storageAccounts", "servers", "networkSecurityGroups"})

    assert snapshot.coverage["diagnostic_settings"]["outcome"] == "SKIPPED"
    assert "logging" in snapshot.errors


async def test_progress_counts_every_task_in_the_plan() -> None:
    seen: list[tuple[int, int]] = []

    async def record(done: int, total: int) -> None:
        seen.append((done, total))

    collector = AzureCollector(
        tenant_id="t", subscription_id="sub-1", http_client=azure()
    )
    await collector.collect(record)

    assert seen, "collection reports progress"
    assert seen[-1][0] == seen[-1][1], "finishes at 100%"
    assert seen[-1][1] > 5, "the plan is more than a handful of tasks"
