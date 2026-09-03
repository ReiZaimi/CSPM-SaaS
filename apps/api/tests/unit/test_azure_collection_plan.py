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

        # Resource Graph answers a query, not a listing: its own shape, its own
        # completeness signal, and a POST rather than a GET.
        if "Microsoft.ResourceGraph" in path:
            total = 2 if any("ResourceGraph" in f for f in truncate) else 1
            return httpx.Response(
                200,
                json={
                    "data": [{"id": "/x/inventory", "name": "a"}],
                    "totalRecords": total,
                    "count": 1,
                },
            )

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


# ------------------------------------- a listing read in part, one server deep
async def test_a_half_read_firewall_listing_makes_the_server_task_partial() -> None:
    """The SQL listing makes a second call per server, and used to report on
    the first alone.

    A per-server failure was recorded on the server for the rules to degrade on
    and nowhere else, so the reading came back COMPLETE -- and the one screen
    whose job is saying what was and was not read said everything was.
    """
    snapshot = await collect(fail={"firewallRules"})

    assert snapshot.data["sql_servers"], "the servers themselves were still read"
    assert snapshot.coverage["sql_servers"]["outcome"] == "PARTIAL"
    assert "firewall rules" in snapshot.coverage["sql_servers"]["detail"]


async def test_a_truncated_listing_still_reports_its_own_reason() -> None:
    """The wrapper's reason and the call's own reason are different facts, and
    the wrapper must not lose either."""
    snapshot = await collect(truncate={"Microsoft.Sql/servers"})

    assert snapshot.coverage["sql_servers"]["outcome"] == "PARTIAL"
    assert "longer than CloudGuard reads" in snapshot.coverage["sql_servers"]["detail"]


async def test_a_fully_read_listing_is_still_complete() -> None:
    """The other direction, and the one that keeps the signal worth having. A
    task that reports PARTIAL when nothing went wrong is a task nobody reads."""
    snapshot = await collect()

    assert snapshot.coverage["sql_servers"]["outcome"] == "COMPLETE"
    assert snapshot.coverage["sql_auditing"]["outcome"] == "COMPLETE"


# ------------------------------------------------- auditing is its own reading
async def test_auditing_is_collected_as_its_own_reading() -> None:
    """A key is the unit a rule depends on, and these two are different units:
    reachability rests on the servers and their firewall rules, the audit trail
    rests on this."""
    snapshot = await collect()

    assert "sql_auditing" in snapshot.coverage
    assert snapshot.data["sql_auditing"]


async def test_a_refused_auditing_read_leaves_the_server_listing_complete() -> None:
    """The whole reason for the split.

    A scanner role deployed before v4 reads servers and firewall rules
    perfectly well and is refused the auditing call. Folded into one key, that
    403 cost AZ-DB-001 its verdict too -- over a call it never reads, which is a
    gap CloudGuard invented rather than found.
    """
    snapshot = await collect(fail={"auditingSettings"})

    assert snapshot.coverage["sql_servers"]["outcome"] == "COMPLETE"
    assert snapshot.coverage["sql_auditing"]["outcome"] == "PARTIAL"


async def test_a_refused_auditing_read_names_the_role_as_the_likely_cause() -> None:
    """Otherwise a v3 customer sees an unexplained partial on every scan with
    nothing to act on."""
    snapshot = await collect(fail={"auditingSettings"})

    assert "role deployed before" in snapshot.coverage["sql_auditing"]["detail"]


async def test_auditing_waits_for_the_servers_it_reads(monkeypatch) -> None:
    """It is a dependent task: without the ids there is nothing to ask about,
    and asking anyway would report a gap where there was no server."""
    snapshot = await collect(fail={"Microsoft.Sql/servers"})

    assert snapshot.coverage["sql_auditing"]["outcome"] == "SKIPPED"


async def test_diagnostics_ask_about_the_subscription_itself() -> None:
    """The activity log, which AZ-LOG-002 judges.

    Every other target here is a resource whose own logging is in question;
    this one is the record of who did what across all of them. It is read
    through the same action and the same endpoint -- a subscription is a scope
    diagnostic settings apply to like any other -- so it costs no customer a
    new permission, which is why it shipped ahead of the checks that do.
    """
    snapshot = await collect()

    assert "/subscriptions/sub-1" in snapshot.data["diagnostic_settings"], (
        "the subscription's own diagnostic settings were never asked for, so "
        "the activity log check can only ever report UNKNOWN"
    )


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


# ------------------------------------------------------------- the inventory
async def test_inventory_is_read_through_resource_graph() -> None:
    """The one task that does not go to ARM. It asks for every provider's
    resources at once, which is a query rather than a listing."""
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(f"{request.method} {request.url.path}")
        if "Microsoft.ResourceGraph" in request.url.path:
            return httpx.Response(
                200, json={"data": [{"id": "/x"}], "totalRecords": 1, "count": 1}
            )
        return httpx.Response(200, json={"value": []})

    collector = AzureCollector(
        tenant_id="t",
        subscription_id="sub-1",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    snapshot = await collector.collect()

    assert snapshot.data["resources"], "inventory collected"
    assert snapshot.coverage["resources"]["outcome"] == "COMPLETE"
    assert "POST /providers/Microsoft.ResourceGraph/resources" in paths
    assert not any(
        path.endswith("/subscriptions/sub-1/resources") for path in paths
    ), "and not through the ARM listing it replaced"


async def test_an_inventory_short_of_its_stated_total_is_partial() -> None:
    """Resource Graph states how many rows the query matched, so a short read
    is a comparison rather than the inference ARM paging had to make."""
    snapshot = await collect(truncate={"ResourceGraph"})

    assert snapshot.coverage["resources"]["outcome"] == "PARTIAL"
    assert "resources" in snapshot.errors
    assert "incomplete" in snapshot.errors["resources"]


# --------------------------------------------------------------- the ceiling
async def test_the_whole_plan_shares_one_request_ceiling() -> None:
    """Every task builds its own client, and several fan out per resource
    underneath. What must not be per task is how many requests are open at
    once, because Azure meters the subscription rather than the task."""
    import asyncio

    from app.connectors.azure.client import RequestLimiter
    from app.connectors.azure.plan import AzurePlanBuilder
    from app.connectors.collection import CollectionRun

    state = {"in_flight": 0, "peak": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        state["in_flight"] += 1
        state["peak"] = max(state["peak"], state["in_flight"])
        try:
            await asyncio.sleep(0.005)
        finally:
            state["in_flight"] -= 1
        if "Microsoft.ResourceGraph" in request.url.path:
            return httpx.Response(
                200, json={"data": [{"id": "/x"}], "totalRecords": 1}
            )
        return httpx.Response(
            200, json={"value": [{"id": f"/x/{n}", "name": "a"} for n in range(5)]}
        )

    limiter = RequestLimiter(3)
    plan = AzurePlanBuilder(
        tokens=FakeTokens(),
        subscription_id="sub-1",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        limiter=limiter,
    ).build_account_plan()

    await CollectionRun(plan).execute({})

    assert limiter.stats()["requests"] > 10, "the plan really did fan out"
    assert state["peak"] <= 3


# ------------------------------------------ encryption is its own reading too
async def test_encryption_is_collected_as_its_own_reading() -> None:
    """A per-database fan-out beneath the server listing, keyed separately.

    The permissions behind it arrive in role v6, so on every connection that
    has not redeployed this is the reading that fails while the servers, their
    firewall rules and their auditing settings all succeed.
    """
    snapshot = await collect()

    assert "sql_tde" in snapshot.coverage
    assert snapshot.coverage["sql_tde"]["outcome"] == "COMPLETE"
    assert snapshot.data["sql_tde"]


async def test_a_refused_encryption_read_leaves_the_server_listing_complete() -> None:
    """The gap a role upgrade produces, and the one ``requires_evidence``
    exists to keep from spreading: a 403 here must not cost the reachability
    rule its verdict over a call it never reads."""
    snapshot = await collect(fail={"transparentDataEncryption"})

    assert snapshot.coverage["sql_servers"]["outcome"] == "COMPLETE"
    assert snapshot.coverage["sql_tde"]["outcome"] == "PARTIAL"


async def test_a_refused_encryption_read_names_the_role_as_the_likely_cause() -> None:
    """"Encryption state could not be read" points nowhere. "Your scanner role
    predates the permission" is a thing a customer can act on this afternoon."""
    snapshot = await collect(fail={"transparentDataEncryption"})

    assert "role deployed before" in snapshot.coverage["sql_tde"]["detail"]


async def test_a_refused_database_listing_is_reported_rather_than_empty() -> None:
    """A server whose databases could not be listed is not a server with no
    databases, and only one of those can support a pass."""
    snapshot = await collect(fail={"/databases"})

    assert snapshot.coverage["sql_tde"]["outcome"] == "PARTIAL"
    assert all(
        isinstance(entry, str) and entry.startswith("error:")
        for entry in snapshot.data["sql_tde"].values()
    )


async def test_encryption_waits_for_the_servers_it_reads() -> None:
    """It reads one call per database of each server, so it cannot run before
    the server listing that names them."""
    from app.connectors.azure.evidence import AzureEvidence
    from app.connectors.azure.plan import AzurePlanBuilder

    builder = AzurePlanBuilder(
        tokens=FakeTokens(), subscription_id="sub-1", http_client=azure()
    )
    task = next(
        t for t in builder.build_account_plan() if t.key is AzureEvidence.SQL_TDE
    )

    assert AzureEvidence.SQL_SERVERS in task.depends_on
