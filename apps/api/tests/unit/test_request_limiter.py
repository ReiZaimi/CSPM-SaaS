"""The ceiling on how much of a subscription a scan asks for at once.

Concurrency in the collector is nested, and nobody owned the product of it. A
wave of tasks runs together; several of those tasks fan out per resource under
their own semaphore. Both numbers look modest and their product does not, and
it moves every time a task joins the plan -- so the limit belongs over
requests, which is what Azure meters, rather than over tasks, which are a proxy
that gets worse with every plan change.
"""

import asyncio

import httpx
import pytest

from app.connectors.azure.client import ArmClient, RequestLimiter


class FakeTokens:
    def arm_token(self) -> str:
        return "arm"

    def graph_token(self) -> str:
        return "graph"


class ConcurrencyWatcher:
    """An Azure that reports the most requests it ever had open at once."""

    def __init__(self, hold: float = 0.01) -> None:
        self.hold = hold
        self.in_flight = 0
        self.peak = 0
        self.calls = 0

    def client(self) -> httpx.AsyncClient:
        async def handler(request: httpx.Request) -> httpx.Response:
            self.calls += 1
            self.in_flight += 1
            self.peak = max(self.peak, self.in_flight)
            try:
                await asyncio.sleep(self.hold)
            finally:
                self.in_flight -= 1
            return httpx.Response(200, json={"value": [{"id": "/x", "name": "a"}]})

        return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_the_cap_holds_across_clients_that_never_meet() -> None:
    """The point of a scan-wide limiter: two tasks build their own clients and
    share nothing except the subscription being read, which is the only thing
    Azure counts."""
    watcher = ConcurrencyWatcher()
    http = watcher.client()
    limiter = RequestLimiter(3)

    async def one_call(n: int) -> None:
        arm = ArmClient(FakeTokens(), http, limiter=limiter)
        await arm.list_storage_accounts(f"sub-{n}")

    await asyncio.gather(*(one_call(n) for n in range(12)))

    assert watcher.calls == 12
    assert watcher.peak <= 3
    assert limiter.stats()["requests"] == 12


async def test_nested_fan_out_cannot_multiply_past_the_cap() -> None:
    """Four outer tasks, six inner calls apiece: twenty-four requests that
    without a shared ceiling arrive together."""
    watcher = ConcurrencyWatcher()
    http = watcher.client()
    limiter = RequestLimiter(5)

    async def outer(n: int) -> None:
        arm = ArmClient(FakeTokens(), http, limiter=limiter)
        await asyncio.gather(
            *(arm.list_sql_firewall_rules(f"/servers/{n}-{i}") for i in range(6))
        )

    await asyncio.gather(*(outer(n) for n in range(4)))

    assert watcher.calls == 24
    assert watcher.peak <= 5
    assert limiter.peak_in_flight <= 5


async def test_paging_releases_between_pages() -> None:
    """A permit covers one request, not one listing. Holding it across a paged
    read would let a single large listing occupy the ceiling on its own."""
    pages = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        pages["n"] += 1
        body: dict = {"value": [{"id": f"/{pages['n']}"}]}
        if pages["n"] < 3:
            body["nextLink"] = "https://management.azure.com/next"
        return httpx.Response(200, json=body)

    limiter = RequestLimiter(1)
    arm = ArmClient(
        FakeTokens(),
        httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        limiter=limiter,
    )

    found = await arm.list_storage_accounts("sub-1")

    assert len(found) == 3
    assert limiter.stats()["requests"] == 3, "one permit taken per page"


async def test_a_throttled_call_waits_without_holding_a_slot() -> None:
    """Retry-After is time spent not using the network. Holding a permit
    through it would idle part of the budget exactly when Azure has asked the
    scan to slow down -- and with a ceiling of one, would stop it entirely.

    The wait here is ten seconds, so a permit held across it blocks the second
    call past this test's patience rather than merely slowing it.
    """
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path.endswith("storageAccounts"):
            return httpx.Response(429, headers={"Retry-After": "10"}, json={})
        return httpx.Response(200, json={"value": []})

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    limiter = RequestLimiter(1)

    throttled = asyncio.create_task(
        ArmClient(FakeTokens(), http, limiter=limiter).list_storage_accounts("s")
    )
    # Long enough for that call to take the only permit and be told to back off.
    await asyncio.sleep(0.05)

    await asyncio.wait_for(
        ArmClient(FakeTokens(), http, limiter=limiter).list_virtual_machines("s"),
        timeout=2,
    )
    assert any("virtualMachines" in path for path in seen)

    throttled.cancel()
    with pytest.raises(asyncio.CancelledError):
        await throttled


async def test_no_limiter_means_no_gate() -> None:
    """One-off probes outside collection -- connection validation, the consent
    read-back -- are not a scan and are not metered as one."""
    watcher = ConcurrencyWatcher()
    http = watcher.client()

    await asyncio.gather(
        *(
            ArmClient(FakeTokens(), http).list_storage_accounts(f"sub-{n}")
            for n in range(8)
        )
    )

    assert watcher.peak > 1


def test_a_ceiling_of_zero_is_refused() -> None:
    """A limiter that admits nothing would hang the scan rather than fail it."""
    with pytest.raises(ValueError):
        RequestLimiter(0)
