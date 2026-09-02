"""Thin async REST clients for Azure Resource Manager and Microsoft Graph.

Deliberately REST rather than the ``azure-mgmt-*`` SDK wrappers. The snapshot is
supposed to be the provider's own JSON, kept verbatim so a scan can be replayed
later; going through SDK model objects would mean serializing them back out
again, and the SDKs are synchronous. MSAL — Microsoft's own auth library — still
handles every token.
"""

import asyncio
import random
from email.utils import parsedate_to_datetime
from types import TracebackType
from typing import Any, ClassVar, Self

import httpx

from app.connectors.azure.auth import TokenProvider
from app.core.errors import CloudConnectionError
from app.core.logging import get_logger

log = get_logger(__name__)

ARM_BASE = "https://management.azure.com"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
RESOURCE_GRAPH_QUERY_URL = (
    "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
)

DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)

# Azure throttles ARM reads per subscription as ordinary behaviour, not as an
# incident, and answers with 429 plus a Retry-After. Without this a throttled
# call raised, and because a category gathers several calls at once, one 429
# cost every rule that depended on that whole category -- reported as UNKNOWN,
# which is honest but avoidable.
MAX_ATTEMPTS = 4
# A single Retry-After longer than this is not worth waiting on inside a scan.
MAX_RETRY_WAIT_SECONDS = 20.0
# ...and neither is a series of shorter ones. Without a total budget, four
# attempts against a Retry-After of 30 would hold one call -- and the worker
# slot behind it -- for a minute and a half, while the rest of the plan waits.
# Past this the category is recorded as unreadable, which is a truthful answer
# available now rather than a possibly-better one much later.
RETRY_BUDGET_SECONDS = 30.0

# How many Azure requests one scan may have in flight at once, across every
# client it builds. See RequestLimiter for why the number lives at this level
# rather than inside a task.
DEFAULT_MAX_CONCURRENT_REQUESTS = 16


class RequestLimiter:
    """A ceiling on concurrent Azure requests, shared by one scan.

    Concurrency in the collector is nested and nobody owns the product. The
    executor runs a wave of tasks at once; several of those tasks then fan out
    per resource under their own semaphore. Two limits that each look modest --
    a wave of nine tasks, eight detail calls apiece -- multiply to seventy-odd
    requests against one subscription, and the number moves every time a task
    is added to the plan. Azure answers that with 429s, which the retry path
    then turns into wall-clock time, and past the retry budget into recorded
    gaps: a scan that collects less because it asked for more at once.

    So the cap is expressed once, over the thing Azure actually meters --
    requests -- rather than over tasks, which are only a proxy for requests and
    a worse one after every plan change. The per-task limits stay: they are
    fairness between tasks inside one wave, not protection for the
    subscription. This is the protection.

    A permit is held for one HTTP attempt and released before any retry sleep,
    so a throttled call waits without holding a slot the rest of the plan
    could use. Nothing acquires a permit while holding another, and no task
    waits on another task's request, so there is no cycle here to deadlock on.
    """

    def __init__(self, max_concurrent: int = DEFAULT_MAX_CONCURRENT_REQUESTS) -> None:
        if max_concurrent < 1:
            raise ValueError("max_concurrent must be at least 1")
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._in_flight = 0
        # Kept because collection has no other account of what it cost. A scan
        # that spent a minute queued behind its own ceiling and one that never
        # touched it look identical in the logs otherwise, and the first is the
        # one that wants a different number.
        self.requests = 0
        self.peak_in_flight = 0
        self.waited_seconds = 0.0

    async def __aenter__(self) -> "RequestLimiter":
        started = asyncio.get_running_loop().time()
        await self._semaphore.acquire()
        self.waited_seconds += asyncio.get_running_loop().time() - started
        self.requests += 1
        self._in_flight += 1
        self.peak_in_flight = max(self.peak_in_flight, self._in_flight)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._in_flight -= 1
        self._semaphore.release()

    def stats(self) -> dict[str, Any]:
        return {
            "requests": self.requests,
            "peak_in_flight": self.peak_in_flight,
            "limit": self.max_concurrent,
            "waited_seconds": round(self.waited_seconds, 2),
        }


class AzureApiError(CloudConnectionError):
    """An Azure API call failed. Carries enough detail to explain a gap."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.azure_status_code = status_code


class _BaseClient:
    base_url: str

    # What a 403 from this surface actually means, in terms the customer can
    # act on. ARM access and Graph access are granted by two different people
    # doing two different things -- a role deployment and an admin consent --
    # and they fail independently, which is why ``validate_connection`` probes
    # them separately (AZURE_INTEGRATION.md section 2). A single sentence
    # naming both remedies throws that distinction away at the last step and
    # sends half of everyone who reads it to a blade that looks correctly
    # configured, because for their failure it is.
    access_denied_hint: ClassVar[str] = ""

    def __init__(
        self,
        tokens: TokenProvider,
        client: httpx.AsyncClient | None = None,
        limiter: RequestLimiter | None = None,
    ) -> None:
        self.tokens = tokens
        self._client = client
        self._owns_client = client is None
        # Shared across every client a scan builds, so the ceiling is on the
        # scan rather than on any one task. None means ungated, which is what
        # the one-off probes outside collection -- connection validation, the
        # consent read-back -- actually want.
        self._limiter = limiter
        # Paged listings that hit the page cap and returned less than the
        # provider holds. Recorded rather than logged, because a warning in
        # Railway's log stream cannot reach the rule engine, and the rule
        # engine is the only thing that can turn "we saw part of it" into
        # UNKNOWN instead of PASS.
        self.truncated: set[str] = set()

    async def __aenter__(self) -> Self:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=DEFAULT_TIMEOUT)
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def _auth_header(self) -> dict[str, str]:
        raise NotImplementedError

    async def get(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return await self._request("GET", url, params=params)

    async def post(self, url: str, body: dict[str, Any]) -> dict[str, Any]:
        """A read expressed as a POST, which Resource Graph queries are.

        Same retry, throttling and error handling as ``get``: what makes a call
        worth retrying is the answer Azure gave, not the verb it was asked
        with.
        """
        return await self._request("POST", url, json=body)

    async def _request(
        self,
        method: str,
        url: str,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self._client is None:  # pragma: no cover -- misuse guard
            raise RuntimeError("Client used outside an async context manager")

        full_url = url if url.startswith("http") else f"{self.base_url}{url}"

        spent = 0.0
        for attempt in range(MAX_ATTEMPTS):
            response = await self._send(method, full_url, params=params, json=json)
            if not self._should_retry(response) or attempt == MAX_ATTEMPTS - 1:
                break
            wait = self._retry_wait(response, attempt)
            if wait is None or spent + wait > RETRY_BUDGET_SECONDS:
                break
            spent += wait
            log.info(
                "azure.retrying",
                status=response.status_code,
                attempt=attempt + 1,
                wait_seconds=round(wait, 2),
            )
            await asyncio.sleep(wait)

        if response.status_code == 403:
            raise AzureApiError(
                f"Access denied. {self.access_denied_hint}"
                f"{self._reported_detail(response)}",
                status_code=403,
            )
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After", "unknown")
            raise AzureApiError(
                f"Azure is throttling requests (retry after {retry_after}s)", status_code=429
            )
        if response.status_code >= 400:
            raise AzureApiError(
                f"Azure API returned {response.status_code}: {self._detail(response)}",
                status_code=response.status_code,
            )

        return response.json()

    async def _send(
        self,
        method: str,
        url: str,
        params: dict[str, Any] | None,
        json: dict[str, Any] | None,
    ) -> httpx.Response:
        """One attempt, holding a scan-wide permit for exactly its duration.

        Acquired here rather than around the retry loop on purpose: a call
        waiting out a Retry-After is not using the network, and holding a slot
        through that sleep would idle part of the scan's budget precisely when
        Azure has told it to slow down.
        """
        assert self._client is not None  # narrowed by _request
        if self._limiter is None:
            return await self._client.request(
                method, url, headers=self._auth_header(), params=params, json=json
            )
        async with self._limiter:
            return await self._client.request(
                method, url, headers=self._auth_header(), params=params, json=json
            )

    @staticmethod
    def _should_retry(response: httpx.Response) -> bool:
        """Throttling and server faults are worth another go; 4xx is not.

        A 403 will still be a 403 in two seconds, and retrying it would turn a
        clear permission error into a slow one.
        """
        return response.status_code == 429 or 500 <= response.status_code < 600

    @classmethod
    def _retry_wait(cls, response: httpx.Response, attempt: int) -> float | None:
        """Seconds to wait, or None when waiting is not worth it.

        Azure's own Retry-After is preferred over any backoff curve invented
        here -- it is the only party that knows when the throttle lifts. Jitter
        is added to the fallback because a scan fires several calls at once and
        un-jittered backoff would retry them in the same instant that got them
        throttled.
        """
        hinted = cls._retry_after_seconds(response)
        if hinted is not None:
            return None if hinted > MAX_RETRY_WAIT_SECONDS else hinted
        return min(2.0**attempt + random.uniform(0, 0.5), MAX_RETRY_WAIT_SECONDS)

    @staticmethod
    def _retry_after_seconds(response: httpx.Response) -> float | None:
        """Retry-After, which is either a count of seconds or an HTTP date."""
        raw = response.headers.get("Retry-After")
        if not raw:
            return None
        try:
            return float(raw)
        except ValueError:
            pass
        try:
            when = parsedate_to_datetime(raw)
        except (TypeError, ValueError):
            return None
        from datetime import UTC, datetime

        return max(0.0, (when - datetime.now(UTC)).total_seconds())

    @staticmethod
    def _detail(response: httpx.Response) -> str:
        """Azure's own account of what went wrong, however it chose to send it."""
        try:
            return str(response.json().get("error", {}).get("message", ""))
        except Exception:
            return response.text[:200]

    def _reported_detail(self, response: httpx.Response) -> str:
        """The provider's message, appended only when it says something.

        Graph in particular answers a missing grant with "Insufficient
        privileges to complete the operation", which names the shape of the
        problem better than any sentence written here can.
        """
        detail = self._detail(response).strip()
        return f" Azure reported: {detail}" if detail else ""

    async def get_all(
        self, url: str, params: dict[str, Any] | None = None, max_pages: int = 50
    ) -> list[dict[str, Any]]:
        """Follow paging links and return the flattened item list.

        ``max_pages`` is a safety stop: a runaway pagination loop against a very
        large tenant should degrade one category to a partial result, not hang
        the whole scan.
        """
        items: list[dict[str, Any]] = []
        next_url: str | None = url
        pages = 0

        while next_url and pages < max_pages:
            payload = await self.get(next_url, params=params if pages == 0 else None)
            items.extend(payload.get("value", []))
            next_url = payload.get("nextLink") or payload.get("@odata.nextLink")
            pages += 1

        if next_url:
            # The dangerous case, and the reason this is not just a log line.
            # A list cut off at the page cap is still a list: the rules would
            # evaluate 5,000 storage accounts out of 8,000, find nothing public
            # among them, and return PASS -- reporting "no public storage
            # found" over three thousand resources nobody looked at. That is
            # exactly the confusion of "could not look" with "looked and it was
            # fine" that the four rule states exist to prevent, one layer below
            # where the doctrine is enforced.
            self.truncated.add(url)
            log.warning(
                "azure.pagination_truncated", url=url, pages=pages, items=len(items)
            )
        return items


class ArmClient(_BaseClient):
    """Azure Resource Manager — subscriptions, resources, configuration."""

    base_url = ARM_BASE
    # Not "the Reader role": CloudGuard stopped asking for Reader when the
    # custom role landed, and a customer sent to look for a Reader assignment
    # will not find one even on a correctly configured connection.
    access_denied_hint: ClassVar[str] = (
        "CloudGuard's scanner role is not assigned on this scope. Redeploy it "
        "from the connection page, or check Access control (IAM) on the "
        "subscription. This is not affected by admin consent."
    )

    def _auth_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.tokens.arm_token()}"}

    async def list_subscriptions(self) -> list[dict[str, Any]]:
        return await self.get_all("/subscriptions?api-version=2022-12-01")

    async def list_resources(self, subscription_id: str) -> list[dict[str, Any]]:
        return await self.get_all(
            f"/subscriptions/{subscription_id}/resources?api-version=2021-04-01"
        )

    async def list_network_security_groups(self, subscription_id: str) -> list[dict[str, Any]]:
        return await self.get_all(
            f"/subscriptions/{subscription_id}/providers/Microsoft.Network"
            "/networkSecurityGroups?api-version=2023-09-01"
        )

    async def list_network_interfaces(self, subscription_id: str) -> list[dict[str, Any]]:
        return await self.get_all(
            f"/subscriptions/{subscription_id}/providers/Microsoft.Network"
            "/networkInterfaces?api-version=2023-09-01"
        )

    async def list_public_ips(self, subscription_id: str) -> list[dict[str, Any]]:
        return await self.get_all(
            f"/subscriptions/{subscription_id}/providers/Microsoft.Network"
            "/publicIPAddresses?api-version=2023-09-01"
        )

    async def list_virtual_machines(self, subscription_id: str) -> list[dict[str, Any]]:
        return await self.get_all(
            f"/subscriptions/{subscription_id}/providers/Microsoft.Compute"
            "/virtualMachines?api-version=2023-09-01"
        )

    async def list_storage_accounts(self, subscription_id: str) -> list[dict[str, Any]]:
        return await self.get_all(
            f"/subscriptions/{subscription_id}/providers/Microsoft.Storage"
            "/storageAccounts?api-version=2023-01-01"
        )

    async def list_sql_servers(self, subscription_id: str) -> list[dict[str, Any]]:
        return await self.get_all(
            f"/subscriptions/{subscription_id}/providers/Microsoft.Sql"
            "/servers?api-version=2021-11-01"
        )

    async def list_sql_firewall_rules(self, server_id: str) -> list[dict[str, Any]]:
        return await self.get_all(f"{server_id}/firewallRules?api-version=2021-11-01")

    async def list_postgresql_servers(self, subscription_id: str) -> list[dict[str, Any]]:
        return await self.get_all(
            f"/subscriptions/{subscription_id}/providers/Microsoft.DBforPostgreSQL"
            "/flexibleServers?api-version=2023-03-01-preview"
        )

    async def list_diagnostic_settings(self, resource_id: str) -> list[dict[str, Any]]:
        return await self.get_all(
            f"{resource_id}/providers/Microsoft.Insights"
            "/diagnosticSettings?api-version=2021-05-01-preview"
        )

    async def list_role_assignments(self, subscription_id: str) -> list[dict[str, Any]]:
        return await self.get_all(
            f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization"
            "/roleAssignments?api-version=2022-04-01"
        )

    async def list_role_assignments_at_scope(self, scope: str) -> list[dict[str, Any]]:
        """Assignments at an arbitrary scope -- a management group, typically.

        Separate from ``list_role_assignments`` because a tenant-scoped
        connection's grant lives above any subscription, so there is no
        subscription to ask about when confirming it.
        """
        return await self.get_all(
            f"{scope}/providers/Microsoft.Authorization"
            "/roleAssignments?api-version=2022-04-01"
        )

    async def list_role_definitions(self, subscription_id: str) -> list[dict[str, Any]]:
        return await self.get_all(
            f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization"
            "/roleDefinitions?api-version=2022-04-01"
        )


class ResourceGraphClient(_BaseClient):
    """Azure Resource Graph — inventory, read across subscriptions at once.

    Deliberately a separate client rather than more methods on ``ArmClient``.
    The two speak to the same host and share the retry and throttling
    behaviour, and nothing else about them is the same: ARM is a per-provider
    listing API paged by ``nextLink`` and metered per subscription, Resource
    Graph is a KQL query surface paged by ``$skipToken`` and metered against a
    separate per-principal quota. Mixing them would put two paging models and
    two throttling stories behind one class, and a reader could no longer tell
    which one a call is subject to.

    Inventory is the whole remit for now. Resource Graph returns a projection
    of ARM's own state that is minutes stale in the worst case -- fine for
    "what exists here", wrong for the configuration a rule passes or fails on.
    Those reads stay on ARM, where the snapshot keeps the provider's own JSON
    verbatim (DECISIONS.md).
    """

    base_url = ARM_BASE
    access_denied_hint: ClassVar[str] = (
        "CloudGuard's scanner role does not grant Resource Graph queries on "
        "this scope. Redeploy the role from the connection page -- a role "
        "deployed before Resource Graph inventory shipped will not have it. "
        "This is not affected by admin consent."
    )

    # Page size. Resource Graph's own maximum is 1000 rows per page.
    PAGE_SIZE: ClassVar[int] = 1000

    def _auth_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.tokens.arm_token()}"}

    async def list_inventory(
        self, subscription_id: str, max_pages: int = 50
    ) -> list[dict[str, Any]]:
        """Every resource in one subscription, as inventory rather than config.

        The projection is deliberate and excludes ``properties``. Inventory
        answers what exists, where, and under whose resource group; the
        per-resource configuration a rule reasons about comes from the ARM
        listing for that type, which is the copy stored verbatim. Projecting
        ``properties`` here would double the size of every snapshot to hold a
        second, staler copy of data no rule reads.

        ``order by id asc`` is not cosmetic: Resource Graph's paging is only
        stable over an ordered query, and an unordered one can repeat or drop
        rows between pages -- which would be a miscount presented as an
        inventory.
        """
        query = (
            "Resources | project id, name, type, kind, location, resourceGroup, "
            "subscriptionId, managedBy, sku, plan, tags, identity, zones "
            "| order by id asc"
        )
        return await self._query(query, [subscription_id], max_pages=max_pages)

    async def probe_inventory(self, subscription_id: str) -> int:
        """Cheapest proof that inventory can be queried on this scope.

        One row, one page. Connection validation needs to know whether the
        query surface answers at all -- a role deployed before Resource Graph
        inventory shipped does not grant it -- and reading a whole tenant's
        inventory to learn that would make validating a connection as
        expensive as scanning one.

        Truncation is meaningless here and ignored: the query asks for a single
        row on purpose, so falling short of the total is the expected outcome.
        """
        rows = await self._query(
            "Resources | project id | order by id asc | limit 1",
            [subscription_id],
            max_pages=1,
        )
        return len(rows)

    async def _query(
        self, query: str, subscriptions: list[str], max_pages: int = 50
    ) -> list[dict[str, Any]]:
        """Run a KQL query, following ``$skipToken`` to the end of the results.

        Where ARM paging can only report that a cap was hit, Resource Graph
        states ``totalRecords`` for the whole query, so completeness is checked
        against a number the service supplied rather than inferred from having
        stopped early. That is the difference between "we read everything" and
        "we did not notice reading only some of it", and it is why truncation
        here is a comparison rather than a guess.
        """
        rows: list[dict[str, Any]] = []
        skip_token: str | None = None
        total: int | None = None
        service_truncated = False
        pages = 0

        while pages < max_pages:
            options: dict[str, Any] = {
                "resultFormat": "objectArray",
                "$top": self.PAGE_SIZE,
            }
            if skip_token:
                options["$skipToken"] = skip_token

            payload = await self.post(
                RESOURCE_GRAPH_QUERY_URL,
                {"subscriptions": subscriptions, "query": query, "options": options},
            )
            rows.extend(payload.get("data") or [])
            if total is None and isinstance(payload.get("totalRecords"), int):
                total = payload["totalRecords"]
            # Resource Graph's own word for "I did not return all of this",
            # sent as a string rather than a boolean.
            if str(payload.get("resultTruncated", "")).lower() == "true":
                service_truncated = True
            skip_token = payload.get("$skipToken")
            pages += 1
            if not skip_token:
                break

        short = total is not None and len(rows) < total
        if skip_token or service_truncated or short:
            # Recorded, not logged, for the same reason ARM truncation is: the
            # rule engine is the only thing that can turn a partial inventory
            # into UNKNOWN instead of a PASS nobody earned.
            self.truncated.add(RESOURCE_GRAPH_QUERY_URL)
            log.warning(
                "azure.resource_graph_truncated",
                pages=pages,
                rows=len(rows),
                total_records=total,
                result_truncated=service_truncated,
            )
        return rows


class GraphClient(_BaseClient):
    """Microsoft Graph — directory objects, roles, authentication methods."""

    base_url = GRAPH_BASE
    # Everything in the identity category comes through here, and none of it
    # goes anywhere near Azure RBAC.
    access_denied_hint: ClassVar[str] = (
        "Admin consent for CloudGuard's directory permissions is missing or "
        "incomplete. A Global Administrator must grant it under Microsoft "
        "Entra ID > Enterprise applications > CloudGuard > Permissions. "
        "Azure role assignments do not affect this."
    )

    def _auth_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.tokens.graph_token()}"}

    async def list_users(self) -> list[dict[str, Any]]:
        return await self.get_all(
            "/users?$select=id,displayName,userPrincipalName,accountEnabled&$top=999"
        )

    async def list_directory_roles(self) -> list[dict[str, Any]]:
        return await self.get_all("/directoryRoles")

    async def list_role_members(self, role_id: str) -> list[dict[str, Any]]:
        return await self.get_all(f"/directoryRoles/{role_id}/members")

    async def list_authentication_methods(self, user_id: str) -> list[dict[str, Any]]:
        return await self.get_all(f"/users/{user_id}/authentication/methods")

    async def get_organization(self) -> list[dict[str, Any]]:
        return await self.get_all("/organization")

    async def get_security_defaults(self) -> dict[str, Any]:
        """Whether Entra's own baseline is switched on.

        A singleton rather than a collection, so it is fetched directly rather
        than through ``get_all``. Enabling it requires MFA of every account in
        the tenant, which is how most small tenants have multi-factor at all --
        and it is the fallback the MFA rule's own remediation names for Entra ID
        Free.
        """
        return await self.get("/policies/identitySecurityDefaultsEnforcementPolicy")

    async def list_conditional_access_policies(self) -> list[dict[str, Any]]:
        """Every Conditional Access policy, enforced or not.

        Not filtered to the enabled ones here. ``state`` is part of what the
        rules have to reason about -- a policy in report-only mode grants
        nothing and looks identical in every other field -- and a collector that
        dropped the others would leave a rule unable to tell "no policy" from
        "a policy nobody turned on".
        """
        return await self.get_all("/identity/conditionalAccess/policies")

    async def list_group_members(self, group_id: str) -> list[dict[str, Any]]:
        """Who is in one group, by id.

        Read only for the groups a Conditional Access policy actually names, so
        the cost is a handful of calls rather than one per group in the tenant.
        Without it a policy that excludes a break-glass group -- which is how
        essentially every real tenant is configured -- could not be reasoned
        about at all, because CloudGuard would be unable to rule out that the
        account it is judging is the excluded one.
        """
        return await self.get_all(f"/groups/{group_id}/members?$select=id&$top=999")

    async def find_service_principal(self, app_id: str) -> dict[str, Any] | None:
        """CloudGuard's own service principal, as it exists in this tenant.

        Consent creates it; this reads back its object id. That id is what a
        customer's role assignment has to point at, and knowing it is the
        difference between "find CloudGuard in the portal" and a command with
        nothing left to fill in.
        """
        results = await self.get_all(
            f"/servicePrincipals?$filter=appId eq '{app_id}'&$select=id,appId,displayName"
        )
        return results[0] if results else None
