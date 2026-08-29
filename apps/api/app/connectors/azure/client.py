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
from typing import Any, ClassVar, Self

import httpx

from app.connectors.azure.auth import TokenProvider
from app.core.errors import CloudConnectionError
from app.core.logging import get_logger

log = get_logger(__name__)

ARM_BASE = "https://management.azure.com"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"

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

    def __init__(self, tokens: TokenProvider, client: httpx.AsyncClient | None = None) -> None:
        self.tokens = tokens
        self._client = client
        self._owns_client = client is None
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
        if self._client is None:  # pragma: no cover -- misuse guard
            raise RuntimeError("Client used outside an async context manager")

        full_url = url if url.startswith("http") else f"{self.base_url}{url}"

        spent = 0.0
        for attempt in range(MAX_ATTEMPTS):
            response = await self._client.get(
                full_url, headers=self._auth_header(), params=params
            )
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
