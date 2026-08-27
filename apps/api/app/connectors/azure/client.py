"""Thin async REST clients for Azure Resource Manager and Microsoft Graph.

Deliberately REST rather than the ``azure-mgmt-*`` SDK wrappers. The snapshot is
supposed to be the provider's own JSON, kept verbatim so a scan can be replayed
later; going through SDK model objects would mean serializing them back out
again, and the SDKs are synchronous. MSAL — Microsoft's own auth library — still
handles every token.
"""

from typing import Any, Self

import httpx

from app.connectors.azure.auth import TokenProvider
from app.core.errors import CloudConnectionError
from app.core.logging import get_logger

log = get_logger(__name__)

ARM_BASE = "https://management.azure.com"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"

DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)


class AzureApiError(CloudConnectionError):
    """An Azure API call failed. Carries enough detail to explain a gap."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.azure_status_code = status_code


class _BaseClient:
    base_url: str

    def __init__(self, tokens: TokenProvider, client: httpx.AsyncClient | None = None) -> None:
        self.tokens = tokens
        self._client = client
        self._owns_client = client is None

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
        response = await self._client.get(full_url, headers=self._auth_header(), params=params)

        if response.status_code == 403:
            raise AzureApiError(
                "Access denied. Check that the Reader role is assigned and admin consent "
                "was granted.",
                status_code=403,
            )
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After", "unknown")
            raise AzureApiError(
                f"Azure is throttling requests (retry after {retry_after}s)", status_code=429
            )
        if response.status_code >= 400:
            detail = ""
            try:
                detail = response.json().get("error", {}).get("message", "")
            except Exception:
                detail = response.text[:200]
            raise AzureApiError(
                f"Azure API returned {response.status_code}: {detail}",
                status_code=response.status_code,
            )

        return response.json()

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
            log.warning("azure.pagination_truncated", url=url, pages=pages)
        return items


class ArmClient(_BaseClient):
    """Azure Resource Manager — subscriptions, resources, configuration."""

    base_url = ARM_BASE

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
