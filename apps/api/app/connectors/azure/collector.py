"""Collection: Azure APIs -> raw snapshot.

Collection never evaluates anything. It gathers, records what it could not
gather, and hands both to the normalizer. That separation is what makes a scan
reproducible and a coverage gap explainable.

Every category is isolated. A Storage API timeout records
``errors["storage"] = "..."`` and collection continues; the rules that depend on
storage data then return UNKNOWN rather than evaluating against nothing
(AZURE_INTEGRATION.md section 5).
"""

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

import httpx

from app.connectors.azure.auth import TokenProvider
from app.connectors.azure.client import ArmClient, GraphClient
from app.connectors.base import RawSnapshot
from app.core.enums import Provider
from app.core.logging import get_logger

log = get_logger(__name__)

T = TypeVar("T")

# Directory roles whose members we bother reading MFA state for. Reading
# authentication methods costs one Graph call per user, so we spend it only
# where AZ-ID-001 actually applies.
PRIVILEGED_ROLE_NAMES = {
    "global administrator",
    "privileged role administrator",
    "privileged authentication administrator",
    "security administrator",
    "application administrator",
    "cloud application administrator",
    "exchange administrator",
    "sharepoint administrator",
    "user administrator",
    "billing administrator",
    "conditional access administrator",
    "hybrid identity administrator",
    "intune administrator",
}

# How many per-resource detail calls to run at once. Enough to keep a scan
# brisk, low enough not to trip Azure's throttling.
DETAIL_CONCURRENCY = 8


class AzureCollector:
    def __init__(
        self,
        tenant_id: str,
        subscription_id: str,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.subscription_id = subscription_id
        self.tokens = TokenProvider(tenant_id)
        self._http = http_client

    async def collect(self) -> RawSnapshot:
        snapshot = RawSnapshot(
            provider=Provider.AZURE,
            tenant_id=self.tenant_id,
            subscription_id=self.subscription_id,
        )

        async with ArmClient(self.tokens, self._http) as arm:
            await self._collect_category(
                snapshot, "network", lambda: self._collect_network(arm)
            )
            await self._collect_category(
                snapshot, "compute", lambda: self._collect_compute(arm)
            )
            await self._collect_category(
                snapshot, "storage", lambda: self._collect_storage(arm)
            )
            await self._collect_category(
                snapshot, "database", lambda: self._collect_database(arm)
            )
            await self._collect_category(
                snapshot, "logging", lambda: self._collect_logging(arm, snapshot)
            )
            await self._collect_category(
                snapshot, "resources", lambda: self._collect_inventory(arm)
            )

        async with GraphClient(self.tokens, self._http) as graph:
            await self._collect_category(
                snapshot, "identity", lambda: self._collect_identity(graph, snapshot)
            )

        return snapshot

    async def _collect_category(
        self,
        snapshot: RawSnapshot,
        category: str,
        collect: Callable[[], Awaitable[dict[str, Any]]],
    ) -> None:
        """Run one category, converting failure into a recorded gap.

        The bare ``except`` is the point of this method, not an oversight: no
        single API failure may take down a scan, and every failure must leave a
        trace that the rule engine can see.
        """
        try:
            snapshot.data.update(await collect())
        except Exception as exc:
            message = str(exc) or type(exc).__name__
            snapshot.errors[category] = message
            log.warning(
                "azure.collection_failed",
                category=category,
                tenant_id=self.tenant_id,
                error=message,
            )

    # ---------------------------------------------------------------- network
    async def _collect_network(self, arm: ArmClient) -> dict[str, Any]:
        nsgs, nics, public_ips = await asyncio.gather(
            arm.list_network_security_groups(self.subscription_id),
            arm.list_network_interfaces(self.subscription_id),
            arm.list_public_ips(self.subscription_id),
        )
        return {
            "network_security_groups": nsgs,
            "network_interfaces": nics,
            "public_ip_addresses": public_ips,
        }

    # ---------------------------------------------------------------- compute
    async def _collect_compute(self, arm: ArmClient) -> dict[str, Any]:
        return {"virtual_machines": await arm.list_virtual_machines(self.subscription_id)}

    # ---------------------------------------------------------------- storage
    async def _collect_storage(self, arm: ArmClient) -> dict[str, Any]:
        return {"storage_accounts": await arm.list_storage_accounts(self.subscription_id)}

    # --------------------------------------------------------------- database
    async def _collect_database(self, arm: ArmClient) -> dict[str, Any]:
        sql_servers, pg_servers = await asyncio.gather(
            arm.list_sql_servers(self.subscription_id),
            arm.list_postgresql_servers(self.subscription_id),
        )

        # Firewall rules are a per-server call; without them AZ-DB-001 cannot
        # tell "locked down" from "open to the world".
        async def with_rules(server: dict[str, Any]) -> dict[str, Any]:
            try:
                rules = await arm.list_sql_firewall_rules(server["id"])
            except Exception as exc:
                server["_firewall_rules_error"] = str(exc)
                return server
            server["_firewall_rules"] = rules
            return server

        sql_servers = await self._gather_limited([with_rules(s) for s in sql_servers])
        return {"sql_servers": sql_servers, "postgresql_servers": pg_servers}

    # ---------------------------------------------------------------- logging
    async def _collect_logging(
        self, arm: ArmClient, snapshot: RawSnapshot
    ) -> dict[str, Any]:
        """Diagnostic settings for the resources AZ-LOG-001 covers."""
        targets: list[str] = []
        for key in ("storage_accounts", "sql_servers", "network_security_groups"):
            targets.extend(item["id"] for item in snapshot.data.get(key, []) if item.get("id"))

        async def for_resource(resource_id: str) -> tuple[str, list | str]:
            try:
                return resource_id, await arm.list_diagnostic_settings(resource_id)
            except Exception as exc:
                return resource_id, f"error: {exc}"

        pairs = await self._gather_limited([for_resource(rid) for rid in targets])
        return {"diagnostic_settings": dict(pairs)}

    # -------------------------------------------------------------- inventory
    async def _collect_inventory(self, arm: ArmClient) -> dict[str, Any]:
        return {"resources": await arm.list_resources(self.subscription_id)}

    # --------------------------------------------------------------- identity
    async def _collect_identity(
        self, graph: GraphClient, snapshot: RawSnapshot
    ) -> dict[str, Any]:
        """Directory state, degrading one call at a time rather than all at once.

        These two calls used to be bare, so a 403 on ``/directoryRoles`` threw
        away the user list that had already been read successfully -- and with
        it the whole identity asset inventory, for a permission that only the
        role rules needed. The calls below have always been defended
        individually; these two were the exception.

        Recording the gap is not optional, and is why the snapshot is passed
        in: partial identity data must still mark the category failed, so every
        identity rule degrades to UNKNOWN. Half a directory is not grounds for
        saying anyone's MFA is fine (RULE_ENGINE.md section 2).
        """
        failures: list[str] = []

        try:
            users = await graph.list_users()
        except Exception as exc:
            log.warning("azure.users_failed", tenant_id=self.tenant_id, error=str(exc))
            failures.append(f"directory users could not be read ({exc})")
            users = []

        try:
            roles = await graph.list_directory_roles()
        except Exception as exc:
            log.warning("azure.roles_failed", tenant_id=self.tenant_id, error=str(exc))
            failures.append(f"directory roles could not be read ({exc})")
            roles = []

        if failures:
            snapshot.errors["identity"] = "; ".join(failures)

        # user id -> [role display names]
        role_map: dict[str, list[str]] = {}
        privileged_ids: set[str] = set()

        for role in roles:
            role_name = role.get("displayName", "")
            try:
                members = await graph.list_role_members(role["id"])
            except Exception as exc:
                log.warning("azure.role_members_failed", role=role_name, error=str(exc))
                continue
            for member in members:
                member_id = member.get("id")
                if not member_id:
                    continue
                role_map.setdefault(member_id, []).append(role_name)
                if role_name.strip().lower() in PRIVILEGED_ROLE_NAMES:
                    privileged_ids.add(member_id)

        async def methods_for(user_id: str) -> tuple[str, list | None]:
            try:
                methods = await graph.list_authentication_methods(user_id)
            except Exception as exc:
                # Usually a missing UserAuthenticationMethod.Read.All consent.
                # None (not []) so the rule reports UNKNOWN rather than "no MFA".
                log.warning("azure.auth_methods_failed", error=str(exc))
                return user_id, None
            return user_id, methods

        pairs = await self._gather_limited([methods_for(uid) for uid in privileged_ids])

        return {
            "users": users,
            "directory_roles": roles,
            "user_role_map": role_map,
            "authentication_methods": dict(pairs),
        }

    async def _gather_limited(self, coros: list[Awaitable[T]]) -> list[T]:
        semaphore = asyncio.Semaphore(DETAIL_CONCURRENCY)

        async def run(coro: Awaitable[T]) -> T:
            async with semaphore:
                return await coro

        return list(await asyncio.gather(*(run(c) for c in coros)))
