"""Azure's collection plan: what to gather, and what each piece needs.

One entry per listing, rather than one per category. That granularity is the
whole reason the plan exists -- ``_collect_network`` used to gather NSGs, NICs
and public IPs under a single ``try``, so a failure reading public IPs took the
NSG data with it and every network rule reported UNKNOWN over data that had
arrived intact.

Each task also carries the ARM actions it needs. ``rbac.py`` derives the
permission set from this, so a listing and the permission that grants it can no
longer disagree: adding a task without its action fails a test rather than
reaching a customer as a 403 inside one collection category.

Every task gets its own client over a shared connection pool. Truncation is
recorded per client, and tasks in a wave run concurrently -- a single shared
client would record a truncated listing without saying which task it belonged
to, and the resulting PARTIAL would be attributed to whichever task happened to
be awaiting at the time.
"""

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from app.connectors.azure.auth import TokenProvider
from app.connectors.azure.client import (
    ArmClient,
    GraphClient,
    RequestLimiter,
    ResourceGraphClient,
)
from app.connectors.collection import CollectionTask, TaskData
from app.core.logging import get_logger

log = get_logger(__name__)

# How many per-resource detail calls one task runs at once. Enough to keep a
# scan brisk, low enough not to trip Azure's throttling on its own -- and now
# per task rather than global, since the executor already limits how many tasks
# are in flight.
DETAIL_CONCURRENCY = 8


class AzurePlanBuilder:
    """Builds the task list for one subscription."""

    def __init__(
        self,
        tokens: TokenProvider,
        subscription_id: str,
        http_client: httpx.AsyncClient,
        limiter: RequestLimiter | None = None,
    ) -> None:
        self.tokens = tokens
        self.subscription_id = subscription_id
        self._http = http_client
        # Handed to every client the plan builds, so the ceiling covers the
        # whole run rather than each task separately. DETAIL_CONCURRENCY below
        # still bounds one task's fan-out; that is fairness inside a wave, and
        # this is what keeps the product of the two off the subscription.
        self._limiter = limiter

    # ------------------------------------------------------------- plumbing
    def _arm_task(
        self,
        key: str,
        category: str,
        actions: tuple[str, ...],
        call: Callable[[ArmClient], Awaitable[dict[str, Any]]],
        depends_on: tuple[str, ...] = (),
    ) -> CollectionTask:
        """Wrap one ARM listing, turning truncation into a PARTIAL result.

        The client is created inside the task so its ``truncated`` set belongs
        to this task alone. Without that, a truncated listing during a
        concurrent wave could be attributed to the wrong task, and a PARTIAL
        pointing at the wrong data is worse than no PARTIAL at all.
        """

        async def run(collected: dict[str, Any]) -> TaskData:
            arm = ArmClient(self.tokens, self._http, limiter=self._limiter)
            data = await call(arm)
            if arm.truncated:
                return TaskData(
                    data,
                    partial_reason=(
                        "the listing was longer than CloudGuard reads in one scan, "
                        "so these results are incomplete and cannot support a pass"
                    ),
                )
            return TaskData(data)

        return CollectionTask(
            key=key, category=category, run=run, depends_on=depends_on, actions=actions
        )

    async def _gather_limited(self, coros: list[Awaitable[Any]]) -> list[Any]:
        semaphore = asyncio.Semaphore(DETAIL_CONCURRENCY)

        async def bounded(coro: Awaitable[Any]) -> Any:
            async with semaphore:
                return await coro

        return list(await asyncio.gather(*(bounded(c) for c in coros)))

    # ----------------------------------------------------------------- plan
    def build(self) -> list[CollectionTask]:
        sub = self.subscription_id

        async def nsgs(arm: ArmClient) -> dict[str, Any]:
            return {"network_security_groups": await arm.list_network_security_groups(sub)}

        async def nics(arm: ArmClient) -> dict[str, Any]:
            return {"network_interfaces": await arm.list_network_interfaces(sub)}

        async def public_ips(arm: ArmClient) -> dict[str, Any]:
            return {"public_ip_addresses": await arm.list_public_ips(sub)}

        async def vms(arm: ArmClient) -> dict[str, Any]:
            return {"virtual_machines": await arm.list_virtual_machines(sub)}

        async def storage(arm: ArmClient) -> dict[str, Any]:
            return {"storage_accounts": await arm.list_storage_accounts(sub)}

        async def postgres(arm: ArmClient) -> dict[str, Any]:
            return {"postgresql_servers": await arm.list_postgresql_servers(sub)}

        async def sql(arm: ArmClient) -> dict[str, Any]:
            servers = await arm.list_sql_servers(sub)

            # Firewall rules are a per-server call; without them AZ-DB-001
            # cannot tell "locked down" from "open to the world". A server
            # whose rules failed carries the reason, so the rule degrades for
            # that server rather than for the whole subscription.
            async def with_rules(server: dict[str, Any]) -> dict[str, Any]:
                try:
                    server["_firewall_rules"] = await arm.list_sql_firewall_rules(
                        server["id"]
                    )
                except Exception as exc:
                    server["_firewall_rules_error"] = str(exc)
                return server

            return {"sql_servers": await self._gather_limited(
                [with_rules(s) for s in servers]
            )}


        tasks = [
            self._arm_task(
                "network_security_groups",
                "network",
                ("Microsoft.Network/networkSecurityGroups/read",),
                nsgs,
            ),
            self._arm_task(
                "network_interfaces",
                "network",
                ("Microsoft.Network/networkInterfaces/read",),
                nics,
            ),
            self._arm_task(
                "public_ip_addresses",
                "network",
                ("Microsoft.Network/publicIPAddresses/read",),
                public_ips,
            ),
            self._arm_task(
                "virtual_machines",
                "compute",
                ("Microsoft.Compute/virtualMachines/read",),
                vms,
            ),
            self._arm_task(
                "storage_accounts",
                "storage",
                ("Microsoft.Storage/storageAccounts/read",),
                storage,
            ),
            self._arm_task(
                "sql_servers",
                "database",
                (
                    "Microsoft.Sql/servers/read",
                    "Microsoft.Sql/servers/firewallRules/read",
                ),
                sql,
            ),
            self._arm_task(
                "postgresql_servers",
                "database",
                ("Microsoft.DBforPostgreSQL/flexibleServers/read",),
                postgres,
            ),
            self._inventory_task(),
            self._diagnostics_task(),
            *self._identity_tasks(),
        ]
        return tasks

    def _inventory_task(self) -> CollectionTask:
        """Everything in the subscription, read through Resource Graph.

        The only task that does not go to ARM, and the reason is what it asks
        for: not one provider's resources but all of them. ARM answers that
        with a paged listing whose completeness can only be inferred from
        whether the page cap was reached, while Resource Graph answers it in
        one query and states how many rows the query matched -- so a short
        read is detected by comparing counts rather than by noticing that
        paging stopped.

        It is also the task that scales worst on ARM as a tenant grows, and the
        one whose data no rule reads, which together make it the right first
        thing to move and the cheapest one to get wrong.
        """

        async def run(collected: dict[str, Any]) -> TaskData:
            client = ResourceGraphClient(
                self.tokens, self._http, limiter=self._limiter
            )
            rows = await client.list_inventory(self.subscription_id)
            data = {"resources": rows}
            if client.truncated:
                return TaskData(
                    data,
                    partial_reason=(
                        "the inventory query returned fewer resources than the "
                        "subscription holds, so these results are incomplete "
                        "and cannot support a pass"
                    ),
                )
            return TaskData(data)

        return CollectionTask(
            key="resources",
            category="resources",
            run=run,
            actions=(
                "Microsoft.Resources/subscriptions/read",
                "Microsoft.Resources/subscriptions/resources/read",
                "Microsoft.ResourceGraph/resources/read",
            ),
        )

    def _diagnostics_task(self) -> CollectionTask:
        """Diagnostic settings for the resources AZ-LOG-001 covers.

        The only task with real dependencies, and the reason the executor sorts
        rather than just running everything at once: it needs the ids that the
        storage, SQL and NSG listings produce. That used to be expressed as
        "call it fifth".
        """
        sources = ("storage_accounts", "sql_servers", "network_security_groups")

        async def run(collected: dict[str, Any]) -> TaskData:
            arm = ArmClient(self.tokens, self._http, limiter=self._limiter)
            targets = [
                item["id"]
                for key in sources
                for item in collected.get(key, [])
                if item.get("id")
            ]

            failures = 0

            async def for_resource(resource_id: str) -> tuple[str, list | str]:
                nonlocal failures
                try:
                    return resource_id, await arm.list_diagnostic_settings(resource_id)
                except Exception as exc:
                    failures += 1
                    return resource_id, f"error: {exc}"

            pairs = await self._gather_limited([for_resource(r) for r in targets])
            data = {"diagnostic_settings": dict(pairs)}

            # A resource whose settings could not be read is a resource whose
            # logging posture is unknown, and "most of them were fine" is not
            # an answer AZ-LOG-001 is allowed to give.
            if failures:
                return TaskData(
                    data,
                    partial_reason=(
                        f"diagnostic settings could not be read for {failures} of "
                        f"{len(targets)} resources"
                    ),
                )
            return TaskData(data)

        return CollectionTask(
            key="diagnostic_settings",
            category="logging",
            run=run,
            depends_on=sources,
            actions=("Microsoft.Insights/diagnosticSettings/read",),
        )

    def _identity_tasks(self) -> list[CollectionTask]:
        """Directory state. Graph, so no ARM action grants any of it."""

        async def users(collected: dict[str, Any]) -> TaskData:
            graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
            found = await graph.list_users()
            if graph.truncated:
                return TaskData(
                    {"users": found},
                    partial_reason="the directory is larger than one scan reads",
                )
            return TaskData({"users": found})

        async def roles(collected: dict[str, Any]) -> TaskData:
            graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
            found = await graph.list_directory_roles()
            return TaskData({"directory_roles": found})

        return [
            CollectionTask(key="users", category="identity", run=users),
            CollectionTask(key="directory_roles", category="identity", run=roles),
            CollectionTask(
                key="user_role_map",
                category="identity",
                run=self._role_membership,
                depends_on=("users", "directory_roles"),
            ),
        ]

    async def _role_membership(self, collected: dict[str, Any]) -> TaskData:
        """Who holds which directory role, and whether they have MFA.

        Authentication methods cost one Graph call per user, so they are read
        only for members of the roles AZ-ID-001 actually applies to.
        """
        from app.connectors.azure.collector import PRIVILEGED_ROLE_NAMES

        graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
        role_map: dict[str, list[str]] = {}
        privileged: set[str] = set()
        failures = 0

        for role in collected.get("directory_roles", []):
            name = role.get("displayName", "")
            try:
                members = await graph.list_role_members(role["id"])
            except Exception as exc:
                failures += 1
                log.warning("azure.role_members_failed", role=name, error=str(exc))
                continue
            for member in members:
                member_id = member.get("id")
                if not member_id:
                    continue
                role_map.setdefault(member_id, []).append(name)
                if name.strip().lower() in PRIVILEGED_ROLE_NAMES:
                    privileged.add(member_id)

        async def methods_for(user_id: str) -> tuple[str, list | None]:
            try:
                return user_id, await graph.list_authentication_methods(user_id)
            except Exception as exc:
                # None, not [], so AZ-ID-001 reports UNKNOWN rather than
                # concluding this administrator has no MFA configured.
                log.warning("azure.auth_methods_failed", error=str(exc))
                return user_id, None

        pairs = await self._gather_limited([methods_for(u) for u in privileged])
        data = {
            "user_role_map": role_map,
            "authentication_methods": dict(pairs),
        }
        if failures:
            return TaskData(
                data, partial_reason=f"membership unreadable for {failures} role(s)"
            )
        return TaskData(data)
