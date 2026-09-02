"""Azure's collection plans: what to gather, and what each piece needs.

Two plans, not one, because a scan reads two different things. ARM answers
questions about a *subscription* and is asked once per subscription;
Graph answers questions about the *tenant* and must be asked once for the whole
scan. Collecting both under one plan meant the directory was re-read for every
subscription -- and, worse than the cost, normalized into a separate set of user
resources each time, so one administrator without MFA produced one finding per
subscription.

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
    AzureApiError,
    GraphClient,
    RequestLimiter,
    ResourceGraphClient,
)
from app.connectors.azure.evidence import AzureEvidence
from app.connectors.collection import CollectionTask, TaskData
from app.connectors.evidence import ProviderEndpoint
from app.core.logging import get_logger

log = get_logger(__name__)

# How many per-resource detail calls one task runs at once. Enough to keep a
# scan brisk, low enough not to trip Azure's throttling on its own -- and now
# per task rather than global, since the executor already limits how many tasks
# are in flight.
DETAIL_CONCURRENCY = 8


# What each ARM listing calls, and the contract it calls under.
#
# Declared here beside the tasks rather than parsed out of ``client.py``: a
# parser would make the record a function of how the URL happens to be spelled,
# and the point is a statement that can be checked against the client rather
# than derived from it. ``tests/unit/test_provider_endpoints.py`` asserts every
# api-version below appears in the client, and that every ARM listing the client
# offers is declared by some task -- the same discipline ``rbac.py`` applies to
# actions, for the same reason: a declaration nothing verifies is a
# plausible-looking string.
ARM = "https://management.azure.com"

NSG_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Network"
    "/networkSecurityGroups",
    "2023-09-01",
)
NIC_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Network"
    "/networkInterfaces",
    "2023-09-01",
)
PUBLIC_IP_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Network"
    "/publicIPAddresses",
    "2023-09-01",
)
VM_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Compute"
    "/virtualMachines",
    "2023-09-01",
)
STORAGE_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Storage"
    "/storageAccounts",
    "2023-01-01",
)
SQL_SERVERS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Sql/servers",
    "2021-11-01",
)
# The second call the SQL task makes, per server. Declared rather than folded
# into the one above, because a reading of servers whose firewall rules failed
# is a different reading from one where both succeeded.
SQL_FIREWALL_ENDPOINT = ProviderEndpoint(
    f"{ARM}/{{serverId}}/firewallRules", "2021-11-01"
)
POSTGRES_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.DBforPostgreSQL"
    "/flexibleServers",
    "2023-03-01-preview",
)
ROLE_ASSIGNMENTS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Authorization"
    "/roleAssignments",
    "2022-04-01",
)
ROLE_DEFINITIONS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Authorization"
    "/roleDefinitions",
    "2022-04-01",
)
DIAGNOSTICS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/{{resourceId}}/providers/Microsoft.Insights/diagnosticSettings",
    "2021-05-01-preview",
)
RESOURCE_GRAPH_ENDPOINT = ProviderEndpoint(
    f"{ARM}/providers/Microsoft.ResourceGraph/resources", "2022-10-01"
)

# Microsoft Graph versions itself in the path rather than in a query parameter,
# so "v1.0" is the api-version here in every sense that matters: it is the
# contract the response shape is a function of, which is the whole reason this
# is recorded. Writing it as a version rather than leaving it blank keeps the
# question answerable in the same terms for both providers.
GRAPH = "https://graph.microsoft.com/v1.0"
GRAPH_VERSION = "v1.0"

USERS_ENDPOINT = ProviderEndpoint(f"{GRAPH}/users", GRAPH_VERSION)
DIRECTORY_ROLES_ENDPOINT = ProviderEndpoint(f"{GRAPH}/directoryRoles", GRAPH_VERSION)
ROLE_MEMBERS_ENDPOINT = ProviderEndpoint(
    f"{GRAPH}/directoryRoles/{{roleId}}/members", GRAPH_VERSION
)
AUTH_METHODS_ENDPOINT = ProviderEndpoint(
    f"{GRAPH}/users/{{userId}}/authentication/methods", GRAPH_VERSION
)
SECURITY_DEFAULTS_ENDPOINT = ProviderEndpoint(
    f"{GRAPH}/policies/identitySecurityDefaultsEnforcementPolicy", GRAPH_VERSION
)
CONDITIONAL_ACCESS_ENDPOINT = ProviderEndpoint(
    f"{GRAPH}/identity/conditionalAccess/policies", GRAPH_VERSION
)
GROUP_MEMBERS_ENDPOINT = ProviderEndpoint(
    f"{GRAPH}/groups/{{groupId}}/members", GRAPH_VERSION
)


class AzurePlanBuilder:
    """Builds the task lists a scan runs.

    ``subscription_id`` is optional because the directory plan does not need
    one: it reads the tenant, and the tenant is whichever one the token
    provider authenticates against. Building an account plan without a
    subscription is refused rather than allowed to produce URLs with ``None``
    in them.
    """

    def __init__(
        self,
        tokens: TokenProvider,
        subscription_id: str | None,
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
        key: AzureEvidence,
        actions: tuple[str, ...],
        call: Callable[[ArmClient], Awaitable[dict[str, Any]]],
        depends_on: tuple[AzureEvidence, ...] = (),
        endpoints: tuple[ProviderEndpoint, ...] = (),
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
            key=key,
            run=run,
            depends_on=depends_on,
            actions=actions,
            endpoints=endpoints,
        )

    async def _gather_limited(self, coros: list[Awaitable[Any]]) -> list[Any]:
        semaphore = asyncio.Semaphore(DETAIL_CONCURRENCY)

        async def bounded(coro: Awaitable[Any]) -> Any:
            async with semaphore:
                return await coro

        return list(await asyncio.gather(*(bounded(c) for c in coros)))

    # ----------------------------------------------------------------- plans
    def build_account_plan(self) -> list[CollectionTask]:
        """Everything that is a reading of one subscription.

        No Graph task belongs here. A directory read placed in this plan runs
        once per subscription and is the same answer every time, which is both
        the cost and the correctness problem this split exists to fix.
        """
        if not self.subscription_id:
            raise ValueError(
                "An account plan reads one subscription and needs its id"
            )
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

        async def role_assignments(arm: ArmClient) -> dict[str, Any]:
            """Who holds which role over what, inside this subscription.

            The half of "who can do what" that ARM answers. The directory says
            which principals exist; this says what they are allowed to do, and
            a tenant can have a perfectly readable directory alongside no
            visibility into this at all -- the two are different grants.
            """
            return {"role_assignments": await arm.list_role_assignments(sub)}

        async def role_definitions(arm: ArmClient) -> dict[str, Any]:
            """What each role actually permits.

            Collected beside the assignments because an assignment on its own
            names a GUID. "Contributor over this subscription" and "Reader over
            one storage account" are the same shape of row, and only the
            definition tells them apart.
            """
            return {"role_definitions": await arm.list_role_definitions(sub)}

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
                AzureEvidence.NETWORK_SECURITY_GROUPS,
                ("Microsoft.Network/networkSecurityGroups/read",),
                nsgs,
                endpoints=(NSG_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.NETWORK_INTERFACES,
                ("Microsoft.Network/networkInterfaces/read",),
                nics,
                endpoints=(NIC_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.PUBLIC_IP_ADDRESSES,
                ("Microsoft.Network/publicIPAddresses/read",),
                public_ips,
                endpoints=(PUBLIC_IP_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.VIRTUAL_MACHINES,
                ("Microsoft.Compute/virtualMachines/read",),
                vms,
                endpoints=(VM_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.STORAGE_ACCOUNTS,
                ("Microsoft.Storage/storageAccounts/read",),
                storage,
                endpoints=(STORAGE_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.SQL_SERVERS,
                (
                    "Microsoft.Sql/servers/read",
                    "Microsoft.Sql/servers/firewallRules/read",
                ),
                sql,
                endpoints=(SQL_SERVERS_ENDPOINT, SQL_FIREWALL_ENDPOINT),
            ),
            self._arm_task(
                AzureEvidence.POSTGRESQL_SERVERS,
                ("Microsoft.DBforPostgreSQL/flexibleServers/read",),
                postgres,
                endpoints=(POSTGRES_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.ROLE_ASSIGNMENTS,
                ("Microsoft.Authorization/roleAssignments/read",),
                role_assignments,
                endpoints=(ROLE_ASSIGNMENTS_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.ROLE_DEFINITIONS,
                ("Microsoft.Authorization/roleDefinitions/read",),
                role_definitions,
                endpoints=(ROLE_DEFINITIONS_ENDPOINT,),
            ),
            self._inventory_task(),
            self._diagnostics_task(),
        ]
        return tasks

    def build_directory_plan(self) -> list[CollectionTask]:
        """Everything that is a reading of the tenant directory.

        Run once per scan, whatever the scan covers. Needs no subscription:
        Graph is scoped by the token, and the token is issued for the tenant
        the connection was consented in.
        """
        return self._identity_tasks()

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

        # Bound here rather than read off ``self`` inside the closure: this task
        # only ever appears in the account plan, which has already refused to
        # build without a subscription, and capturing it says so to the reader
        # and the type checker at once.
        sub = self.subscription_id
        if not sub:
            raise ValueError("The inventory task reads one subscription")

        async def run(collected: dict[str, Any]) -> TaskData:
            client = ResourceGraphClient(
                self.tokens, self._http, limiter=self._limiter
            )
            rows = await client.list_inventory(sub)
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
            key=AzureEvidence.RESOURCES,
            run=run,
            actions=(
                "Microsoft.Resources/subscriptions/read",
                "Microsoft.Resources/subscriptions/resources/read",
                "Microsoft.ResourceGraph/resources/read",
            ),
            endpoints=(RESOURCE_GRAPH_ENDPOINT,),
        )

    def _diagnostics_task(self) -> CollectionTask:
        """Diagnostic settings for the resources AZ-LOG-001 covers.

        The only task with real dependencies, and the reason the executor sorts
        rather than just running everything at once: it needs the ids that the
        storage, SQL and NSG listings produce. That used to be expressed as
        "call it fifth".
        """
        sources = (
            AzureEvidence.STORAGE_ACCOUNTS,
            AzureEvidence.SQL_SERVERS,
            AzureEvidence.NETWORK_SECURITY_GROUPS,
        )

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
            key=AzureEvidence.DIAGNOSTIC_SETTINGS,
            run=run,
            depends_on=sources,
            actions=("Microsoft.Insights/diagnosticSettings/read",),
            endpoints=(DIAGNOSTICS_ENDPOINT,),
        )

    def _name_missing_permissions(self) -> str:
        """Which directory permissions this tenant's consent did not grant.

        Empty when the answer cannot be established. Graph answers a missing
        application permission with "Insufficient privileges to complete the
        operation", which names neither the permission nor who can grant it,
        and the collector's own hint could only ever guess at which of nine it
        was. The token knows: a client-credentials token lists its granted
        permissions in the ``roles`` claim, so the failure can be reported as a
        list an administrator can act on rather than as a category that went
        UNKNOWN for reasons.
        """
        from app.connectors.azure.auth import missing_permissions

        try:
            absent = missing_permissions(self.tokens.graph_token())
        except Exception:
            # A token that cannot be read or fetched says nothing about the
            # grant, and inventing nine gaps would send someone to fix a
            # directory that is configured correctly.
            return ""
        if not absent:
            return ""
        return f" Consent in this tenant did not grant: {', '.join(absent)}."

    async def _graph_call(self, call: Awaitable[Any]) -> Any:
        """Await a Graph call, naming the missing permissions behind a 403."""
        try:
            return await call
        except AzureApiError as exc:
            if exc.azure_status_code != 403:
                raise
            named = self._name_missing_permissions()
            if not named:
                raise
            raise AzureApiError(f"{exc}{named}", status_code=403) from exc

    def _identity_tasks(self) -> list[CollectionTask]:
        """Directory state. Graph, so no ARM action grants any of it."""

        async def users(collected: dict[str, Any]) -> TaskData:
            graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
            found = await self._graph_call(graph.list_users())
            if graph.truncated:
                return TaskData(
                    {"users": found},
                    partial_reason="the directory is larger than one scan reads",
                )
            return TaskData({"users": found})

        async def roles(collected: dict[str, Any]) -> TaskData:
            graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
            found = await self._graph_call(graph.list_directory_roles())
            return TaskData({"directory_roles": found})

        async def security_defaults(collected: dict[str, Any]) -> TaskData:
            graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
            policy = await self._graph_call(graph.get_security_defaults())
            return TaskData({"security_defaults": policy})

        async def conditional_access(collected: dict[str, Any]) -> TaskData:
            graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
            found = await self._graph_call(graph.list_conditional_access_policies())

            # The groups those policies name, and only those. A policy that
            # excludes a break-glass group -- which is how essentially every
            # real tenant is configured -- cannot be reasoned about without
            # knowing who is in it: CloudGuard would be unable to rule out that
            # the account it is judging is the excluded one, and would have to
            # discard the policy. Reading every group in the tenant to answer
            # that would be a directory dump for a handful of ids.
            wanted: set[str] = set()
            for policy in found:
                users = (policy.get("conditions") or {}).get("users") or {}
                for key in ("includeGroups", "excludeGroups"):
                    wanted.update(str(g) for g in (users.get(key) or []) if g)

            async def members_of(group_id: str) -> tuple[str, list[str] | None]:
                try:
                    people = await graph.list_group_members(group_id)
                except Exception as exc:
                    # None, not [], and the normalizer drops any policy whose
                    # exclusions it could not read. An empty list would read as
                    # "nobody is excluded", which is the one wrong answer here.
                    log.warning("azure.group_members_failed", error=str(exc))
                    return group_id, None
                return group_id, [str(m["id"]) for m in people if m.get("id")]

            pairs = await self._gather_limited([members_of(g) for g in sorted(wanted)])
            data = {
                "conditional_access_policies": found,
                "group_members": {g: m for g, m in pairs if m is not None},
            }
            if graph.truncated:
                return TaskData(
                    data,
                    partial_reason=(
                        "there are more Conditional Access policies than one scan "
                        "reads, so a policy that would lower a finding's score may "
                        "be missing from this list"
                    ),
                )
            return TaskData(data)

        return [
            CollectionTask(
                key=AzureEvidence.USERS,
                run=users,
                endpoints=(USERS_ENDPOINT,),
            ),
            CollectionTask(
                key=AzureEvidence.DIRECTORY_ROLES,
                run=roles,
                endpoints=(DIRECTORY_ROLES_ENDPOINT,),
            ),
            CollectionTask(
                key=AzureEvidence.USER_ROLE_MAP,
                run=self._role_membership,
                depends_on=(AzureEvidence.USERS, AzureEvidence.DIRECTORY_ROLES),
                # Two calls per user it judges: who holds each role, and what
                # each of those accounts can authenticate with.
                endpoints=(ROLE_MEMBERS_ENDPOINT, AUTH_METHODS_ENDPOINT),
            ),
            # The two defences. Independent tasks rather than one, because they
            # are separate readings that fail separately -- and because a tenant
            # on security defaults has no Conditional Access at all, so one
            # returning nothing must not cost the other its verdict.
            CollectionTask(
                key=AzureEvidence.SECURITY_DEFAULTS,
                run=security_defaults,
                endpoints=(SECURITY_DEFAULTS_ENDPOINT,),
            ),
            CollectionTask(
                key=AzureEvidence.CONDITIONAL_ACCESS_POLICIES,
                run=conditional_access,
                endpoints=(CONDITIONAL_ACCESS_ENDPOINT, GROUP_MEMBERS_ENDPOINT),
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
