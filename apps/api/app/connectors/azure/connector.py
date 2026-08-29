"""The Azure connector: validate, collect, normalize."""

from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from app.connectors.azure.auth import (
    REQUIRED_GRAPH_PERMISSIONS,
    TokenProvider,
    missing_permissions,
)
from app.connectors.azure.client import ArmClient, GraphClient, ResourceGraphClient
from app.connectors.azure.collector import AzureCollector
from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.base import CloudConnector, ConnectionCheck, NormalizedState, RawSnapshot
from app.core.enums import Provider
from app.core.logging import get_logger

log = get_logger(__name__)


# The Graph calls collection depends on, each paired with the permission that
# grants it. Verifying by calling is the only verification available: Graph
# exposes no "what am I consented to" endpoint, and a consent screen that was
# clicked is not evidence that the grant covers what CloudGuard needs today.
#
# These are exactly the two calls ``_collect_identity`` makes before anything
# else, plus the tenant read that proves consent happened at all. The deeper
# identity calls are absent on purpose -- they already degrade to UNKNOWN
# individually, so they cost a category rather than a connection.
# The call is the function itself, not its name. Looking it up with getattr
# inside the same try that catches a 403 would turn a rename into a permission
# diagnosis: every customer told to change their Entra configuration to fix a
# typo in ours. Referencing the method here fails at import instead.
GRAPH_PROBES: tuple[tuple[Callable[[GraphClient], Awaitable[Any]], str, str], ...] = (
    (GraphClient.get_organization, "the tenant directory", "Directory.Read.All"),
    (GraphClient.list_users, "directory users", "User.Read.All or Directory.Read.All"),
    (
        GraphClient.list_directory_roles,
        "directory roles",
        "RoleManagement.Read.Directory or Directory.Read.All",
    ),
)


class AzureConnector(CloudConnector):
    provider = Provider.AZURE

    def __init__(
        self,
        tenant_id: str,
        subscription_id: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.subscription_id = subscription_id
        self._http = http_client
        self._normalizer = AzureNormalizer()

    async def validate_connection(self) -> ConnectionCheck:
        """Verify both grants by using them, not by asking whether they exist.

        Graph consent and the RBAC Reader assignment are independent, and a
        customer very often completes the first and forgets the second. The two
        are therefore checked separately so the UI can say which one is missing
        (AZURE_INTEGRATION.md section 2).
        """
        check = ConnectionCheck(ok=False, tenant_id=self.tenant_id)

        try:
            tokens = TokenProvider(self.tenant_id)
        except Exception as exc:
            check.problems.append(f"Could not authenticate to tenant {self.tenant_id}: {exc}")
            check.detail = "Authentication failed"
            return check

        # --- Graph: did admin consent cover what the collector needs? -------
        # One call per probe, because one call is what a permission grants.
        # Reading /organization and then declaring Directory.Read.All verified
        # was the old shape, and it claimed far more than it had shown: that
        # endpoint answers with much less, so a connection could validate green
        # and then lose the whole identity category to a 403 on the first scan.
        # Asked of the token before anything is called. Its ``roles`` claim is
        # the tenant's actual consent, so a missing grant can be named -- nine
        # permissions, this is which ones -- instead of being inferred from
        # whichever endpoint happened to 403 first.
        try:
            absent = missing_permissions(tokens.graph_token())
        except Exception:
            absent = ()
        if absent:
            check.problems.append(
                f"Admin consent in this tenant did not grant {len(absent)} of the "
                f"{len(REQUIRED_GRAPH_PERMISSIONS)} directory permissions CloudGuard "
                f"needs: {', '.join(absent)}. Add them to the CloudGuard app "
                "registration as application permissions, then re-run admin consent "
                "-- consent covers only what the registration declared at the moment "
                "it was granted."
            )

        async with GraphClient(tokens, self._http) as graph:
            for probe, subject, permission in GRAPH_PROBES:
                try:
                    await probe(graph)
                except Exception as exc:
                    check.problems.append(
                        f"CloudGuard cannot read {subject}. Grant {permission} as an "
                        "application permission on the app registration, then re-run "
                        "admin consent for this tenant. Consent covers the permissions "
                        "configured at the moment it is granted, so a permission added "
                        f"afterwards needs consenting again. ({exc})"
                    )
                else:
                    check.permissions_verified.append(f"Microsoft Graph: {subject}")

        # --- ARM: was the Reader role assigned? -----------------------------
        async with ArmClient(tokens, self._http) as arm:
            try:
                subscriptions = await arm.list_subscriptions()
                visible = [
                    str(s["subscriptionId"])
                    for s in subscriptions
                    if s.get("subscriptionId")
                ]

                if not subscriptions:
                    check.problems.append(
                        "No subscriptions are visible. Assign the Reader role to CloudGuard "
                        "on the subscription you want to scan."
                    )
                elif self.subscription_id and self.subscription_id not in visible:
                    check.problems.append(
                        f"Subscription {self.subscription_id} is not visible to CloudGuard. "
                        "Check that the Reader role is assigned on that subscription."
                    )
                else:
                    chosen = self.subscription_id or visible[0]
                    check.subscription_id = chosen
                    check.permissions_verified.append(f"Azure RBAC Reader on {chosen}")

                    # Reading a resource list proves the role works, not just
                    # that the subscription is listed.
                    await arm.list_resources(chosen)
                    check.permissions_verified.append("Resource listing readable")
            except Exception as exc:
                check.problems.append(f"Azure Resource Manager is not readable: {exc}")

        # --- Resource Graph: can inventory be queried? ----------------------
        # A note rather than a problem, and the asymmetry is the doctrine of
        # this method rather than leniency: a probe belongs here when its
        # failure costs the connection, and this one costs a category. Every
        # rule keeps evaluating without it -- inventory is the one collection
        # task nothing judges -- so failing the connection over it would send a
        # customer to fix an outage they do not have.
        #
        # Worth probing all the same, because the cause is specific and
        # actionable: a role deployed before Resource Graph inventory shipped
        # does not grant the query, and without this the customer meets that as
        # a degraded category several minutes into their first scan.
        if check.subscription_id:
            async with ResourceGraphClient(tokens, self._http) as resource_graph:
                try:
                    await resource_graph.probe_inventory(check.subscription_id)
                except Exception as exc:
                    check.notes.append(
                        "Resource inventory cannot be collected: CloudGuard's "
                        "scanner role on this scope does not allow Azure Resource "
                        "Graph queries. Redeploy the role from the connection page "
                        "-- a role deployed before inventory moved to Resource "
                        "Graph will not have it. Every other check still runs. "
                        f"({exc})"
                    )
                else:
                    check.permissions_verified.append(
                        "Azure Resource Graph inventory queryable"
                    )

        check.ok = not check.problems
        check.detail = (
            "Read-only access verified"
            if check.ok
            else "; ".join(check.problems)
        )
        return check

    async def collect(
        self, on_progress: Callable[[int, int], Awaitable[None]] | None = None
    ) -> RawSnapshot:
        if not self.subscription_id:
            raise ValueError("A subscription id is required to collect Azure state")
        collector = AzureCollector(
            tenant_id=self.tenant_id,
            subscription_id=self.subscription_id,
            http_client=self._http,
        )
        return await collector.collect(on_progress)

    def normalize(self, snapshot: RawSnapshot) -> NormalizedState:
        return self._normalizer.normalize(snapshot)

    @staticmethod
    def required_permissions() -> dict[str, Any]:
        """What CloudGuard asks for, in the form the onboarding UI shows it.

        Presented to the customer before they consent, because "what does this
        thing get to see" is the first question anyone sensible asks
        (SECURITY.md section 5).
        """
        return {
            "graph_application_permissions": REQUIRED_GRAPH_PERMISSIONS,
            "azure_rbac_role": "Reader",
            "access_type": "read-only",
            "writes_performed": "none",
        }
