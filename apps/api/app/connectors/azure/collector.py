"""Collection: Azure APIs -> raw snapshot.

Collection never evaluates anything. It gathers, records what it could not
gather, and hands both to the normalizer. That separation is what makes a scan
reproducible and a coverage gap explainable.

What to gather now lives in ``plan.py`` as declared tasks, and
:class:`~app.connectors.collection.CollectionRun` runs them. This module is the
seam between the two: it owns the connection pool, turns the run's coverage
report into the ``errors`` the rule engine already understands, and hands both
to the normalizer.

Every task is isolated. A Storage API timeout records
``errors["storage"] = "..."`` and collection continues; the rules that depend on
storage data then return UNKNOWN rather than evaluating against nothing
(AZURE_INTEGRATION.md section 5). A listing that stopped early is recorded the
same way, which is newer and matters more: a truncated list is not a short list,
it is an unknown one.
"""

from collections.abc import Awaitable, Callable

import httpx

from app.connectors.azure.auth import TokenProvider
from app.connectors.azure.client import DEFAULT_TIMEOUT, RequestLimiter
from app.connectors.azure.plan import AzurePlanBuilder
from app.connectors.base import RawSnapshot
from app.connectors.collection import CollectionRun, CollectionTask
from app.core.enums import CollectionScope, Provider
from app.core.logging import get_logger

log = get_logger(__name__)

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
        subscription_id: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.subscription_id = subscription_id
        self.tokens = TokenProvider(tenant_id)
        self._http = http_client

    async def collect(
        self, on_progress: Callable[[int, int], Awaitable[None]] | None = None
    ) -> RawSnapshot:
        """Build the account plan, run it, and record what it managed to see.

        The sequence of ``_collect_category`` calls this replaced encoded three
        things it could not express: that NSGs and public IPs are independent,
        that diagnostic settings are not, and that a listing which stopped early
        is not a listing. ``plan.py`` declares all three and
        :class:`CollectionRun` acts on them.
        """
        if not self.subscription_id:
            raise ValueError("A subscription id is required to collect Azure state")
        return await self._run(
            RawSnapshot(
                provider=Provider.AZURE,
                tenant_id=self.tenant_id,
                subscription_id=self.subscription_id,
                scope=CollectionScope.ACCOUNT,
            ),
            lambda builder: builder.build_account_plan(),
            on_progress,
        )

    async def collect_directory(
        self, on_progress: Callable[[int, int], Awaitable[None]] | None = None
    ) -> RawSnapshot:
        """Read the tenant directory, once for the whole scan.

        Carries no subscription id, because there is no subscription in the
        answer: Graph is scoped by the token, and the token belongs to the
        tenant the connection was consented in.
        """
        return await self._run(
            RawSnapshot(
                provider=Provider.AZURE,
                tenant_id=self.tenant_id,
                subscription_id=None,
                scope=CollectionScope.DIRECTORY,
            ),
            lambda builder: builder.build_directory_plan(),
            on_progress,
        )

    async def _run(
        self,
        snapshot: RawSnapshot,
        select_plan: Callable[[AzurePlanBuilder], list[CollectionTask]],
        on_progress: Callable[[int, int], Awaitable[None]] | None,
    ) -> RawSnapshot:
        """Execute one plan into one snapshot.

        Shared by both scopes deliberately. Coverage, degradation and the
        request ceiling are properties of *a collection run*, not of what it
        happened to be reading, and letting the two scopes each grow their own
        copy is how one of them ends up quietly not recording a gap.
        """
        # One connection pool for the whole run; each task wraps it in its own
        # client so truncation stays attributable. One request limiter too, and
        # for the opposite reason: what must not be per task is how many
        # requests are outstanding, because Azure meters the subscription, not
        # the task that happened to ask.
        owns_http = self._http is None
        http = self._http or httpx.AsyncClient(timeout=DEFAULT_TIMEOUT)
        limiter = RequestLimiter()
        try:
            builder = AzurePlanBuilder(
                self.tokens, self.subscription_id, http, limiter=limiter
            )
            run = CollectionRun(select_plan(builder), on_progress=on_progress)
            report = await run.execute(snapshot.data)
        finally:
            if owns_http:
                await http.aclose()

        snapshot.coverage = report.to_json()
        # Held for the pipeline to store as evidence, then dropped: they are
        # the same objects already inside ``data``, sliced by what produced
        # them.
        snapshot.payloads = report.payloads
        # Both views derived from the one report, never assigned separately.
        # ``gaps`` is what the rules degrade on, key by key; ``errors`` is the
        # category summary the scan banner and the role-drift explanation read.
        # PARTIAL lands in both alongside FAILED deliberately: a truncated
        # listing costs a verdict exactly as an unreachable API does, and no
        # rule has to learn that truncation exists.
        snapshot.gaps.update(report.key_problems())
        snapshot.errors.update(report.category_problems())

        log.info(
            "azure.collection_finished",
            tenant_id=self.tenant_id,
            subscription_id=self.subscription_id,
            scope=snapshot.scope.value,
            tasks=run.size,
            complete=report.is_complete,
            degraded=sorted(snapshot.errors),
            # What the run cost in requests, and how long it spent queued
            # behind its own ceiling. A scan that never waits and one that
            # waits a minute are indistinguishable without this, and only the
            # second is evidence the limit wants changing.
            **limiter.stats(),
        )
        return snapshot
