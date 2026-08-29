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
from app.connectors.azure.client import DEFAULT_TIMEOUT
from app.connectors.azure.plan import AzurePlanBuilder
from app.connectors.base import RawSnapshot
from app.connectors.collection import CollectionRun
from app.core.enums import Provider
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
        subscription_id: str,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.subscription_id = subscription_id
        self.tokens = TokenProvider(tenant_id)
        self._http = http_client

    async def collect(
        self, on_progress: Callable[[int, int], Awaitable[None]] | None = None
    ) -> RawSnapshot:
        """Build the plan, run it, and record what it managed to see.

        The sequence of ``_collect_category`` calls this replaced encoded three
        things it could not express: that NSGs and public IPs are independent,
        that diagnostic settings are not, and that a listing which stopped early
        is not a listing. ``plan.py`` declares all three and
        :class:`CollectionRun` acts on them.
        """
        snapshot = RawSnapshot(
            provider=Provider.AZURE,
            tenant_id=self.tenant_id,
            subscription_id=self.subscription_id,
        )

        # One connection pool for the whole run; each task wraps it in its own
        # client so truncation stays attributable.
        owns_http = self._http is None
        http = self._http or httpx.AsyncClient(timeout=DEFAULT_TIMEOUT)
        try:
            plan = AzurePlanBuilder(self.tokens, self.subscription_id, http).build()
            run = CollectionRun(plan, on_progress=on_progress)
            report = await run.execute(snapshot.data)
        finally:
            if owns_http:
                await http.aclose()

        snapshot.coverage = report.to_json()
        # Derived, not assigned alongside: every untrustworthy task lands in
        # ``errors`` under its category, so PARTIAL degrades rules through the
        # same ``requires_collection`` path a failure always has. No rule needs
        # to learn that truncation exists.
        snapshot.errors.update(report.category_problems())

        log.info(
            "azure.collection_finished",
            tenant_id=self.tenant_id,
            subscription_id=self.subscription_id,
            tasks=run.size,
            complete=report.is_complete,
            degraded=sorted(snapshot.errors),
        )
        return snapshot
