"""Collection: AWS APIs -> raw snapshot.

The same seam Azure's collector occupies, and deliberately the same shape: it
owns the assumed session, runs the plan, and turns the coverage report into the
two views the pipeline already understands -- ``gaps`` for the rules, keyed one
evidence key at a time, and ``errors`` for the customer, keyed by permission
category.

Collection never evaluates anything. It gathers, records what it could not
gather, and hands both to the normalizer.

One difference from Azure, and it is the region dimension: a wave here holds one
listing per region, so the run is given a concurrency ceiling. AWS throttles per
region per service, and a wave that opened seventeen regions at once would be
shaped to be throttled.
"""

from collections.abc import Awaitable, Callable

from aiobotocore.session import AioSession

from app.connectors.aws.auth import RoleAssumer
from app.connectors.aws.plan import MAX_CONCURRENT_TASKS, AwsPlanBuilder
from app.connectors.base import RawSnapshot
from app.connectors.collection import CollectionRun, CollectionTask
from app.connectors.planning import CollectionPlan
from app.core.enums import CollectionScope, Provider
from app.core.logging import get_logger

log = get_logger(__name__)


class AwsCollector:
    def __init__(
        self,
        organization_id: str,
        account_id: str | None = None,
        *,
        role_arn: str = "",
        external_id: str = "",
        session: AioSession | None = None,
    ) -> None:
        # The trust boundary, in the column Azure's tenant id occupies. An AWS
        # organization id, or the account's own id where the customer connected
        # a standalone account -- a boundary of one.
        self.organization_id = organization_id
        self.account_id = account_id
        self.assumer = RoleAssumer(role_arn, external_id, session=session)
        self.session = session

    async def collect(
        self,
        on_progress: Callable[[int, int], Awaitable[None]] | None = None,
        plan: CollectionPlan | None = None,
    ) -> RawSnapshot:
        if not self.account_id:
            raise ValueError("An account id is required to collect AWS state")
        builder = AwsPlanBuilder(
            self.assumer, self.account_id, session=self.session
        )
        return await self._run(
            RawSnapshot(
                provider=Provider.AWS,
                tenant_id=self.organization_id,
                subscription_id=self.account_id,
                scope=CollectionScope.ACCOUNT,
            ),
            await builder.build_account_plan(),
            on_progress,
            plan,
        )

    async def collect_directory(
        self,
        on_progress: Callable[[int, int], Awaitable[None]] | None = None,
        plan: CollectionPlan | None = None,
    ) -> RawSnapshot:
        """The organization, read once for the whole scan.

        Carries no account id, because there is no account in the answer: the
        organization's account list belongs to the boundary, not to any account
        beneath it.
        """
        builder = AwsPlanBuilder(self.assumer, None, session=self.session)
        return await self._run(
            RawSnapshot(
                provider=Provider.AWS,
                tenant_id=self.organization_id,
                subscription_id=None,
                scope=CollectionScope.DIRECTORY,
            ),
            builder.build_directory_plan(),
            on_progress,
            plan,
        )

    async def _run(
        self,
        snapshot: RawSnapshot,
        tasks: list[CollectionTask],
        on_progress: Callable[[int, int], Awaitable[None]] | None,
        plan: CollectionPlan | None,
    ) -> RawSnapshot:
        """Execute one plan into one snapshot.

        Shared by both scopes for the same reason Azure's is: coverage and
        degradation are properties of *a collection run* rather than of what it
        happened to be reading, and letting the two scopes each grow their own
        copy is how one of them ends up quietly not recording a gap.
        """
        run = CollectionRun(
            tasks,
            on_progress=on_progress,
            plan=plan,
            max_concurrency=MAX_CONCURRENT_TASKS,
        )
        report = await run.execute(snapshot.data)

        snapshot.coverage = report.to_json()
        # Held for the pipeline to store as evidence, then dropped: the same
        # objects already inside ``data``, sliced by what produced them.
        snapshot.payloads = report.payloads
        # Both views derived from the one report, never assigned separately.
        # ``gaps`` is what the rules degrade on -- one entry per evidence key,
        # with the failing regions named inside the reason. ``errors`` is the
        # category summary the scan banner reads.
        snapshot.gaps.update(report.key_problems())
        snapshot.errors.update(report.category_problems())

        log.info(
            "aws.collection_finished",
            organization_id=self.organization_id,
            account_id=self.account_id,
            scope=snapshot.scope.value,
            tasks=run.size,
            # How wide the fan-out actually was. A scan of one region and a scan
            # of seventeen are not the same scan, and without this the log says
            # they are.
            regions=len({t.region for t in run.tasks if t.region}),
            carried=sorted(run.carried),
            complete=report.is_complete,
            degraded=sorted(snapshot.errors),
        )
        return snapshot
