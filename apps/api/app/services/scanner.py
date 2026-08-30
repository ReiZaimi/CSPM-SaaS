"""The scan pipeline.

    collect -> snapshot -> normalize -> persist assets -> evaluate
            -> findings -> risks -> verify fixes -> summarize

Two things here are the product, not plumbing:

* **Every scan writes a snapshot** before anything is interpreted, so a scan can
  be re-evaluated later against improved rules. :meth:`ScanPipeline.replay`
  is that promise being kept: it re-enters the pipeline at ``normalize`` with a
  stored capture and runs the identical remaining stages, so a rule written
  today can be applied to state collected months ago without asking the
  customer for anything.
* **A rescan verifies remediation by itself.** Where a previous scan produced
  FAIL and this one produces PASS, the finding is resolved automatically and
  stamped with the scan that proved it. Nobody clicks "verified"
  (RULE_ENGINE.md section 3).

The two combine into the one rule that constrains replay: **only the newest
snapshot for an account may write findings.** Verification means an observation
was made, and replaying an old capture makes none.

Runs in the Celery worker, which has no authenticated user, so it uses the
owner connection and scopes every write by the ``organization_id`` taken from
the scan record it was handed — never from client input.
"""

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import and_, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from app.connectors.base import NormalizedState, RawSnapshot
from app.connectors.registry import get_connector
from app.core.db import service_session
from app.core.enums import (
    FindingStatus,
    Level,
    RelationshipType,
    RiskStatus,
    ScanStatus,
    Severity,
    TaskOutcome,
)
from app.core.logging import get_logger
from app.domain.resource import CloudResource
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.models.finding import Finding
from app.models.resource import ResourceRecord, ResourceRelationship
from app.models.risk import Risk, RiskFinding
from app.models.scan import (
    CloudSnapshot,
    Scan,
    ScanCollectionResult,
    ScanEvaluationGap,
    ScanRuleResult,
)
from app.risk.scorer import RiskInputs, ScoredRisk, default_scorer
from app.rules.base import RuleContext, SecurityRule
from app.rules.engine import EvaluationReport, RuleEngine
from app.services.cloud_connections import degraded_categories

log = get_logger(__name__)


class _ScanProgress:
    """How far along collection is, across every phase of one scan.

    Two things it does that the closure it replaced could not.

    It writes through its **own** session. The old reporter committed on the
    pipeline's session, mid-pipeline: a commit there is not merely a wasted
    round trip, it ends the transaction the pipeline is still building work in.
    A short UPDATE of two columns on a separate connection says the same thing
    and touches nothing else.

    And it accumulates across phases rather than assuming they are identical.
    Progress used to be ``index * plan_size + done``, which reads every phase as
    the same size as the one currently reporting -- true while every phase was
    one subscription running one fixed plan, and false the moment a
    tenant-scoped directory phase runs a plan of its own. The total grows as
    phases announce their size, so it can be short early but is never wrong
    about what has finished.
    """

    def __init__(self, scan_id: UUID, account_count: int) -> None:
        self.scan_id = scan_id
        self.account_count = account_count
        self._finished = 0  # units completed in phases that have ended
        self._directory_size = 0
        self._account_size = 0

    def directory_reporter(self) -> Callable[[int, int], Awaitable[None]]:
        return self._reporter(is_directory=True)

    def account_reporter(self) -> Callable[[int, int], Awaitable[None]]:
        return self._reporter(is_directory=False)

    def _reporter(self, *, is_directory: bool) -> Callable[[int, int], Awaitable[None]]:
        # Captured when the phase starts, so the next phase resumes from where
        # this one left off instead of restarting the count at each
        # subscription. The executor's last callback carries done == plan_size,
        # which is what leaves ``_finished`` at the phase's full size.
        base = self._finished

        async def report(done: int, plan_size: int) -> None:
            if is_directory:
                self._directory_size = plan_size
            else:
                self._account_size = plan_size
            self._finished = base + done
            await self._write(self._finished, self._total())

        return report

    def _total(self) -> int:
        return self._directory_size + self.account_count * self._account_size

    async def _write(self, done: int, total: int) -> None:
        try:
            async with service_session() as progress_session:
                await progress_session.execute(
                    update(Scan)
                    .where(Scan.id == self.scan_id)
                    .values(progress_done=done, progress_total=total)
                )
                await progress_session.commit()
        except Exception as exc:  # pragma: no cover - progress is never fatal
            # A scan must not fail because a cosmetic counter could not be
            # written. The bar stops moving; the scan keeps going.
            log.warning("scan.progress_write_failed", scan_id=str(self.scan_id), error=str(exc))


class ScanPipeline:
    def __init__(self, scan_id: UUID) -> None:
        self.scan_id = scan_id
        self.engine = RuleEngine()

    async def run(self) -> None:
        """Collect the customer's current state, then evaluate it.

        A scan covers whatever its scope resolves to: every in-scope
        subscription under a connection, or the single subscription a targeted
        rescan names. Each subscription is collected and stored separately --
        the snapshot has to stay what Azure said -- and all of them are
        evaluated together, so a rule sees the tenant rather than one slice of
        it.
        """
        async with service_session() as session:
            scan = await session.get(Scan, self.scan_id)
            if scan is None:
                log.error("scan.missing", scan_id=str(self.scan_id))
                return

            accounts = await self._resolve_scope(session, scan)
            if not accounts:
                await self._fail(
                    session,
                    scan,
                    "This scan has nothing in scope. Its subscriptions may have "
                    "been removed, excluded from scanning, or never discovered.",
                )
                return

            # Cancelled between being queued and being picked up. The worker
            # may sit behind a backlog for minutes, which is exactly the window
            # someone uses the cancel button in -- starting anyway would ignore
            # them and write findings they asked not to collect.
            if scan.status == ScanStatus.CANCELLED:
                log.info("scan.cancelled_before_start", scan_id=str(self.scan_id))
                return

            scan.started_at = datetime.now(UTC)
            org_id = scan.organization_id  # authoritative; never from a request

            try:
                # --- collect ------------------------------------------------
                await self._set_status(session, scan, ScanStatus.DISCOVERING)
                observed_at = datetime.now(UTC)
                merged = NormalizedState()
                account_state: list[tuple[CloudAccount, NormalizedState]] = []
                errors: dict[str, str] = {}
                connection = await self._resolve_connection(session, scan, accounts)
                progress = _ScanProgress(scan.id, len(accounts))

                # --- the tenant, once ---------------------------------------
                # Before any subscription, and exactly once however many there
                # are. The directory is the same directory from every one of
                # them; reading it per subscription produced a duplicate set of
                # user assets each time, and with them a duplicate finding per
                # subscription for every administrator missing MFA.
                directory = await self._collect_directory(
                    session, scan, connection, progress
                )
                if directory is not None:
                    directory_state, directory_snapshot = directory
                    # Unqualified, unlike a subscription's. A directory failure
                    # happened once, to the tenant, and naming a subscription
                    # beside it would invite someone to go and look at one.
                    errors.update(directory_snapshot.errors)
                    merged.resources.extend(directory_state.resources)
                    merged.relationships.extend(directory_state.relationships)
                elif connection is not None:
                    errors["identity"] = (
                        "The directory could not be read for this scan, so no "
                        "identity check could reach a verdict."
                    )
                else:
                    # A subscription with no connection behind it predates
                    # connections entirely. There is no tenant-level grant to
                    # read the directory through, and saying so is the only
                    # honest answer -- the identity rules degrade to UNKNOWN
                    # rather than passing over a directory nobody looked at.
                    errors["identity"] = (
                        "This subscription is not attached to a cloud connection, "
                        "so CloudGuard has no grant to read its tenant directory. "
                        "Reconnect it from the connections page."
                    )

                # --- each subscription --------------------------------------
                for account in accounts:
                    connector = get_connector(
                        account.provider,
                        tenant_id=account.tenant_id,
                        subscription_id=account.subscription_id,
                    )
                    snapshot = await connector.collect(progress.account_reporter())
                    await self._explain_role_drift(session, account, snapshot)

                    # Persisted before interpretation, always. One row per
                    # subscription, so a tenant-wide scan can still be replayed
                    # subscription by subscription.
                    session.add(
                        CloudSnapshot(
                            organization_id=org_id,
                            cloud_account_id=account.id,
                            connection_id=account.connection_id,
                            scan_id=scan.id,
                            snapshot_version=snapshot.version,
                            data=snapshot.to_json(),
                        )
                    )
                    # Namespaced by subscription: two subscriptions can both
                    # fail to read storage, and "storage: timeout" twice over
                    # tells a customer nothing about which one to look at.
                    for category, reason in snapshot.errors.items():
                        errors[self._scoped_key(account, category, len(accounts))] = reason

                    self._record_collection_status(
                        session, org_id, scan, snapshot, account=account
                    )

                    state = connector.normalize(snapshot)
                    account_state.append((account, state))
                    merged.resources.extend(state.resources)
                    merged.relationships.extend(state.relationships)

                scan.collection_errors = errors
                # The rule engine keys degradation on the bare category, so it
                # gets the unqualified names; the scan row keeps the detail.
                merged.collection_errors = {
                    category: reason
                    for _account, state in account_state
                    for category, reason in state.collection_errors.items()
                }
                if directory is not None:
                    merged.collection_errors.update(directory[0].collection_errors)
                elif "identity" in errors:
                    merged.collection_errors["identity"] = errors["identity"]
                await session.commit()

                await self._evaluate(
                    session,
                    scan,
                    account_state,
                    merged,
                    observed_at=observed_at,
                    mutate_findings=True,
                    degraded=bool(errors),
                    directory=(
                        (connection, directory[0])
                        if directory is not None and connection is not None
                        else None
                    ),
                )

                for account in accounts:
                    account.last_scan_at = scan.completed_at
                await session.commit()

            except Exception as exc:
                log.exception("scan.failed", scan_id=str(scan.id))
                await session.rollback()
                await self._fail(session, scan, str(exc))

    async def _collect_directory(
        self,
        session: AsyncSession,
        scan: Scan,
        connection: CloudConnection | None,
        progress: "_ScanProgress",
    ) -> tuple[NormalizedState, RawSnapshot] | None:
        """Read the tenant directory once, and store it as its own capture.

        Returns ``None`` when there is nothing to read it through, or when the
        read failed outright. Both cases end as a recorded gap rather than as a
        failed scan: a directory CloudGuard could not reach costs the identity
        rules their verdict and costs the subscription rules nothing.

        The capture is stored with a NULL ``cloud_account_id`` because it is not
        a reading of any subscription. That is also what makes it replayable on
        its own terms -- a replay reconstructs the tenant from this row and the
        subscriptions from theirs, exactly as the original scan saw them.
        """
        if connection is None or not connection.tenant_id:
            return None

        connector = get_connector(
            connection.provider,
            tenant_id=connection.tenant_id,
            subscription_id=None,
        )
        try:
            snapshot = await connector.collect_directory(progress.directory_reporter())
        except Exception as exc:
            # Never fatal. The same position collection takes on a single
            # failing ARM category, applied one level up: the directory is one
            # source among several, and losing it must cost the checks that
            # needed it and nothing else.
            log.warning(
                "scan.directory_collection_failed",
                scan_id=str(scan.id),
                connection_id=str(connection.id),
                error=str(exc),
            )
            return None

        session.add(
            CloudSnapshot(
                organization_id=scan.organization_id,
                cloud_account_id=None,
                connection_id=connection.id,
                scan_id=scan.id,
                snapshot_version=snapshot.version,
                data=snapshot.to_json(),
            )
        )
        self._record_collection_status(
            session, scan.organization_id, scan, snapshot, connection=connection
        )
        return connector.normalize(snapshot), snapshot

    async def _resolve_connection(
        self, session: AsyncSession, scan: Scan, accounts: list[CloudAccount]
    ) -> CloudConnection | None:
        """The connection this scan reads through.

        Named on the scan for a tenant-wide run and reachable through the
        account for a single-subscription one. Both forms cover subscriptions
        beneath a single grant, so there is at most one connection either way --
        which is what makes "read the directory once" well defined.
        """
        if scan.connection_id is not None:
            return await session.get(CloudConnection, scan.connection_id)
        for account in accounts:
            if account.connection_id is not None:
                return await session.get(CloudConnection, account.connection_id)
        return None

    def _record_collection_status(
        self,
        session: AsyncSession,
        org_id: UUID,
        scan: Scan,
        snapshot: RawSnapshot,
        *,
        account: CloudAccount | None = None,
        connection: CloudConnection | None = None,
    ) -> None:
        """Turn the run's coverage report into rows that can be queried.

        The same facts already travel inside the snapshot, which is the right
        home for them -- a replay has to see exactly what the original run saw.
        But a fact buried in a JSONB payload can answer questions about one
        scan and no questions at all about a fleet, and "has storage been
        truncating in this subscription all week?" is the one that matters when
        deciding whether a customer has an outage or simply a large tenant.
        """
        connection_id = (
            connection.id if connection is not None else
            account.connection_id if account is not None else None
        )
        for key, entry in snapshot.coverage.items():
            session.add(
                ScanCollectionResult(
                    organization_id=org_id,
                    scan_id=scan.id,
                    cloud_account_id=account.id if account is not None else None,
                    connection_id=connection_id,
                    task_key=key,
                    category=entry.get("category", ""),
                    outcome=TaskOutcome(entry.get("outcome", TaskOutcome.FAILED.value)),
                    detail=entry.get("detail") or None,
                    item_count=int(entry.get("item_count", 0)),
                )
            )

    # ------------------------------------------------------------------ scope
    async def _resolve_scope(
        self, session: AsyncSession, scan: Scan
    ) -> list[CloudAccount]:
        """Which subscriptions this scan covers.

        A connection-scoped scan resolves at execution time rather than at
        creation: a subscription discovered or excluded between queueing and
        running should be picked up or left out accordingly, and a queue that
        can sit for minutes makes that a real difference rather than a
        theoretical one.
        """
        if scan.connection_id is not None:
            rows = (
                (
                    await session.execute(
                        select(CloudAccount)
                        .where(
                            CloudAccount.organization_id == scan.organization_id,
                            CloudAccount.connection_id == scan.connection_id,
                        )
                        .order_by(CloudAccount.display_name)
                    )
                )
                .scalars()
                .all()
            )
            return [a for a in rows if a.is_scannable]

        if scan.cloud_account_id is None:
            return []
        account = await session.get(CloudAccount, scan.cloud_account_id)
        return [account] if account is not None else []

    def _scoped_key(
        self, account: CloudAccount, category: str, account_count: int
    ) -> str:
        """Category name, qualified by subscription when there is more than one."""
        if account_count == 1:
            return category
        return f"{account.display_name or account.subscription_id}: {category}"

    async def replay(self) -> None:
        """Re-evaluate an earlier scan's stored snapshots against today's rules.

        No collection, no Azure call, no consent required: everything after the
        snapshot is a pure function of it, which is what the raw capture was
        kept for. A tenant-wide scan stored one snapshot per subscription, and
        a replay re-reads all of them.

        The dangerous case is why ``evaluation_only`` exists. Replaying a
        month-old snapshot that now produces PASS where a finding was FAIL would
        otherwise reach the auto-resolve path and stamp that finding "verified
        fixed" -- on the strength of data collected before anyone was even told
        about it. Nothing was observed, so nothing may be resolved. Only a
        replay of the newest snapshots, which are CloudGuard's current picture
        of that environment, may touch findings at all; every older one writes
        coverage and reports counts, and stops there.

        For a multi-subscription scan that is all-or-nothing on purpose: if any
        subscription has been re-read since, the set as a whole no longer
        describes the present, and findings across it cannot be resolved from a
        picture that is partly stale.
        """
        async with service_session() as session:
            scan = await session.get(Scan, self.scan_id)
            if scan is None:
                log.error("scan.missing", scan_id=str(self.scan_id))
                return

            if scan.status == ScanStatus.CANCELLED:
                log.info("scan.cancelled_before_start", scan_id=str(self.scan_id))
                return

            scan.started_at = datetime.now(UTC)
            org_id = scan.organization_id

            try:
                stored = await self._stored_snapshots(session, org_id, scan)
                if not stored:
                    await self._fail(
                        session,
                        scan,
                        "That scan has no stored snapshot to replay. Snapshots are "
                        "written when collection succeeds, so a scan that failed "
                        "before that point has nothing to re-evaluate.",
                    )
                    return

                merged = NormalizedState()
                account_state: list[tuple[CloudAccount, NormalizedState]] = []
                directory: tuple[CloudConnection, NormalizedState] | None = None
                errors: dict[str, str] = {}
                is_current = True
                observed_at = min(row.created_at for row in stored)

                # Both lookups are done for the whole set rather than inside
                # the loop: one subscription's account and one subscription's
                # newest snapshot are two statements each, which a tenant-wide
                # replay would multiply by every subscription it covered.
                accounts = await self._accounts_by_id(
                    session,
                    org_id,
                    [row.cloud_account_id for row in stored if row.cloud_account_id],
                )
                newest_by_account = await self._newest_snapshot_ids(
                    session, org_id, list(accounts)
                )

                for row in stored:
                    # The scan's directory capture, replayed on its own terms.
                    # It is a reading of the tenant, so it has no account to
                    # resolve and no per-subscription staleness to check --
                    # only whether a later scan has since re-read the same
                    # directory through the same connection.
                    if row.cloud_account_id is None:
                        replayed = await self._replay_directory(
                            session, org_id, row
                        )
                        if replayed is None:
                            is_current = False
                            continue
                        directory, snapshot, current = replayed
                        is_current = is_current and current
                        merged.resources.extend(directory[1].resources)
                        merged.relationships.extend(directory[1].relationships)
                        merged.collection_errors.update(directory[1].collection_errors)
                        errors.update(snapshot.errors)
                        continue

                    account = accounts.get(row.cloud_account_id)
                    if account is None:
                        # The subscription is gone. Its capture is still real
                        # history, but there is nothing left to attribute the
                        # resources to, so it cannot be re-evaluated.
                        is_current = False
                        continue

                    if row.id != newest_by_account.get(account.id):
                        is_current = False

                    snapshot = RawSnapshot.from_json(row.data)
                    connector = get_connector(
                        account.provider,
                        tenant_id=account.tenant_id,
                        subscription_id=account.subscription_id,
                    )
                    state = connector.normalize(snapshot)
                    account_state.append((account, state))
                    merged.resources.extend(state.resources)
                    merged.relationships.extend(state.relationships)
                    for category, reason in snapshot.errors.items():
                        errors[
                            self._scoped_key(account, category, len(stored))
                        ] = reason
                    merged.collection_errors.update(state.collection_errors)

                if not account_state and directory is None:
                    await self._fail(
                        session,
                        scan,
                        "None of the subscriptions this scan covered still exist, "
                        "so its snapshots cannot be re-evaluated.",
                    )
                    return

                scan.evaluation_only = not is_current
                scan.collection_errors = errors
                await session.commit()

                await self._evaluate(
                    session,
                    scan,
                    account_state,
                    merged,
                    # The observation happened when the snapshots were taken.
                    # Stamping findings with the replay time would date
                    # month-old evidence to today.
                    observed_at=observed_at,
                    mutate_findings=is_current,
                    degraded=bool(errors),
                    directory=directory,
                )

                # ``last_scan_at`` is deliberately left alone: it records when
                # Azure was last read, and a replay reads only the database.
                await session.commit()

            except Exception as exc:
                log.exception("scan.replay_failed", scan_id=str(scan.id))
                await session.rollback()
                await self._fail(session, scan, str(exc))

    # --------------------------------------------------------------- evaluate
    async def _evaluate(
        self,
        session: AsyncSession,
        scan: Scan,
        account_state: list[tuple[CloudAccount, NormalizedState]],
        merged: NormalizedState,
        *,
        observed_at: datetime,
        mutate_findings: bool,
        degraded: bool,
        directory: tuple[CloudConnection, NormalizedState] | None = None,
    ) -> None:
        """Everything downstream of the snapshots: persist, evaluate, finalize.

        Shared verbatim by a fresh scan and a replay, and the sharing is the
        point. If the two paths diverged, a replay would stop being evidence
        about the pipeline a real scan runs.

        Assets are persisted per subscription, because a resource belongs to
        one; rules are evaluated once over all of them, because a tenant is
        what the customer actually has.
        """
        org_id = scan.organization_id

        # --- normalize ------------------------------------------------------
        await self._set_status(session, scan, ScanStatus.NORMALIZING)
        if mutate_findings:
            id_map = await self._persist_resources(
                session, org_id, account_state, observed_at, directory=directory
            )
        else:
            # A superseded capture describes an environment that has since
            # moved on. Upserting from it would overwrite live criticality,
            # exposure and metadata with historical values -- the columns the
            # risk scorer reads -- and re-create resources deleted since.
            # ``evaluation_only`` means the run changes nothing, and the asset
            # inventory is part of "nothing".
            id_map = await self._existing_resource_ids(
                session,
                org_id,
                [account.id for account, _ in account_state],
                connection_id=directory[0].id if directory is not None else None,
            )
        scan.resource_count = len(merged.resources)

        # Now the size of the job is known, so progress can be a count
        # rather than a phase name. Committed here so a long evaluation
        # shows a denominator immediately rather than at the end.
        scan.progress_total = len(merged.resources)
        scan.progress_done = len(merged.resources)
        await session.commit()

        # --- evaluate -------------------------------------------------------
        await self._set_status(session, scan, ScanStatus.EVALUATING)
        context = RuleContext(
            resources=merged.resources,
            relationships=self._group_edges(merged),
            collection_errors=merged.collection_errors,
        )
        report = self.engine.evaluate(context)
        scan.rule_count = report.rules_run

        await self._persist_coverage(session, org_id, scan, report, id_map)

        # --- findings and risks ---------------------------------------------
        await self._set_status(session, scan, ScanStatus.CALCULATING_RISK)
        if mutate_findings:
            finding_count = await self._persist_findings(
                session, org_id, scan, report, id_map, observed_at
            )
            await self._verify_remediations(session, org_id, scan, report, id_map)
        else:
            # What today's rules would have raised against that capture,
            # reported as a number without being written down as fact --
            # counted the same way a real scan counts, so the two are
            # comparable in the column that shows them side by side.
            finding_count = await self._would_be_open_count(
                session, org_id, report, id_map
            )

        scan.finding_count = finding_count
        scan.completed_at = datetime.now(UTC)
        scan.status = ScanStatus.PARTIAL if degraded else ScanStatus.COMPLETED
        await session.commit()

        log.info(
            "scan.completed",
            scan_id=str(scan.id),
            status=scan.status.value,
            subscriptions=len(account_state),
            resources=scan.resource_count,
            findings=finding_count,
            coverage=round(report.coverage_ratio, 3),
            evaluation_only=scan.evaluation_only,
        )

    async def _existing_resource_ids(
        self,
        session: AsyncSession,
        org_id: UUID,
        account_ids: list[UUID],
        *,
        connection_id: UUID | None = None,
    ) -> dict[str, UUID]:
        """Provider id -> database id, read without writing anything.

        The evaluation-only counterpart to ``_persist_resources``. Resources in
        the snapshot that no longer have a row simply have no id, so the gaps
        they produce are recorded against the scan rather than against an asset
        -- which is accurate: there is no asset to point at any more.

        One query for every subscription, for the same reason its writing
        counterpart takes them all at once. Directory assets are read by
        connection in the same statement: they have no account, so an
        account-only filter would leave every identity gap unattributed.
        """
        scopes: list[ColumnElement[bool]] = []
        if account_ids:
            scopes.append(ResourceRecord.cloud_account_id.in_(account_ids))
        if connection_id is not None:
            scopes.append(
                and_(
                    ResourceRecord.cloud_account_id.is_(None),
                    ResourceRecord.connection_id == connection_id,
                )
            )
        if not scopes:
            return {}
        rows = (
            (
                await session.execute(
                    select(
                        ResourceRecord.provider_resource_id, ResourceRecord.id
                    ).where(
                        ResourceRecord.organization_id == org_id,
                        or_(*scopes),
                    )
                )
            )
            .tuples()
            .all()
        )
        return dict(rows)

    async def _would_be_open_count(
        self,
        session: AsyncSession,
        org_id: UUID,
        report: EvaluationReport,
        id_map: dict[str, UUID],
    ) -> int:
        """How many failures a real scan would have counted as open findings.

        ``_persist_findings`` returns the number of *open* findings, so a plain
        ``len(report.failures)`` would report a larger number for identical
        state: a finding someone has accepted is still a FAIL, and still not
        something the scans list should count. RESOLVED and FALSE_POSITIVE are
        counted, because a real scan reopens both on re-detection.
        """
        keys = {
            (
                f.rule.rule_id,
                id_map.get(f.resource.provider_resource_id) if f.resource else None,
            )
            for f in report.failures
        }
        if not keys:
            return 0

        accepted = {
            (row.rule_id, row.resource_id)
            for row in (
                await session.execute(
                    select(Finding).where(
                        Finding.organization_id == org_id,
                        Finding.status == FindingStatus.ACCEPTED_RISK,
                    )
                )
            )
            .scalars()
            .all()
        }
        return len(keys - accepted)

    # --------------------------------------------------------------- snapshots
    async def _stored_snapshots(
        self, session: AsyncSession, org_id: UUID, scan: Scan
    ) -> list[CloudSnapshot]:
        """Every snapshot the replayed scan stored, one per subscription.

        Scoped by organization as well as scan id: the id arrives on the scan
        row rather than from a request, but a tenant boundary that is only
        enforced where input is untrusted is one nobody can reason about.
        """
        if scan.replay_of_scan_id is None:
            return []
        return list(
            (
                await session.execute(
                    select(CloudSnapshot)
                    .where(
                        CloudSnapshot.scan_id == scan.replay_of_scan_id,
                        CloudSnapshot.organization_id == org_id,
                    )
                    .order_by(CloudSnapshot.created_at)
                )
            )
            .scalars()
            .all()
        )

    async def _replay_directory(
        self, session: AsyncSession, org_id: UUID, row: CloudSnapshot
    ) -> tuple[tuple[CloudConnection, NormalizedState], RawSnapshot, bool] | None:
        """Re-normalize a stored directory capture.

        Returns the state, the snapshot it came from, and whether that capture
        is still the newest directory read for its connection. ``None`` when
        the connection is gone -- the capture remains real history, but there is
        no tenant left to attribute directory assets to.

        The staleness question is the same one asked of a subscription, asked of
        the right thing. A directory capture from last month cannot resolve an
        MFA finding today, for exactly the reason a month-old subscription
        capture cannot resolve a storage finding: nothing was observed.
        """
        if row.connection_id is None:
            return None
        connection = await session.get(CloudConnection, row.connection_id)
        if connection is None or connection.organization_id != org_id:
            return None

        newest = (
            await session.execute(
                select(CloudSnapshot.id)
                .where(
                    CloudSnapshot.organization_id == org_id,
                    CloudSnapshot.connection_id == connection.id,
                    CloudSnapshot.cloud_account_id.is_(None),
                )
                .order_by(CloudSnapshot.created_at.desc(), CloudSnapshot.id.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

        snapshot = RawSnapshot.from_json(row.data)
        connector = get_connector(
            connection.provider,
            tenant_id=connection.tenant_id,
            subscription_id=None,
        )
        state = connector.normalize(snapshot)
        return (connection, state), snapshot, row.id == newest

    async def _accounts_by_id(
        self, session: AsyncSession, org_id: UUID, account_ids: list[UUID]
    ) -> dict[UUID, CloudAccount]:
        if not account_ids:
            return {}
        rows = (
            (
                await session.execute(
                    select(CloudAccount).where(
                        CloudAccount.organization_id == org_id,
                        CloudAccount.id.in_(account_ids),
                    )
                )
            )
            .scalars()
            .all()
        )
        return {account.id: account for account in rows}

    async def _newest_snapshot_ids(
        self, session: AsyncSession, org_id: UUID, account_ids: list[UUID]
    ) -> dict[UUID, UUID]:
        """The most recent snapshot for each of these subscriptions.

        One grouped query rather than one per subscription. ``DISTINCT ON`` is
        PostgreSQL-specific and this application targets exactly one database
        (DECISIONS.md section 13), so the portable-but-slower alternative would
        be paying for a portability nothing asks for.
        """
        if not account_ids:
            return {}
        rows = (
            (
                await session.execute(
                    select(CloudSnapshot.cloud_account_id, CloudSnapshot.id)
                    .where(
                        CloudSnapshot.organization_id == org_id,
                        # Not merely redundant with the ``in_`` beside it. The
                        # column is nullable now -- a directory capture has no
                        # account -- and the NOT NULL is what lets the result be
                        # read as the account-keyed mapping this returns.
                        CloudSnapshot.cloud_account_id.is_not(None),
                        CloudSnapshot.cloud_account_id.in_(account_ids),
                    )
                    .distinct(CloudSnapshot.cloud_account_id)
                    .order_by(
                        CloudSnapshot.cloud_account_id,
                        CloudSnapshot.created_at.desc(),
                        CloudSnapshot.id.desc(),
                    )
                )
            )
            .tuples()
            .all()
        )
        # The NOT NULL in the query is what makes this narrowing sound; the
        # comprehension states it in a form the type checker can follow.
        return {
            account_id: snapshot_id
            for account_id, snapshot_id in rows
            if account_id is not None
        }

    # -------------------------------------------------------------- role drift
    async def _explain_role_drift(
        self, session: AsyncSession, account: CloudAccount, snapshot: RawSnapshot
    ) -> None:
        """Turn a 403 from an out-of-date role into an instruction.

        A customer whose deployed role predates a newer check sees that check's
        collection call fail with ``Forbidden``, which is true and useless. This
        rewrites the recorded reason for exactly those categories.

        It never *invents* a failure. A category that collected successfully is
        left alone even when the role is behind, because many customers also
        hold a broad Reader assignment that covers the new actions anyway --
        marking their working categories as gaps would degrade rules that had
        every right to a verdict.
        """
        if not snapshot.errors or account.connection_id is None:
            return

        connection = await session.get(CloudConnection, account.connection_id)
        if connection is None:
            return

        behind = degraded_categories(connection)
        for category, explanation in behind.items():
            if category in snapshot.errors:
                snapshot.errors[category] = (
                    f"{explanation} (underlying error: {snapshot.errors[category]})"
                )

        if behind:
            log.info(
                "scan.role_behind",
                connection_id=str(connection.id),
                deployed=connection.role_version,
                categories=sorted(behind),
            )

    # ------------------------------------------------------------------ state
    async def _set_status(
        self, session: AsyncSession, scan: Scan, status: ScanStatus
    ) -> None:
        scan.status = status
        await session.commit()

    async def _fail(self, session: AsyncSession, scan: Scan, message: str) -> None:
        scan.status = ScanStatus.FAILED
        scan.error_message = message[:2000]
        scan.completed_at = datetime.now(UTC)
        await session.commit()

    # -------------------------------------------------------------- resources
    async def _persist_resources(
        self,
        session: AsyncSession,
        org_id: UUID,
        account_state: list[tuple[CloudAccount, NormalizedState]],
        observed_at: datetime,
        *,
        directory: tuple[CloudConnection, NormalizedState] | None = None,
    ) -> dict[str, UUID]:
        """Upsert this scan's assets, returning provider id -> row id.

        Resources are updated rather than replaced so ``first_seen_at`` survives
        and a finding keeps pointing at the same asset row across scans.

        ``observed_at`` is when the state was *captured*, not when it was
        processed. The two are the same for a live scan and months apart for a
        replay, and ``last_seen_at`` means nothing if a replay of an old
        snapshot can report a deleted resource as seen today.

        Assets arrive in two scopes and are keyed differently because they are
        different things. A subscription's assets are keyed by (account,
        provider id); the directory's are keyed by (connection, provider id) and
        written once, which is the whole point -- keyed per account they became
        one row per subscription for every user in the tenant, and one finding
        per subscription for every administrator missing MFA.

        Every subscription is handled in one pass on purpose. Per-subscription
        this was one query for the existing rows, one more for *each newly
        created resource* to read back an id the flush had already assigned, and
        a scan of the organization's whole relationship table -- so a tenant of
        fifty subscriptions holding five hundred resources each issued tens of
        thousands of statements to write what is now four.
        """
        now = observed_at
        account_ids = [account.id for account, _ in account_state]
        if not account_ids and directory is None:
            return {}

        # Both scopes read in one statement. The directory rows carry a NULL
        # account, so an ``in_(account_ids)`` filter alone would not see them
        # and every user would be inserted afresh on every scan.
        scopes: list[ColumnElement[bool]] = []
        if account_ids:
            scopes.append(ResourceRecord.cloud_account_id.in_(account_ids))
        if directory is not None:
            scopes.append(
                and_(
                    ResourceRecord.cloud_account_id.is_(None),
                    ResourceRecord.connection_id == directory[0].id,
                )
            )

        existing = {
            (row.cloud_account_id, row.provider_resource_id): row
            for row in (
                await session.execute(
                    select(ResourceRecord).where(
                        ResourceRecord.organization_id == org_id,
                        or_(*scopes),
                    )
                )
            )
            .scalars()
            .all()
        }

        # Held as objects rather than looked up again afterwards. The rows were
        # already in hand; the read-back loop existed only because this
        # reference was dropped.
        touched: dict[str, ResourceRecord] = {}

        def upsert(
            resource: CloudResource,
            *,
            account_id: UUID | None,
            connection_id: UUID | None,
        ) -> None:
            row = existing.get((account_id, resource.provider_resource_id))
            if row is None:
                row = ResourceRecord(
                    organization_id=org_id,
                    cloud_account_id=account_id,
                    connection_id=connection_id,
                    provider=resource.provider,
                    provider_resource_id=resource.provider_resource_id,
                    first_seen_at=now,
                )
                session.add(row)

            row.resource_type = resource.resource_type
            row.name = resource.name
            row.region = resource.region
            row.environment = resource.environment
            row.criticality = resource.criticality
            row.data_sensitivity = resource.data_sensitivity
            row.public_exposure = resource.public_exposure
            row.resource_metadata = resource.metadata
            # Never moved backwards. A replay carries the capture's own
            # time, which is older than a detection already recorded
            # against a live scan -- and "last seen" going backwards would
            # be a lie in the one direction that matters, making a present
            # resource look stale.
            row.last_seen_at = max(row.last_seen_at or now, now)
            touched[resource.provider_resource_id] = row

        for account, state in account_state:
            for resource in state.resources:
                upsert(
                    resource,
                    account_id=account.id,
                    connection_id=account.connection_id,
                )

        # The directory last, and the order is load-bearing. ``touched`` is
        # keyed by provider id alone, so if a scan run before this split left
        # per-account copies of a user behind, whichever scope is written second
        # is the row findings get attributed to. That has to be the tenant-scoped
        # one: it is the row that will still be here after the stale copies age
        # out, and attributing to a per-account copy would re-create the
        # duplicate finding this split exists to remove.
        if directory is not None:
            connection, directory_state = directory
            for resource in directory_state.resources:
                upsert(resource, account_id=None, connection_id=connection.id)

        # One flush assigns every pending primary key.
        await session.flush()
        id_map = {provider_id: row.id for provider_id, row in touched.items()}

        edges = [edge for _account, state in account_state for edge in state.relationships]
        if directory is not None:
            edges.extend(directory[1].relationships)
        await self._persist_relationships(session, org_id, edges, id_map)
        await session.commit()
        return id_map

    async def _persist_relationships(
        self,
        session: AsyncSession,
        org_id: UUID,
        edges: list[tuple[str, RelationshipType, str]],
        id_map: dict[str, UUID],
    ) -> None:
        """Insert the edges that are not already recorded.

        Reads the organization's existing edges once for the whole scan. It
        used to run per subscription, and the query is not scoped by
        subscription -- so the same full-table read was repeated once for every
        subscription in the tenant.
        """
        wanted = {
            (id_map[s], rel, id_map[t])
            for s, rel, t in edges
            if s in id_map and t in id_map
        }
        if not wanted:
            return

        existing = {
            (r.source_resource_id, RelationshipType(r.relationship_type), r.target_resource_id)
            for r in (
                await session.execute(
                    select(ResourceRelationship).where(
                        ResourceRelationship.organization_id == org_id
                    )
                )
            )
            .scalars()
            .all()
        }

        for source, rel, target in wanted - existing:
            session.add(
                ResourceRelationship(
                    organization_id=org_id,
                    source_resource_id=source,
                    target_resource_id=target,
                    relationship_type=rel,
                )
            )

    def _group_edges(self, state: NormalizedState) -> dict[tuple[str, str], list[str]]:
        grouped: dict[tuple[str, str], list[str]] = {}
        for source, rel_type, target in state.relationships:
            grouped.setdefault((source, rel_type.value), []).append(target)
        return grouped

    # --------------------------------------------------------------- coverage
    async def _persist_coverage(
        self,
        session: AsyncSession,
        org_id: UUID,
        scan: Scan,
        report: EvaluationReport,
        id_map: dict[str, UUID],
    ) -> None:
        """Aggregate counts per rule, plus one row per UNKNOWN.

        PASS and NOT_APPLICABLE are counted only. Storing them per resource would
        add resources x rules rows per scan for no benefit
        (RULE_ENGINE.md section 2).
        """
        for rule_id, coverage in report.coverage.items():
            session.add(
                ScanRuleResult(
                    organization_id=org_id,
                    scan_id=scan.id,
                    rule_id=rule_id,
                    evaluated_count=coverage.evaluated_count,
                    passed_count=coverage.passed_count,
                    failed_count=coverage.failed_count,
                    unknown_count=coverage.unknown_count,
                    not_applicable_count=coverage.not_applicable_count,
                )
            )

        for gap in report.gaps:
            resource_uuid = (
                id_map.get(gap.resource.provider_resource_id) if gap.resource else None
            )
            session.add(
                ScanEvaluationGap(
                    organization_id=org_id,
                    scan_id=scan.id,
                    rule_id=gap.rule.rule_id,
                    resource_id=resource_uuid,
                    reason=(gap.result.message or "Rule could not be evaluated")[:1000],
                )
            )

        await session.commit()

    # --------------------------------------------------------------- findings
    async def _persist_findings(
        self,
        session: AsyncSession,
        org_id: UUID,
        scan: Scan,
        report: EvaluationReport,
        id_map: dict[str, UUID],
        observed_at: datetime,
    ) -> int:
        """Write this scan's failures as findings, and score each one.

        Everything the loop needs is read up front. It used to issue a lookup
        per failure for the finding, another for its risk link and a third for
        the risk itself, plus a flush each time round -- four round trips per
        failing check, which a tenant-wide scan multiplies by every subscription
        it covers. The reads are two queries whatever the size of the tenant,
        and the writes flush twice.
        """
        now = observed_at

        # Identity is (organization, rule, resource), so that is the key.
        existing_findings = {
            (f.rule_id, f.resource_id): f
            for f in (
                await session.execute(
                    select(Finding).where(Finding.organization_id == org_id)
                )
            )
            .scalars()
            .all()
        }
        risk_by_finding = {
            link.finding_id: link.risk_id
            for link in (
                await session.execute(
                    select(RiskFinding).where(RiskFinding.organization_id == org_id)
                )
            )
            .scalars()
            .all()
        }

        # Keyed on the finding's identity, not appended per failure. A rule can
        # report the same resource twice in one scan -- AZ-CMP-001 does, when a
        # VM is guarded by the same NSG through two NICs -- and findings are
        # unique on (organization, rule, resource). Two entries for one row
        # meant two INSERTs of the same key.
        pending: dict[
            tuple[str, UUID | None],
            tuple[Finding, SecurityRule, CloudResource | None, ScoredRisk, str],
        ] = {}

        for failure in report.failures:
            rule = failure.rule
            resource = failure.resource
            resource_uuid = id_map.get(resource.provider_resource_id) if resource else None
            key = (rule.rule_id, resource_uuid)

            finding = existing_findings.get(key)
            title = self._title(rule.name, resource)
            description = failure.result.message or rule.description

            if finding is None:
                finding = Finding(
                    organization_id=org_id,
                    rule_id=rule.rule_id,
                    resource_id=resource_uuid,
                    first_detected_at=now,
                    status=FindingStatus.OPEN,
                )
                session.add(finding)
                # Registered immediately so a second failure on the same key
                # updates this row rather than creating a rival for it.
                existing_findings[key] = finding

            elif finding.status in {FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE}:
                # It came back. Reopen rather than leaving a stale RESOLVED --
                # a regression is not a historical record.
                finding.status = FindingStatus.OPEN
                finding.resolved_at = None
                finding.resolved_by_scan_id = None

            finding.scan_id = scan.id
            finding.severity = rule.severity
            finding.title = title
            finding.description = description
            finding.evidence = failure.result.evidence or {}
            # Snapshot-copied so later edits to the rule's guidance do not
            # rewrite the history of findings already raised.
            finding.remediation = rule.remediation
            finding.rule_version = rule.version
            # Never moved backwards. A replay carries the snapshot's own
            # capture time, which can predate a detection already recorded.
            finding.last_detected_at = max(finding.last_detected_at or now, now)

            scored = default_scorer.score(
                RiskInputs(
                    severity=Severity(rule.severity),
                    asset_criticality=resource.criticality if resource else Level.UNKNOWN,
                    data_sensitivity=resource.data_sensitivity if resource else Level.UNKNOWN,
                    internet_exposure=resource.public_exposure if resource else Level.UNKNOWN,
                    exploitability=rule.exploitability,
                )
            )
            finding.risk_score = scored.score
            pending[key] = (finding, rule, resource, scored, title)

        # Counted per finding, not per failure: one row is one finding however
        # many times the rules named it.
        open_count = sum(1 for entry in pending.values() if entry[0].status.is_open)

        # One flush for every new finding, rather than one per finding.
        await session.flush()

        linked_ids = [
            risk_by_finding[f.id] for f, *_ in pending.values() if f.id in risk_by_finding
        ]
        risks = (
            {
                risk.id: risk
                for risk in (
                    await session.execute(select(Risk).where(Risk.id.in_(linked_ids)))
                )
                .scalars()
                .all()
            }
            if linked_ids
            else {}
        )

        # Risks whose junction row does not exist yet. The link needs both ids,
        # so it is written after the risks are flushed rather than inside the
        # loop -- ``RiskFinding`` has no ORM relationships, only the two columns.
        unlinked: list[tuple[Risk, Finding]] = []
        for finding, rule, resource, scored, title in pending.values():
            linked = risk_by_finding.get(finding.id)
            risk = self._upsert_risk(
                session,
                org_id,
                finding,
                rule,
                resource,
                scored,
                title,
                risks.get(linked) if linked else None,
            )
            if linked is None:
                unlinked.append((risk, finding))

        if unlinked:
            await session.flush()
            for risk, finding in unlinked:
                session.add(
                    RiskFinding(
                        risk_id=risk.id,
                        finding_id=finding.id,
                        organization_id=org_id,
                    )
                )

        await session.commit()
        return open_count

    def _upsert_risk(
        self,
        session: AsyncSession,
        org_id: UUID,
        finding: Finding,
        rule: SecurityRule,
        resource: CloudResource | None,
        scored: ScoredRisk,
        title: str,
        risk: Risk | None,
    ) -> Risk:
        """One risk per finding for the MVP, joined through ``risk_findings``.

        Grouping several findings into a single risk later is a change in this
        method, not a migration -- which is exactly why the junction table is
        there from the start (RISK_ENGINE.md section 2).

        ``risk`` is passed in rather than looked up: the caller reads every
        existing risk for the organization once, so this stays a pure decision
        about what the row should contain.
        """
        values = {
            "title": title,
            "description": rule.rationale or rule.description,
            "risk_score": scored.score,
            "risk_level": scored.level,
            "severity": rule.severity.value,
            "asset_criticality": resource.criticality if resource else Level.UNKNOWN,
            "data_sensitivity": resource.data_sensitivity if resource else Level.UNKNOWN,
            "internet_exposure": resource.public_exposure if resource else Level.UNKNOWN,
            "exploitability": rule.exploitability,
            "business_impact": scored.business_impact,
            "score_breakdown": scored.breakdown,
        }

        if risk is None:
            # Fully populated before the flush: several of these columns are
            # NOT NULL, so an empty insert would never reach the database.
            risk = Risk(organization_id=org_id, **values)
            session.add(risk)
        else:
            for key, value in values.items():
                setattr(risk, key, value)

        if finding.status.is_open:
            risk.status = RiskStatus.OPEN
            risk.resolved_at = None

        return risk

    # ----------------------------------------------------------- verification
    async def _verify_remediations(
        self,
        session: AsyncSession,
        org_id: UUID,
        scan: Scan,
        report: EvaluationReport,
        id_map: dict[str, UUID],
    ) -> None:
        """Auto-resolve findings this scan proved fixed.

        The scan result *is* the verification. A finding resolves only on an
        explicit PASS -- an UNKNOWN this time round leaves it open, because
        failing to look is not the same as looking and finding nothing.
        """
        passed: set[tuple[str, UUID | None]] = {
            (rule_id, id_map.get(provider_id) if provider_id else None)
            for rule_id, provider_id in report.passes
        }
        if not passed:
            return

        now = datetime.now(UTC)
        open_findings = (
            (
                await session.execute(
                    select(Finding).where(
                        Finding.organization_id == org_id,
                        Finding.status.in_(
                            [FindingStatus.OPEN, FindingStatus.IN_PROGRESS]
                        ),
                    )
                )
            )
            .scalars()
            .all()
        )

        for finding in open_findings:
            if (finding.rule_id, finding.resource_id) not in passed:
                continue

            finding.status = FindingStatus.RESOLVED
            finding.resolved_at = now
            finding.resolved_by_scan_id = scan.id

            link = (
                await session.execute(
                    select(RiskFinding).where(RiskFinding.finding_id == finding.id)
                )
            ).scalar_one_or_none()
            if link:
                risk = await session.get(Risk, link.risk_id)
                if risk:
                    risk.status = RiskStatus.RESOLVED
                    risk.resolved_at = now

            log.info(
                "finding.auto_resolved",
                finding_id=str(finding.id),
                rule_id=finding.rule_id,
                verified_by_scan=str(scan.id),
            )

        await session.commit()

    def _title(self, rule_name: str, resource: CloudResource | None) -> str:
        """Plain language, naming the asset.

        "Internet-exposed RDP on production-vm-01", not "NSG rule ID 94 permits
        0.0.0.0/0:3389" (PRODUCT_SPEC.md section 4).
        """
        if resource is None:
            return rule_name
        return f"{rule_name} — {resource.name}"
