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

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from app.connectors.base import NormalizedState, RawSnapshot
from app.connectors.evidence import EvidenceCategory
from app.connectors.planning import CollectionPlan
from app.connectors.registry import get_connector
from app.context import ContextDeclaration, resolve_resource
from app.core.db import scan_session, service_session
from app.core.enums import (
    AssetChange,
    FindingEvent,
    FindingStatus,
    Level,
    Provider,
    RelationshipType,
    RiskKind,
    RiskStatus,
    RuleState,
    ScanStatus,
    ScanStepKind,
    ScanStepStatus,
    Severity,
    TaskOutcome,
    VerificationStatus,
)
from app.core.errors import SnapshotUnavailable
from app.core.logging import get_logger, log_context
from app.core.payloads import digest
from app.domain.resource import CloudResource
from app.graph import AssetGraph, Path
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.models.context import ContextDeclarationRecord
from app.models.finding import Finding, FindingEvidence
from app.models.history import AssetChangeEvent, FindingEventRecord
from app.models.resource import ResourceRecord, ResourceRelationship
from app.models.risk import Risk, RiskFinding, RiskHistory
from app.models.scan import (
    CloudSnapshot,
    Evidence,
    EvidenceBlob,
    Scan,
    ScanEvaluationGap,
    ScanRuleResult,
    ScanStep,
)
from app.models.verification import RemediationVerification
from app.risk.scorer import RiskInputs, ScoredRisk, default_scorer
from app.rules.base import RuleContext, RuleResult, SecurityRule
from app.rules.engine import EvaluatedResult, EvaluationReport, RuleEngine
from app.services import orchestrator
from app.services import verification as verification_service
from app.services.cloud_connections import degraded_categories
from app.services.evidence_planner import plan_collection, required_evidence

log = get_logger(__name__)

# One failing check, everything the risk layer needs to write it down:
# the finding row, the rule that raised it, the asset it is about, the score,
# and the sentence. Named because two things now consume it -- a risk per
# finding, and a risk per group of them.
PendingFinding = tuple[Finding, SecurityRule, CloudResource | None, ScoredRisk, str]


def _manifest(snapshot: RawSnapshot) -> dict:
    """The capture, minus the bytes, plus where to find them.

    Everything ``to_json`` records except ``data``, and in its place the content
    hash of each reading. The payloads live once in ``evidence_blobs``, shared
    by every scan that read identical bytes -- so an estate that has not changed
    stores one copy rather than one per night.

    The hashes are computed the same way ``_record_evidence`` computes them,
    from the same ``snapshot.payloads``, so a manifest and the evidence rows
    beside it can never name different bytes for one reading.
    """
    stored = snapshot.to_json()
    stored.pop("data", None)
    stored["payload_hashes"] = {
        key: digest(payload)[0] for key, payload in snapshot.payloads.items()
    }
    return stored


async def _rebuild_capture(
    session: AsyncSession, organization_id: UUID, row: CloudSnapshot
) -> dict:
    """The stored form of a capture, whichever way it was written.

    A capture written before the manifest carries its payloads inline and is
    returned as it stands. A manifest is rebuilt by merging the blobs it names,
    which is exactly what ``TestCaptureReconstruction`` proves adds back up to
    what used to be stored.

    Merged rather than keyed by reading, and that is the case a careless version
    of this gets wrong: one task can produce several payload keys.
    ``authentication_methods`` has no task of its own -- the directory's
    role-map task reads it -- so a rebuild that assumed one key per reading
    would drop it, and the MFA rule would find nothing to judge while reporting
    no error at all.

    A missing blob is refused rather than silently skipped. Half a capture
    replays as an estate that has lost whatever was in the missing half, which
    is the same overclaim as a PASS nobody earned -- retention's interlock
    exists so this cannot happen, and this is what says so if it ever does.

    **The manifest decides which form this is, not ``data``.** This used to ask
    whether ``data`` was NULL, and that question could not be answered by the
    column: 0001 created it ``DEFAULT '{}'::jsonb`` and 0027 dropped only its
    NOT NULL, so a capture written as a manifest came back carrying an empty
    object and read as an inline capture of an estate with nothing in it. Every
    scan then failed in ANALYZE, on a capture that had been stored perfectly.
    0029 removes the default and clears those rows; asking about the manifest
    instead is what stops a column default ever answering "did anybody write
    this" again.
    """
    if row.manifest is None:
        if not row.data:
            raise SnapshotUnavailable(
                "this capture carries neither a manifest nor any inline "
                "readings, so there is nothing to replay it from"
            )
        return dict(row.data)

    manifest = dict(row.manifest)
    hashes = dict(manifest.pop("payload_hashes", {}) or {})
    payloads = {
        blob.content_hash: blob.content
        for blob in (
            await session.execute(
                select(EvidenceBlob).where(
                    EvidenceBlob.organization_id == organization_id,
                    EvidenceBlob.content_hash.in_(list(hashes.values())),
                )
            )
        )
        .scalars()
        .all()
    }

    data: dict = {}
    for key, content_hash in hashes.items():
        payload = payloads.get(content_hash)
        if payload is None:
            raise SnapshotUnavailable(
                f"the stored reading for {key} is no longer held, so this "
                "capture cannot be replayed without describing an estate that "
                "is missing whatever it contained"
            )
        data.update(payload)

    manifest["data"] = data
    return manifest


class ScanVanished(Exception):
    """The scan a step was queued for is gone.

    Not a :class:`ScanStepError`: there is no step outcome to record against a
    scan that no longer exists, and the rows a settle would write would be
    orphans.
    """


class ScanStepError(Exception):
    """A step could not do its work, and said why in terms a customer can read.

    Distinguished from an unexpected exception because the two deserve
    different treatment: this is a condition the pipeline anticipated, so its
    message is the one shown, and there is nothing to retry when the reason is
    "the subscription is gone".
    """

    retryable: bool = False


class ScanScopeEmpty(ScanStepError):
    """Nothing in scope. Retrying resolves the same empty set."""


class CollectionUnavailable(ScanStepError):
    """The scope this step was created for is no longer reachable."""


class NothingToAnalyze(ScanStepError):
    """Every collection failed, so there is nothing to interpret."""


@dataclass
class ReconstructedScan:
    """A scan's captures, read back and normalized.

    What the single-task pipeline used to carry in memory between collection
    and evaluation. Reading it back from the captures is not a workaround for
    having split the two apart: everything after a capture is already a pure
    function of it -- the property replay depends on -- so this is the same
    operation the pipeline always performed.
    """

    merged: NormalizedState = field(default_factory=NormalizedState)
    account_state: list[tuple[CloudAccount, NormalizedState]] = field(
        default_factory=list
    )
    directory: tuple[CloudConnection, NormalizedState] | None = None
    errors: dict[str, str] = field(default_factory=dict)
    # Whether these captures are still CloudGuard's current picture. False when
    # any of them has been superseded, which is what forbids resolving a finding
    # from them.
    is_current: bool = True
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class _StepHeartbeat:
    """The progress callback a step hands to collection.

    Renews the step's lease rather than counting anything. Per-listing progress
    was accumulated in one process, which could only ever describe the part of
    a scan that process happened to run; the scan's progress is now derived
    from its steps, which every worker can see. What is left for a callback to
    do is the thing only the running worker knows -- that it is still alive.
    """

    def __init__(self, step_id: UUID, organization_id: UUID) -> None:
        self.step_id = step_id
        # Carried so the heartbeat runs on the same constrained session as the
        # step it is beating for. It writes one column on one row, and doing
        # that on the owner connection would be a small hole in an otherwise
        # closed boundary.
        self.organization_id = organization_id

    async def __call__(self, done: int, total: int) -> None:
        try:
            async with scan_session(self.organization_id) as session:
                await orchestrator.renew(session, self.step_id)
        except Exception as exc:  # pragma: no cover - a heartbeat is never fatal
            # Losing a heartbeat costs the step its lease eventually, which the
            # reaper handles. Failing the step over it would turn a database
            # blip into lost collection.
            log.warning(
                "scan.heartbeat_failed", step_id=str(self.step_id), error=str(exc)
            )


class ScanPipeline:
    def __init__(self, scan_id: UUID) -> None:
        self.scan_id = scan_id
        self.engine = RuleEngine()
        self._organization_id: UUID | None = None

    @asynccontextmanager
    async def _session(self) -> AsyncIterator[AsyncSession]:
        """A session PostgreSQL will hold to this scan's organization.

        Every read and write a scan makes goes through here. Before this, the
        pipeline ran on the owner connection -- RLS does not apply to it -- so
        the tenant boundary was whatever ``organization_id`` filter each query
        happened to carry. Those filters are all still there and still correct;
        what changed is that they are no longer the only thing standing between
        two customers' data.
        """
        organization_id = await self._organization()
        async with scan_session(organization_id) as session:
            yield session

    async def _organization(self) -> UUID:
        """Which organization this scan belongs to.

        The one read that cannot be scoped, because it is the read that
        establishes the scope. Deliberately narrow: one row by primary key,
        one column, cached for the life of the step -- and taken from the scan
        record rather than from the queue message, which is the same rule the
        pipeline has always followed about where a tenant boundary may come
        from.
        """
        if self._organization_id is None:
            async with service_session() as session:
                organization_id = (
                    await session.execute(
                        select(Scan.organization_id).where(Scan.id == self.scan_id)
                    )
                ).scalar_one_or_none()
            if organization_id is None:
                raise ScanVanished(
                    "This scan no longer exists, so there is nothing to run."
                )
            self._organization_id = organization_id
        return self._organization_id

    # ------------------------------------------------------------------ steps
    #
    # A scan used to be this class's ``run`` method: resolve the scope, read
    # every subscription in sequence, then interpret the lot, all inside one
    # Celery task with no retries. The three methods below are that method cut
    # at the seams it already had, so each becomes a durably recorded step that
    # can be claimed, retried and settled on its own
    # (``app/services/orchestrator.py``).
    #
    # The cut is not arbitrary. Collection writes captures and nothing else;
    # everything after a capture is a pure function of it. That was already
    # true -- it is what makes replay possible -- and it is what lets ANALYZE
    # reconstruct from the database exactly what the old in-memory pipeline
    # carried between its phases.

    async def run_step(self, step_id: UUID) -> ScanStepStatus:
        """Perform one claimed step and settle it. Returns how it went.

        The dispatch lives here rather than in the Celery task so that the
        thing under test and the thing in production are the same code. A test
        that drove the steps its own way would be testing its own driver.

        Which failures are retried is decided here too, and the distinction is
        between conditions the pipeline anticipated and ones it did not. "That
        subscription is gone" will be just as gone on the third attempt;
        a throttled API or a killed worker will not.
        """
        async with self._session() as session:
            step = await session.get(ScanStep, step_id)
            if step is None:
                log.error("scan.step_missing", step_id=str(step_id))
                return ScanStepStatus.FAILED
            kind = step.kind
            scope = step.cloud_account_id

        # Bound here rather than in the Celery task, so a step driven by the
        # tests or by a future caller carries the same context a queued one
        # does. The scope is the id that matters when a tenant-wide scan has
        # fifty collections in flight and one of them is slow.
        with log_context(
            scan_id=str(self.scan_id),
            step_id=str(step_id),
            step_kind=kind.value,
            cloud_account_id=str(scope) if scope else None,
        ):
            try:
                if kind == ScanStepKind.PLAN:
                    await self.plan()
                elif kind == ScanStepKind.COLLECT:
                    await self.collect(step_id)
                else:
                    await self.analyze()
            except ScanStepError as exc:
                return await self._settle(step_id, str(exc), retryable=exc.retryable)
            except Exception as exc:
                log.exception("scan.step_failed")
                return await self._settle(step_id, str(exc), retryable=True)

            return await self._settle(step_id, None, retryable=False)

    def _log_step(self, step: ScanStep, outcome: ScanStepStatus) -> None:
        """One line per stage, carrying what it cost.

        The scan-level log said a scan finished and how many findings it held,
        which cannot distinguish a slow subscription from a slow evaluation.
        A stage names the scope it read and the seconds it took, which is the
        first thing anyone asks about a scan that took twice as long as usual.
        """
        started = step.started_at
        log.info(
            "scan.step_finished",
            scan_id=str(self.scan_id),
            stage=step.kind.value,
            scope=step.describe(),
            outcome=outcome.value,
            attempt=step.attempt,
            seconds=(
                round((datetime.now(UTC) - started).total_seconds(), 1)
                if started
                else None
            ),
        )

    async def _settle(
        self, step_id: UUID, error: str | None, *, retryable: bool
    ) -> ScanStepStatus:
        async with self._session() as session:
            step = await session.get(ScanStep, step_id)
            if step is None:
                return ScanStepStatus.FAILED
            if error is None:
                await orchestrator.finish(session, step, ScanStepStatus.SUCCEEDED)
                self._log_step(step, ScanStepStatus.SUCCEEDED)
                return ScanStepStatus.SUCCEEDED
            if not retryable:
                await orchestrator.finish(
                    session, step, ScanStepStatus.FAILED, error
                )
                self._log_step(step, ScanStepStatus.FAILED)
                return ScanStepStatus.FAILED
            outcome = await orchestrator.fail_or_retry(session, step, error)
            self._log_step(step, outcome)
            return outcome

    async def plan(self) -> list[CloudAccount]:
        """Resolve what this scan covers and create a step per scope.

        Scope is resolved here rather than when the scan was queued, and that
        is deliberate: a subscription discovered or excluded while the scan sat
        in the queue should be picked up or left out accordingly, and a queue
        that can be minutes deep makes that a real difference rather than a
        theoretical one.
        """
        async with self._session() as session:
            scan = await self._require_scan(session)
            if scan is None:
                return []

            accounts = await self._resolve_scope(session, scan)
            if not accounts:
                raise ScanScopeEmpty(
                    "This scan has nothing in scope. Its subscriptions may have "
                    "been removed, excluded from scanning, or never discovered."
                )

            connection = await self._resolve_connection(session, scan, accounts)
            scan.started_at = scan.started_at or datetime.now(UTC)
            await orchestrator.create_collect_steps(
                session,
                scan,
                accounts,
                # No connection means no tenant-level grant to read a directory
                # through, so there is no step to create. ANALYZE records the
                # resulting gap rather than inventing a step that could only
                # fail.
                directory=connection is not None and bool(connection.tenant_id),
            )
            await session.commit()
            log.info(
                "scan.planned",
                scan_id=str(scan.id),
                subscriptions=len(accounts),
                directory=connection is not None,
            )
            return accounts

    async def collect(self, step_id: UUID) -> None:
        """Read one scope and store what came back. Interprets nothing.

        Idempotent by demolition: a retried step deletes whatever the previous
        attempt stored for this scope before storing again. The alternative is
        an upsert across two tables and a blob store, and a retry that half
        matched would be worse than one that starts clean -- a capture is
        supposed to be what the provider said in one reading, not a merge of
        two.
        """
        async with self._session() as session:
            scan = await self._require_scan(session)
            if scan is None:
                return
            step = await session.get(ScanStep, step_id)
            if step is None:
                log.error("scan.step_missing", step_id=str(step_id))
                return

            observed_at = datetime.now(UTC)
            connection = await self._resolve_connection(
                session, scan, await self._resolve_scope(session, scan)
            )
            await self._discard_prior_attempt(session, scan, step.cloud_account_id)

            if step.is_directory:
                if connection is None or not connection.tenant_id:
                    raise CollectionUnavailable(
                        "This connection has no tenant to read a directory from."
                    )
                await self._collect_directory(
                    session,
                    scan,
                    connection,
                    _StepHeartbeat(step_id, scan.organization_id),
                    observed_at,
                    required=True,
                )
                await session.commit()
                return

            account = await session.get(CloudAccount, step.cloud_account_id)
            if account is None:
                raise CollectionUnavailable(
                    "This subscription is no longer connected to CloudGuard."
                )

            connector = get_connector(
                account.provider,
                tenant_id=account.tenant_id,
                subscription_id=account.subscription_id,
            )
            # What this reading is for, decided before it is taken: every key
            # some enabled rule reads, plus the ones the product itself is
            # built from, minus whatever is already held fresh enough to stand
            # in for a new read.
            plan = await plan_collection(
                session,
                organization_id=scan.organization_id,
                provider=account.provider,
                required=required_evidence(
                    account.provider, connector.baseline_evidence()
                ),
                scan_id=scan.id,
                cloud_account_id=account.id,
                connection_id=account.connection_id,
                now=observed_at,
            )
            snapshot = await connector.collect(
                _StepHeartbeat(step_id, scan.organization_id), plan
            )
            await self._explain_role_drift(session, account, snapshot)

            # Persisted before interpretation, always. One row per subscription,
            # so a tenant-wide scan can still be replayed subscription by
            # subscription.
            session.add(
                CloudSnapshot(
                    organization_id=scan.organization_id,
                    cloud_account_id=account.id,
                    connection_id=account.connection_id,
                    scan_id=scan.id,
                    snapshot_version=snapshot.version,
                    manifest=_manifest(snapshot),
                )
            )
            await self._record_evidence(
                session,
                scan.organization_id,
                scan,
                snapshot,
                observed_at=observed_at,
                account=account,
                plan=plan,
            )
            account.last_scan_at = observed_at
            await session.commit()

    async def analyze(self) -> None:
        """Interpret every capture this scan stored.

        Reconstructs from the database what the old single-task pipeline held
        in memory between its phases. That is not a workaround: everything
        after a capture is already a pure function of it, which is the property
        replay depends on, so reading the captures back is the same operation
        the pipeline was always performing -- now with the collection that
        produced them separately durable.
        """
        async with self._session() as session:
            scan = await self._require_scan(session)
            if scan is None:
                return

            stored = await self._snapshots_of(session, scan.organization_id, scan.id)
            if not stored:
                raise NothingToAnalyze(
                    "This scan stored no readings, so there is nothing to "
                    "evaluate. Every subscription it covered failed to collect."
                )

            state = await self._reconstruct(session, scan, stored)
            state.errors.update(await self._directory_gap(session, scan, state))
            scan.collection_errors = state.errors
            await session.commit()

            await self._evaluate(
                session,
                scan,
                state.account_state,
                state.merged,
                observed_at=state.observed_at,
                mutate_findings=True,
                degraded=bool(state.errors),
                directory=state.directory,
                # The orchestrator decides when a scan is finished and how,
                # from the steps. A stage writing its own terminal status would
                # be a second source of truth for it.
                finalize=False,
            )

    async def _require_scan(self, session: AsyncSession) -> Scan | None:
        """The scan, unless it has been cancelled or no longer exists.

        Checked at every step rather than only at the start. A scan runs across
        several steps and possibly several workers, and the cancel button is
        used in exactly the window between two of them -- carrying on would
        write findings somebody asked not to collect.
        """
        scan = await session.get(Scan, self.scan_id)
        if scan is None:
            log.error("scan.missing", scan_id=str(self.scan_id))
            return None
        if scan.status == ScanStatus.CANCELLED:
            log.info("scan.cancelled_before_step", scan_id=str(self.scan_id))
            return None
        return scan

    async def _discard_prior_attempt(
        self, session: AsyncSession, scan: Scan, account_id: UUID | None
    ) -> None:
        """Clear what an earlier attempt at this scope stored.

        A capture is unique on (scan, scope), so a retry that simply wrote again
        would conflict; and a capture is supposed to be one reading rather than
        a merge of two, so clearing is also the honest thing rather than merely
        the convenient one. Evidence rows go with it, since they describe that
        reading.
        """
        scope = (
            CloudSnapshot.cloud_account_id == account_id
            if account_id is not None
            else CloudSnapshot.cloud_account_id.is_(None)
        )
        await session.execute(
            delete(CloudSnapshot).where(
                CloudSnapshot.organization_id == scan.organization_id,
                CloudSnapshot.scan_id == scan.id,
                scope,
            )
        )
        evidence_scope = (
            Evidence.cloud_account_id == account_id
            if account_id is not None
            else Evidence.cloud_account_id.is_(None)
        )
        await session.execute(
            delete(Evidence).where(
                Evidence.organization_id == scan.organization_id,
                Evidence.scan_id == scan.id,
                evidence_scope,
            )
        )

    async def _collect_directory(
        self,
        session: AsyncSession,
        scan: Scan,
        connection: CloudConnection | None,
        heartbeat: Callable[[int, int], Awaitable[None]],
        observed_at: datetime,
        *,
        required: bool = False,
    ) -> tuple[NormalizedState, RawSnapshot] | None:
        """Read the tenant directory once, and store it as its own capture.

        Returns ``None`` when there is nothing to read it through, or when the
        read failed outright. Both cases end as a recorded gap rather than as a
        failed scan: a directory CloudGuard could not reach costs the identity
        rules their verdict and costs the subscription rules nothing.

        ``required`` raises instead, which is what its own step wants: a step
        that swallowed the failure would report SUCCEEDED, spend none of its
        retries, and leave the customer a silent gap where a transient Graph
        error deserved a second attempt.

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
        plan = await plan_collection(
            session,
            organization_id=scan.organization_id,
            provider=connection.provider,
            required=required_evidence(
                connection.provider, connector.baseline_evidence()
            ),
            scan_id=scan.id,
            connection_id=connection.id,
            now=observed_at,
        )
        try:
            snapshot = await connector.collect_directory(heartbeat, plan)
        except Exception as exc:
            if required:
                raise
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
                manifest=_manifest(snapshot),
            )
        )
        await self._record_evidence(
            session,
            scan.organization_id,
            scan,
            snapshot,
            observed_at=observed_at,
            connection=connection,
            plan=plan,
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

    async def _record_evidence(
        self,
        session: AsyncSession,
        org_id: UUID,
        scan: Scan,
        snapshot: RawSnapshot,
        *,
        observed_at: datetime,
        account: CloudAccount | None = None,
        connection: CloudConnection | None = None,
        plan: CollectionPlan | None = None,
    ) -> None:
        """One row per reading, and one stored copy of what it produced.

        The rows answer questions the snapshot cannot. The same facts travel
        inside the capture, which is the right home for them -- a replay has to
        see exactly what the original run saw -- but a fact buried in a JSONB
        payload can answer questions about one scan and none at all about a
        fleet, and "has storage been truncating in this subscription all week?"
        is the one that matters when deciding whether a customer has an outage
        or simply a large tenant.

        The payloads are stored by content hash, which is where the cost goes.
        A customer scanning daily whose network security groups have not changed
        in a month stored thirty identical copies of them. Keyed by hash they
        store one, and every later scan of an unchanged environment adds rows
        rather than megabytes.
        """
        connection_id = (
            connection.id if connection is not None else
            account.connection_id if account is not None else None
        )
        account_id = account.id if account is not None else None
        digests = {
            key: digest(payload) for key, payload in snapshot.payloads.items()
        }
        # Readings this run did not take, and when they were taken. Read off
        # the plan rather than off the capture: the capture carries the same
        # fact as text for whoever reads a snapshot later, and a datetime that
        # never became a string cannot come back as a different one.
        carried_at = {
            key.value: reading.collected_at
            for key, reading in (plan.carried.items() if plan else ())
        }
        await self._store_blobs(session, org_id, snapshot.payloads, digests, observed_at)

        for key, entry in snapshot.coverage.items():
            hashed = digests.get(key)
            session.add(
                Evidence(
                    organization_id=org_id,
                    scan_id=scan.id,
                    cloud_account_id=account_id,
                    connection_id=connection_id,
                    provider=snapshot.provider,
                    evidence_key=key,
                    category=entry.get("category", ""),
                    outcome=TaskOutcome(entry.get("outcome", TaskOutcome.FAILED.value)),
                    detail=entry.get("detail") or None,
                    item_count=int(entry.get("item_count", 0)),
                    # When the provider was read, which for a carried reading
                    # is not now. Recording it as now would make the freshness
                    # question ask about the last scan that reused a reading
                    # rather than about the read itself, and one reading could
                    # then be carried for ever, each scan renewing it.
                    collected_at=carried_at.get(key, observed_at),
                    permissions=list(entry.get("permissions") or []),
                    # `[]` for a reading taken before this was recorded, which
                    # is a fact about CloudGuard's history rather than a claim
                    # that the task called nothing.
                    endpoints=list(entry.get("endpoints") or []),
                    # NULL where a task produced nothing, which a failed one
                    # did. A hash of an empty payload would claim there was
                    # something to point at.
                    content_hash=hashed[0] if hashed else None,
                    byte_size=hashed[1] if hashed else 0,
                )
            )

    async def _store_blobs(
        self,
        session: AsyncSession,
        org_id: UUID,
        payloads: dict[str, dict],
        digests: dict[str, tuple[str, int]],
        observed_at: datetime,
    ) -> None:
        """Write the payloads this run produced that are not already stored.

        One query for what exists rather than one per payload: a scan produces
        a dozen readings and a tenant-wide one produces a dozen per
        subscription, and the whole point of content addressing is that most of
        them are already here.

        That query asks for the hashes alone. It used to load the rows, which
        meant a scan of an unchanged estate -- the case content addressing
        exists for, and the common one -- read every payload it already held
        back out of PostgreSQL, decompressed nothing, used none of it, and set
        a timestamp. The touch is a single UPDATE instead, guarded so it can
        only move ``last_seen_at`` forward: a replay of a capture collected in
        March must not make its payloads look freshly read.
        """
        if not digests:
            return

        hashes = {content_hash for content_hash, _size in digests.values()}
        held = set(
            (
                await session.execute(
                    select(EvidenceBlob.content_hash).where(
                        EvidenceBlob.organization_id == org_id,
                        EvidenceBlob.content_hash.in_(hashes),
                    )
                )
            )
            .scalars()
            .all()
        )

        if held:
            # Already here, byte for byte. Touched rather than rewritten, so
            # retention can tell a payload still in use from one whose last
            # reference was months ago.
            await session.execute(
                update(EvidenceBlob)
                .where(
                    EvidenceBlob.organization_id == org_id,
                    EvidenceBlob.content_hash.in_(held),
                    EvidenceBlob.last_seen_at < observed_at,
                )
                .values(last_seen_at=observed_at)
            )

        for key, (content_hash, size) in digests.items():
            if content_hash in held:
                continue
            session.add(
                EvidenceBlob.of(
                    organization_id=org_id,
                    payload=payloads[key],
                    content_hash=content_hash,
                    byte_size=size,
                    observed_at=observed_at,
                )
            )
            # Recorded immediately: two readings in one scan can produce
            # identical bytes -- two subscriptions with no storage accounts do
            # -- and a second insert of the same key would break on the
            # primary key.
            held.add(content_hash)

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
        """Category name, qualified by subscription when there is more than one.

        ``account_count`` counts *subscriptions*, not captures. A scan now
        stores a directory capture alongside them, and counting captures made a
        single-subscription scan look like two -- so its errors were qualified
        with a subscription id nobody needed, turning a plain "storage" into
        "00000000-0000-0000-0000-000000000001: storage" on the one screen whose
        job is to be readable.
        """
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
        async with self._session() as session:
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

                state = await self._reconstruct(
                    session, scan, stored, check_freshness=True
                )

                if not state.account_state and state.directory is None:
                    await self._fail(
                        session,
                        scan,
                        "None of the subscriptions this scan covered still exist, "
                        "so its snapshots cannot be re-evaluated.",
                    )
                    return

                scan.evaluation_only = not state.is_current
                scan.collection_errors = state.errors
                await session.commit()

                await self._evaluate(
                    session,
                    scan,
                    state.account_state,
                    state.merged,
                    # The observation happened when the snapshots were taken.
                    # Stamping findings with the replay time would date
                    # month-old evidence to today.
                    observed_at=state.observed_at,
                    mutate_findings=state.is_current,
                    degraded=bool(state.errors),
                    directory=state.directory,
                )

                # ``last_scan_at`` is deliberately left alone: it records when
                # Azure was last read, and a replay reads only the database.
                await session.commit()

            except Exception as exc:
                log.exception("scan.replay_failed", scan_id=str(scan.id))
                await session.rollback()
                await self._fail(session, scan, str(exc))

    # ---------------------------------------------------------- reconstruction
    async def _reconstruct(
        self,
        session: AsyncSession,
        scan: Scan,
        stored: list[CloudSnapshot],
        *,
        check_freshness: bool = False,
    ) -> ReconstructedScan:
        """Read captures back into the state the rule engine evaluates.

        Shared verbatim by ANALYZE and by replay, and the sharing is the point.
        The two differ in one thing only -- whether the captures being read are
        this scan's own or an earlier scan's, which is what ``check_freshness``
        asks about -- and if the paths diverged, a replay would stop being
        evidence about the pipeline a real scan runs.

        ``check_freshness`` decides whether findings may be touched at all. A
        capture that has since been superseded describes an environment that has
        moved on, and resolving a finding from it would stamp "verified fixed"
        against something nobody looked at.
        """
        org_id = scan.organization_id
        state = ReconstructedScan(observed_at=min(row.created_at for row in stored))

        # Both lookups are done for the whole set rather than inside the loop:
        # one subscription's account and one subscription's newest capture are
        # two statements each, which a tenant-wide scan would multiply by every
        # subscription it covered.
        accounts = await self._accounts_by_id(
            session,
            org_id,
            [row.cloud_account_id for row in stored if row.cloud_account_id],
        )
        newest_by_account = (
            await self._newest_snapshot_ids(session, org_id, list(accounts))
            if check_freshness
            else {}
        )
        # What the customer has said about these subscriptions since the capture
        # was taken. Read here rather than at collection time on purpose: a
        # declaration is not part of the environment, so it must not be frozen
        # into the capture -- marking a subscription production today should
        # change how its findings rank today, including on a replay of an older
        # reading.
        declarations = await self._declarations_for(session, org_id, list(accounts))

        for row in stored:
            # The directory capture, read on its own terms. It is a reading of
            # the tenant, so it has no account to resolve and no
            # per-subscription staleness to check -- only whether a later scan
            # has since re-read the same directory through the same connection.
            if row.cloud_account_id is None:
                restored = await self._restore_directory(
                    session, org_id, row, check_freshness=check_freshness
                )
                if restored is None:
                    state.is_current = False
                    continue
                state.directory, snapshot, current = restored
                state.is_current = state.is_current and current
                state.merged.resources.extend(state.directory[1].resources)
                state.merged.relationships.extend(state.directory[1].relationships)
                state.merged.collection_errors.update(
                    state.directory[1].collection_errors
                )
                # Tenant defences. They come from the directory reading and are
                # about the whole tenant, so they merge once rather than per
                # subscription -- the same reason the directory is read once.
                state.merged.controls.update(state.directory[1].controls)
                state.errors.update(snapshot.errors)
                continue

            account = accounts.get(row.cloud_account_id)
            if account is None:
                # The subscription is gone. Its capture is still real history,
                # but there is nothing left to attribute the resources to, so it
                # cannot be re-evaluated.
                state.is_current = False
                continue

            if check_freshness and row.id != newest_by_account.get(account.id):
                state.is_current = False

            snapshot = RawSnapshot.from_json(
                await _rebuild_capture(session, org_id, row)
            )
            connector = get_connector(
                account.provider,
                tenant_id=account.tenant_id,
                subscription_id=account.subscription_id,
            )
            account_state = connector.normalize(snapshot)
            # Normalization is a pure function of the capture, so this is where
            # the customer's own view of the subscription is applied: as a
            # floor over what was inferred, never as an override of it.
            declared = declarations.get(account.id)
            if declared is not None:
                account_state.resources = [
                    resolve_resource(resource, declared)
                    for resource in account_state.resources
                ]
            state.account_state.append((account, account_state))
            state.merged.resources.extend(account_state.resources)
            state.merged.relationships.extend(account_state.relationships)
            # Namespaced by subscription: two subscriptions can both fail to
            # read storage, and "storage: timeout" twice over tells a customer
            # nothing about which one to look at.
            for category, reason in snapshot.errors.items():
                state.errors[
                    self._scoped_key(account, category, len(accounts))
                ] = reason
            state.merged.collection_errors.update(account_state.collection_errors)

        return state

    async def _declarations_for(
        self, session: AsyncSession, org_id: UUID, account_ids: list[UUID]
    ) -> dict[UUID, ContextDeclaration]:
        """Customer-declared context for the subscriptions this scan covers.

        One statement for the whole scan. A tenant-wide scan covers as many
        subscriptions as the customer has, and a lookup per subscription is the
        shape that turned every other batch read in this pipeline into a
        thousand statements.
        """
        if not account_ids:
            return {}
        rows = (
            (
                await session.execute(
                    select(ContextDeclarationRecord).where(
                        ContextDeclarationRecord.organization_id == org_id,
                        ContextDeclarationRecord.cloud_account_id.in_(account_ids),
                    )
                )
            )
            .scalars()
            .all()
        )
        return {
            row.cloud_account_id: ContextDeclaration(
                environment=row.environment,
                criticality=row.criticality,
                data_sensitivity=row.data_sensitivity,
                # Declared about the subscription, so every asset inside it
                # inherits the claim rather than being the subject of it. The
                # recorded source has to say which, or "you told us this" would
                # be shown against an asset nobody has ever looked at.
                inherited=True,
            )
            for row in rows
        }

    async def _directory_gap(
        self, session: AsyncSession, scan: Scan, state: ReconstructedScan
    ) -> dict[str, str]:
        """Why the identity checks have no directory, when they have none.

        A scan with no directory capture must not let its identity rules pass:
        failing to look is not the same as looking and finding nothing. The
        steps say which of the two happened -- a directory step that failed, or
        no directory step at all because there was no grant to read one through
        -- and the two need different sentences, because they send the customer
        to different places.

        Written into the rule-facing gaps keyed per evidence key, not per
        category. A category name there would match nothing a rule declares, and
        every identity check would quietly PASS over a directory nobody read.
        """
        if state.directory is not None:
            return {}

        step = (
            await session.execute(
                select(ScanStep).where(
                    ScanStep.scan_id == scan.id,
                    ScanStep.kind == ScanStepKind.COLLECT,
                    ScanStep.cloud_account_id.is_(None),
                )
            )
        ).scalar_one_or_none()

        if step is None:
            reason = (
                "This scan has no cloud connection behind it, so CloudGuard has "
                "no grant to read the tenant directory. Reconnect it from the "
                "connections page."
            )
        else:
            reason = (
                "The tenant directory could not be read for this scan, so no "
                f"identity check could reach a verdict. ({step.error or 'unknown error'})"
            )

        # Asked of the connector rather than of Azure's key enum directly. The
        # pipeline is the provider-neutral half of this system, and a second
        # connector whose categories it could not ask would degrade nothing.
        provider = await self._provider_of(session, scan)
        for key in get_connector(provider).evidence_keys_in(EvidenceCategory.IDENTITY):
            state.merged.collection_errors[key.value] = reason
        return {EvidenceCategory.IDENTITY.value: reason}

    async def _provider_of(self, session: AsyncSession, scan: Scan) -> Provider:
        """Which cloud this scan is reading.

        Off the connection or the subscription, because a scan is scoped to one
        or the other and both name their provider. Not stored on the scan: it
        would be a third place the same fact lives, and the one most likely to
        disagree after a row is edited.
        """
        if scan.connection_id is not None:
            connection = await session.get(CloudConnection, scan.connection_id)
            if connection is not None:
                return connection.provider
        if scan.cloud_account_id is not None:
            account = await session.get(CloudAccount, scan.cloud_account_id)
            if account is not None:
                return account.provider
        # A scan scoped to neither cannot have collected anything, so nothing
        # downstream of this will be asked for a key. Azure is the fallback
        # rather than an error because raising here would turn "this scan had
        # no scope" into an exception in the code that explains gaps.
        return Provider.AZURE

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
        finalize: bool = True,
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
        # What this run is entitled to touch. Every query below that reaches
        # for existing rows is scoped by it, so the cost of a scan tracks what
        # it read rather than how large the customer has grown.
        account_ids = [account.id for account, _ in account_state]
        connection_id = directory[0].id if directory is not None else None
        # Which subscription each asset came from, taken before the merge --
        # after it, a tenant-wide scan's resources are one list and the
        # subscription that produced each is no longer recoverable from them.
        # A finding cites the readings of *its* asset's subscription, so this is
        # what keeps subscription B's storage listing from being offered as the
        # provenance of a finding in subscription A.
        account_of = {
            resource.provider_resource_id: account.id
            for account, state in account_state
            for resource in state.resources
        }

        # --- normalize ------------------------------------------------------
        await self._set_status(session, scan, ScanStatus.NORMALIZING)
        if mutate_findings:
            id_map = await self._persist_resources(
                session,
                org_id,
                account_state,
                observed_at,
                directory=directory,
                scan_id=scan.id,
            )
        else:
            # A superseded capture describes an environment that has since
            # moved on. Upserting from it would overwrite live criticality,
            # exposure and metadata with historical values -- the columns the
            # risk scorer reads -- and re-create resources deleted since.
            # ``evaluation_only`` means the run changes nothing, and the asset
            # inventory is part of "nothing".
            id_map = await self._existing_resource_ids(
                session, org_id, account_ids, connection_id=connection_id
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
            controls=merged.controls,
        )
        report = self.engine.evaluate(context)
        scan.rule_count = report.rules_run

        await self._persist_coverage(session, org_id, scan, report, id_map)

        # --- findings and risks ---------------------------------------------
        await self._set_status(session, scan, ScanStatus.CALCULATING_RISK)
        if mutate_findings:
            finding_count = await self._persist_findings(
                session,
                org_id,
                scan,
                report,
                id_map,
                observed_at,
                account_ids=account_ids,
                connection_id=connection_id,
                account_of=account_of,
            )
            await self._verify_remediations(
                session,
                org_id,
                scan,
                report,
                id_map,
                account_ids=account_ids,
                connection_id=connection_id,
            )
            # After the findings exist, because a scenario is built out of
            # them: the worst member is the floor a route is scored from, and
            # a route assembled before its members would have nothing to stand
            # on.
            await self._correlate_paths(session, org_id, scan, merged, id_map)
            # Last, because it is a reading of everything above it: the
            # findings this scan wrote, the risks they were scored into, and
            # the routes correlation found between them.
            await self._record_posture(session, org_id, scan, observed_at)
        else:
            # What today's rules would have raised against that capture,
            # reported as a number without being written down as fact --
            # counted the same way a real scan counts, so the two are
            # comparable in the column that shows them side by side.
            finding_count = await self._would_be_open_count(
                session, org_id, report, id_map
            )

        scan.finding_count = finding_count
        if finalize:
            # Replay owns its own ending: it is one task rather than a set of
            # steps, so nothing else is going to write this. A step-driven scan
            # passes False and the orchestrator derives the same fields from the
            # steps -- two writers for one fact is how a scan ends up COMPLETED
            # with a step still running.
            scan.completed_at = datetime.now(UTC)
            scan.status = ScanStatus.PARTIAL if degraded else ScanStatus.COMPLETED
            scan.lease_until = None
        await session.commit()

        log.info(
            "scan.evaluated",
            scan_id=str(scan.id),
            # Not the scan's status. A step-driven scan is still running when
            # this line is written -- the orchestrator settles it afterwards --
            # so reporting ``scan.status`` here printed CALCULATING_RISK beside
            # the word "completed" and invited exactly the wrong conclusion.
            finalized=finalize,
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
        scope = self._asset_scope(account_ids, connection_id)
        if scope is None:
            return {}
        rows = (
            (
                await session.execute(
                    select(
                        ResourceRecord.provider_resource_id, ResourceRecord.id
                    ).where(ResourceRecord.organization_id == org_id, scope)
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
    async def _snapshots_of(
        self, session: AsyncSession, org_id: UUID, scan_id: UUID
    ) -> list[CloudSnapshot]:
        """Every capture stored under one scan, oldest first.

        Scoped by organization as well as by scan. The id arrives on a scan row
        rather than from a request, but a tenant boundary enforced only where
        input is untrusted is one nobody can reason about.
        """
        return list(
            (
                await session.execute(
                    select(CloudSnapshot)
                    .where(
                        CloudSnapshot.scan_id == scan_id,
                        CloudSnapshot.organization_id == org_id,
                    )
                    .order_by(CloudSnapshot.created_at)
                )
            )
            .scalars()
            .all()
        )

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

    async def _restore_directory(
        self,
        session: AsyncSession,
        org_id: UUID,
        row: CloudSnapshot,
        *,
        check_freshness: bool = False,
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

        # Skipped when a scan is reading its own captures: they were taken
        # moments ago and are the newest by construction, so the query would be
        # a round trip to confirm what the caller already knows.
        newest = (
            (
                await session.execute(
                    select(CloudSnapshot.id)
                    .where(
                        CloudSnapshot.organization_id == org_id,
                        CloudSnapshot.connection_id == connection.id,
                        CloudSnapshot.cloud_account_id.is_(None),
                    )
                    .order_by(
                        CloudSnapshot.created_at.desc(), CloudSnapshot.id.desc()
                    )
                    .limit(1)
                )
            ).scalar_one_or_none()
            if check_freshness
            else row.id
        )

        snapshot = RawSnapshot.from_json(
            await _rebuild_capture(session, org_id, row)
        )
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
            if category.value in snapshot.errors:
                snapshot.errors[category.value] = (
                    f"{explanation} (underlying error: {snapshot.errors[category.value]})"
                )
            # And every gap underneath it. ``errors`` is what the scan banner
            # reads; ``gaps`` is what a rule quotes when it reports UNKNOWN.
            # Rewriting only the first would leave the customer a useful
            # sentence on the banner and a bare "Forbidden" against the check
            # that actually lost its verdict -- which is the one they clicked
            # into to find out why.
            for key in get_connector(account.provider).evidence_keys_in(category):
                if key.value in snapshot.gaps:
                    snapshot.gaps[key.value] = (
                        f"{explanation} (underlying error: {snapshot.gaps[key.value]})"
                    )

        if behind:
            log.info(
                "scan.role_behind",
                connection_id=str(connection.id),
                deployed=connection.role_version,
                # ``.value``, because the keys are a StrEnum now and a log line
                # reading "[<EvidenceCategory.RESOURCES: 'resources'>]" is
                # noise where a category name was wanted.
                categories=sorted(category.value for category in behind),
            )

    # ------------------------------------------------------------------ state
    async def _set_status(
        self, session: AsyncSession, scan: Scan, status: ScanStatus
    ) -> None:
        scan.status = status
        # Every phase change is a sign of life, and the phases bracket the two
        # stretches that report nothing while they run: rule evaluation and
        # finding reconciliation. Extending here means the lease covers them
        # without a heartbeat task of its own.
        scan.lease_until = datetime.now(UTC) + timedelta(seconds=Scan.LEASE_SECONDS)
        await session.commit()

    async def _fail(self, session: AsyncSession, scan: Scan, message: str) -> None:
        scan.status = ScanStatus.FAILED
        scan.error_message = message[:2000]
        scan.completed_at = datetime.now(UTC)
        # Terminal, so nothing should reclaim it. Released rather than left to
        # expire, so the reaper's index does not carry finished work.
        scan.lease_until = None
        await session.commit()

    # ------------------------------------------------------------------ scope
    def _asset_scope(
        self, account_ids: list[UUID], connection_id: UUID | None
    ) -> ColumnElement[bool] | None:
        """Which assets this scan is entitled to read and write.

        The one predicate every hot-path query in the pipeline shares, and the
        reason it exists is that they used to share the *organization* instead.
        ``_persist_findings`` read every finding in the tenant, its risk links
        read every link, and ``_persist_relationships`` read the whole edge
        table -- on every scan, including a single-subscription rescan of one
        finding in a tenant of fifty. All three grew with the customer rather
        than with the work, which is the shape that fails first and fails as a
        timeout inside a task with no retry.

        Two scopes, because assets have two. A subscription's assets are keyed
        by account; the tenant's directory assets have no account and are keyed
        by connection. ``None`` when a scan covers neither, which is a scan with
        nothing to do.
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
            return None
        return or_(*scopes)

    def _finding_scope(
        self, account_ids: list[UUID], connection_id: UUID | None
    ) -> ColumnElement[bool]:
        """The same scope, expressed over findings.

        Used with an outer join to ``cloud_resources``. The third arm is not
        decoration: an AGGREGATE rule's finding is about the tenant and carries
        no resource at all, so a scope built only from asset columns would leave
        those findings invisible to the scan that is meant to re-detect or
        resolve them -- and an invisible open finding is one that gets inserted
        again, against a unique index that will not have it.
        """
        assets = self._asset_scope(account_ids, connection_id)
        aggregate = Finding.resource_id.is_(None)
        return aggregate if assets is None else or_(assets, aggregate)

    # -------------------------------------------------------------- resources
    async def _persist_resources(
        self,
        session: AsyncSession,
        org_id: UUID,
        account_state: list[tuple[CloudAccount, NormalizedState]],
        observed_at: datetime,
        *,
        directory: tuple[CloudConnection, NormalizedState] | None = None,
        scan_id: UUID | None = None,
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
        scope = self._asset_scope(
            account_ids, directory[0].id if directory is not None else None
        )
        if scope is None:
            return {}

        existing = {
            (row.cloud_account_id, row.provider_resource_id): row
            for row in (
                await session.execute(
                    select(ResourceRecord).where(
                        ResourceRecord.organization_id == org_id, scope
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
        # (row, what changed, before, after). Collected rather than written
        # inline because the rows are not flushed yet: a change event needs the
        # asset's primary key, and a new asset has none until the flush below.
        changes: list[tuple[ResourceRecord, AssetChange, str | None, str | None]] = []

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
                changes.append((row, AssetChange.APPEARED, None, None))
            else:
                # Everything the risk engine multiplies a finding by, and
                # nothing else. Diffing whole payloads would produce a feed
                # nobody can read, and the drift that matters already arrives
                # as a finding.
                for change, before, after in (
                    (
                        AssetChange.EXPOSURE_CHANGED,
                        row.public_exposure,
                        resource.public_exposure,
                    ),
                    (
                        AssetChange.SENSITIVITY_CHANGED,
                        row.data_sensitivity,
                        resource.data_sensitivity,
                    ),
                    (
                        AssetChange.CRITICALITY_CHANGED,
                        row.criticality,
                        resource.criticality,
                    ),
                ):
                    if before != after:
                        changes.append((row, change, before.value, after.value))
                if row.absent_since is not None:
                    # It came back. One asset that vanished for a week, not two
                    # assets -- which is why the row was kept rather than
                    # deleted when it went.
                    changes.append((row, AssetChange.APPEARED, None, None))
            row.absent_since = None

            row.resource_type = resource.resource_type
            row.name = resource.name
            row.region = resource.region
            row.environment = resource.environment
            row.criticality = resource.criticality
            row.data_sensitivity = resource.data_sensitivity
            row.public_exposure = resource.public_exposure
            # Written beside the values they explain, never separately. A row
            # holding CRITICAL with a source of 'none' would be a claim with no
            # author, which is worse than no source at all.
            row.criticality_source = resource.criticality_source
            row.data_sensitivity_source = resource.data_sensitivity_source
            row.environment_source = resource.environment_source
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

        # Assets this scan covered and did not find. Recorded as a transition
        # rather than left to be inferred: an absence derived from
        # ``last_seen_at`` would need a scan cadence nobody records, and would
        # re-report itself on every scan afterwards.
        for row in existing.values():
            if row.provider_resource_id in touched or row.absent_since is not None:
                continue
            row.absent_since = now
            changes.append((row, AssetChange.DISAPPEARED, None, None))

        # One flush assigns every pending primary key.
        await session.flush()
        for row, change, before, after in changes:
            session.add(
                AssetChangeEvent(
                    organization_id=org_id,
                    resource_id=row.id,
                    scan_id=scan_id,
                    change=change,
                    previous_value=before,
                    current_value=after,
                    observed_at=now,
                )
            )
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

        # Only the edges that could collide with the ones being written. This
        # used to read the organization's entire relationship table on every
        # scan, so the cost of writing one subscription's edges grew with every
        # other subscription the customer owned -- and a rescan of a single
        # finding paid the whole tenant's bill.
        sources = {source for source, _rel, _target in wanted}
        existing = {
            (r.source_resource_id, RelationshipType(r.relationship_type), r.target_resource_id)
            for r in (
                await session.execute(
                    select(ResourceRelationship).where(
                        ResourceRelationship.organization_id == org_id,
                        ResourceRelationship.source_resource_id.in_(sources),
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
        *,
        account_ids: list[UUID],
        connection_id: UUID | None,
        account_of: dict[str, UUID],
    ) -> int:
        """Write this scan's failures as findings, and score each one.

        Everything the loop needs is read up front. It used to issue a lookup
        per failure for the finding, another for its risk link and a third for
        the risk itself, plus a flush each time round -- four round trips per
        failing check, which a tenant-wide scan multiplies by every subscription
        it covers. The reads are two queries whatever the size of the tenant,
        and the writes flush twice.

        Two queries, but no longer two queries over the whole tenant. They
        selected every finding and every risk link the organization had, so the
        cost of writing one subscription's findings rose with every other
        subscription the customer owned. Scoped to what this scan covers, they
        grow with the work instead.
        """
        now = observed_at
        scope = self._finding_scope(account_ids, connection_id)

        # Identity is (organization, rule, resource), so that is the key.
        # Outer-joined rather than filtered on ``Finding``: the scope is
        # expressed over the asset a finding is about, and an AGGREGATE finding
        # has no asset -- it needs to be in hand all the same, or the scan would
        # insert a second row for a key the unique index already holds.
        in_scope = (
            select(Finding)
            .outerjoin(ResourceRecord, ResourceRecord.id == Finding.resource_id)
            .where(Finding.organization_id == org_id, scope)
        )
        existing_findings = {
            (f.rule_id, f.resource_id): f
            for f in (await session.execute(in_scope)).scalars().all()
        }
        risk_by_finding = {
            link.finding_id: link.risk_id
            for link in (
                await session.execute(
                    select(RiskFinding).where(
                        RiskFinding.organization_id == org_id,
                        RiskFinding.finding_id.in_(
                            [f.id for f in existing_findings.values()]
                        ),
                    )
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
        pending: dict[tuple[str, UUID | None], PendingFinding] = {}
        # (finding, what happened, the status it left, the sentence). Held
        # until the flush, because a finding raised by this scan has no primary
        # key for an event to point at until then.
        events: list[tuple[Finding, FindingEvent, FindingStatus | None, str]] = []

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
                events.append((finding, FindingEvent.DETECTED, None, title))

            elif finding.status in {FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE}:
                # It came back. Reopen rather than leaving a stale RESOLVED --
                # a regression is not a historical record.
                events.append(
                    (
                        finding,
                        FindingEvent.REOPENED,
                        finding.status,
                        "The check failed again after being resolved.",
                    )
                )
                finding.status = FindingStatus.OPEN
                finding.resolved_at = None
                finding.resolved_by_scan_id = None

            finding.scan_id = scan.id
            finding.severity = rule.severity
            finding.title = title
            finding.description = description
            finding.evidence = self._evidence_with_controls(failure.result)
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
                    # The rule's tag unless this instance earned a lower one.
                    exploitability=rule.effective_exploitability(failure.result),
                )
            )
            finding.risk_score = scored.score
            pending[key] = (finding, rule, resource, scored, title)

        # Counted per finding, not per failure: one row is one finding however
        # many times the rules named it.
        open_count = sum(1 for entry in pending.values() if entry[0].status.is_open)

        # One flush for every new finding, rather than one per finding.
        await session.flush()

        await self._link_evidence(session, org_id, scan, pending, account_of)

        for finding, event, previous, detail in events:
            session.add(
                FindingEventRecord(
                    organization_id=org_id,
                    finding_id=finding.id,
                    scan_id=scan.id,
                    event=event,
                    previous_status=previous,
                    current_status=finding.status,
                    detail=detail,
                    observed_at=now,
                )
            )

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

        # Failures from a rule that groups them: one risk for the rule, with
        # every failing asset as a member.
        grouped: dict[str, list[PendingFinding]] = {}
        for entry in pending.values():
            if entry[1].risk_grouping is not None:
                grouped.setdefault(entry[1].rule_id, []).append(entry)

        # Looked up by key rather than reached through the junction. A group
        # risk outlives every one of its members closing, so the scan that
        # reopens one has to find the existing row -- and inserting a second
        # for a key the unique index already holds would fail the whole scan.
        group_risks: dict[str, Risk] = {}
        if grouped:
            group_risks = {
                risk.scenario_key: risk
                for risk in (
                    await session.execute(
                        select(Risk).where(
                            Risk.organization_id == org_id,
                            Risk.scenario_key.in_(
                                [self._group_key(rule_id) for rule_id in grouped]
                            ),
                        )
                    )
                )
                .scalars()
                .all()
                if risk.scenario_key
            }

        # Risks whose junction row does not exist yet. The link needs both ids,
        # so it is written after the risks are flushed rather than inside the
        # loop -- ``RiskFinding`` has no ORM relationships, only the two columns.
        unlinked: list[tuple[Risk, Finding]] = []
        for finding, rule, resource, scored, title in pending.values():
            if rule.risk_grouping is not None:
                continue
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

        for rule_id, members in grouped.items():
            unlinked.extend(
                await self._upsert_group_risk(
                    session,
                    org_id,
                    members,
                    existing=group_risks.get(self._group_key(rule_id)),
                    linked_risks=risks,
                    risk_by_finding=risk_by_finding,
                )
            )

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

    @staticmethod
    def _group_key(rule_id: str) -> str:
        """What makes a rule's group risk the same risk between scans.

        Reuses ``scenario_key`` -- the column that already answers "what
        identifies a risk that is not identified by a single finding" -- and
        namespaces itself for the same reason the escalation template does: the
        unique index covers (organization, key) across every kind.
        """
        return f"group:{rule_id}"

    async def _upsert_group_risk(
        self,
        session: AsyncSession,
        org_id: UUID,
        members: list[PendingFinding],
        *,
        existing: Risk | None,
        linked_risks: dict[UUID, Risk],
        risk_by_finding: dict[UUID, UUID],
    ) -> list[tuple[Risk, Finding]]:
        """One risk for a rule that groups, with every failing asset in it.

        Scored as the worst member, exactly as a scenario is: a group cannot be
        less serious than the most serious thing in it, and it must not be more
        serious either -- forty accounts missing MFA is one policy that was
        never written, not forty times the problem. Summing them would be the
        arithmetic that pins a security score at zero over a single mistake,
        which is the reason this exists.

        The breakdown is the worst member's, so "why is this 84?" still names
        real components measured on a real asset rather than an average of
        forty. What the group adds is the count, which is in the title.

        Returns the (risk, finding) pairs still needing a junction row.
        """
        rule = members[0][1]
        grouping = rule.risk_grouping
        assert grouping is not None  # only rules that declare one reach here

        worst_finding, _, worst_resource, worst_scored, _ = max(
            members, key=lambda entry: entry[3].score
        )

        # Risks each member used to have to itself, from before this rule
        # grouped -- or from before the declaration was added. Deleted rather
        # than resolved, which is the opposite of what happens to a route that
        # closes, and for the opposite reason: nothing here ended. The same
        # accounts are still failing the same check, and a resolved duplicate
        # would show a customer a fixed MFA risk sitting beside an open one for
        # the same people. The findings keep every event they ever had.
        group_key = self._group_key(rule.rule_id)
        for finding, *_ in members:
            superseded = risk_by_finding.get(finding.id)
            if superseded is None:
                continue
            risk = linked_risks.get(superseded)
            if risk is not None and risk.scenario_key != group_key:
                await session.delete(risk)
                linked_risks.pop(superseded, None)
                risk_by_finding.pop(finding.id, None)

        risk = self._upsert_risk(
            session,
            org_id,
            worst_finding,
            rule,
            worst_resource,
            worst_scored,
            grouping.title(len(members)),
            existing,
        )
        risk.scenario_key = group_key

        # A risk being inserted has no id yet, so every member needs a link.
        # An existing one keeps the links it already has.
        return [
            (risk, finding)
            for finding, *_ in members
            if risk.id is None or risk_by_finding.get(finding.id) != risk.id
        ]

    async def _link_evidence(
        self,
        session: AsyncSession,
        org_id: UUID,
        scan: Scan,
        pending: dict[tuple[str, UUID | None], PendingFinding],
        account_of: dict[str, UUID],
    ) -> None:
        """Cite the readings each finding rests on.

        The finding already carries an excerpt of its evidence. This records
        where that came from: which listing, taken when, under which
        permissions, and the hash of the payload. An excerpt cannot be
        re-verified; a citation can.

        **Read from the scan that collected, not the scan that concluded.** A
        replay evaluates a capture some earlier scan took and writes no evidence
        rows of its own, so resolving against ``scan.id`` would find nothing and
        delete every link it touched -- silently, on the path that exists to
        verify fixes. ``replay_of_scan_id`` is the scan that did the reading.

        Rewritten rather than accumulated. A citation describes what a finding
        rests on *now*; what it used to rest on is ``finding_events``' job.
        """
        if not pending:
            return

        source_scan_id = scan.replay_of_scan_id or scan.id
        wanted = {
            key.value
            for _finding, rule, *_rest in pending.values()
            for key in rule.requires_evidence
        }
        if not wanted:
            # Every rule that failed reads nothing it declared. Nothing to cite,
            # and no rows to clear -- a finding cannot have acquired a citation
            # for a key its rule never asked for.
            return

        rows = (
            (
                await session.execute(
                    select(Evidence).where(
                        Evidence.organization_id == org_id,
                        Evidence.scan_id == source_scan_id,
                        Evidence.evidence_key.in_(wanted),
                    )
                )
            )
            .scalars()
            .all()
        )
        # (account, key) -> reading. The directory's readings are filed under
        # None, which is how ``Evidence`` records them: a tenant-wide read did
        # not happen *in* a subscription, and naming one would attribute it to a
        # scope that is fine.
        by_scope: dict[tuple[UUID | None, str], Evidence] = {
            (row.cloud_account_id, row.evidence_key): row for row in rows
        }

        finding_ids = [finding.id for finding, *_ in pending.values()]
        await session.execute(
            delete(FindingEvidence).where(
                FindingEvidence.organization_id == org_id,
                FindingEvidence.finding_id.in_(finding_ids),
            )
        )

        for finding, rule, resource, *_rest in pending.values():
            account_id = (
                account_of.get(resource.provider_resource_id) if resource else None
            )
            for key in rule.requires_evidence:
                # The asset's own subscription first, then the directory. Both
                # arms are needed rather than one: an aggregate rule reads only
                # tenant-wide listings, while a per-resource rule may read a
                # directory listing beside its subscription's.
                row = by_scope.get((account_id, key.value)) or by_scope.get(
                    (None, key.value)
                )
                if row is None:
                    # No reading of this key reached this scope. That is not an
                    # error and not a gap to record here -- the rule degrades to
                    # UNKNOWN through ``collection_errors`` and never becomes a
                    # finding, so a FAIL citing a key with no reading means the
                    # rule read something it did not declare, which the evidence
                    # tests catch at their own layer.
                    continue
                session.add(
                    FindingEvidence(
                        organization_id=org_id,
                        finding_id=finding.id,
                        evidence_key=row.evidence_key,
                        evidence_id=row.id,
                        content_hash=row.content_hash,
                        # The provider's read time, which for a carried reading
                        # is older than this scan. Copied rather than joined so
                        # the age survives the reading's deletion.
                        collected_at=row.collected_at,
                        source_scan_id=row.scan_id,
                    )
                )

    @staticmethod
    def _evidence_with_controls(result: RuleResult) -> dict:
        """The rule's evidence, plus why its score was lowered.

        Merged here rather than left to each rule, so the key cannot be spelled
        two ways by two authors -- and so a customer asking why an
        administrator without MFA is not scored as a Critical has the answer on
        the finding rather than in a scoring formula they cannot see.
        """
        evidence = dict(result.evidence or {})
        if result.controls:
            evidence["compensating_controls"] = [
                control.as_evidence() for control in result.controls
            ]
        return evidence

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
            "known_risk_level": scored.known_level,
            "severity": rule.severity.value,
            "asset_criticality": resource.criticality if resource else Level.UNKNOWN,
            "data_sensitivity": resource.data_sensitivity if resource else Level.UNKNOWN,
            "internet_exposure": resource.public_exposure if resource else Level.UNKNOWN,
            # From the scored inputs, not from the rule: the two differ whenever
            # a result stepped its own exploitability down, and reading the
            # class tag here would show a number the score was not computed
            # from on the one page that exists to explain the score.
            "exploitability": scored.inputs.exploitability,
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

    # ---------------------------------------------------------------- history
    async def _record_posture(
        self, session: AsyncSession, org_id: UUID, scan: Scan, observed_at: datetime
    ) -> None:
        """Write down what the posture was, so movement becomes measurable.

        Only a scan that observed something reaches here -- a replay of a
        superseded capture reports what today's rules would have found and
        changes nothing, so recording an entry for it would make the line move
        on a day nobody looked at the environment.

        Stamped with when the provider was *read*. For a live scan that is now;
        for a replay of the newest capture it is when that capture was taken,
        and plotting either on write time would date the evidence wrongly.

        One entry per scan, corrected rather than duplicated if ANALYZE runs
        twice: a retried step is the same reading, and a second row would show
        as real movement in posture.
        """
        counts = await self._posture_counts(session, org_id)
        entry = (
            await session.execute(
                select(RiskHistory).where(RiskHistory.scan_id == scan.id)
            )
        ).scalar_one_or_none()

        if entry is None:
            entry = RiskHistory(organization_id=org_id, scan_id=scan.id)
            session.add(entry)

        entry.observed_at = observed_at
        entry.security_score = counts["security_score"]
        entry.open_finding_count = counts["open_finding_count"]
        entry.findings_by_severity = counts["findings_by_severity"]
        entry.risk_bands = counts["risk_bands"]
        entry.attack_path_count = counts["attack_path_count"]
        await session.commit()

    async def _posture_counts(self, session: AsyncSession, org_id: UUID) -> dict:
        """The numbers as they stand right now, for one organization.

        Computed the same way the dashboard computes them, and stored rather
        than recomputed later for the reason a time series exists at all: a
        finding reclassified next month must not silently rewrite what last
        month's posture was.
        """
        open_statuses = [FindingStatus.OPEN, FindingStatus.IN_PROGRESS]

        severity_rows = (
            await session.execute(
                select(Finding.severity, func.count())
                .where(
                    Finding.organization_id == org_id,
                    Finding.status.in_(open_statuses),
                )
                .group_by(Finding.severity)
            )
        ).all()

        # Finding risks only, exactly as the security score counts them: a
        # scenario groups findings already counted here, and including it would
        # charge the customer twice for one problem.
        #
        # Counted distinctly, because the join fans a risk out across its
        # members. A rule that groups its findings has one risk with forty of
        # them, and counting join rows would deduct forty times for the one
        # problem grouping exists to state once.
        band_rows = (
            await session.execute(
                select(
                    Risk.risk_level,
                    func.coalesce(Risk.known_risk_level, Risk.risk_level),
                    func.count(func.distinct(Risk.id)),
                )
                .join(RiskFinding, RiskFinding.risk_id == Risk.id)
                .join(Finding, Finding.id == RiskFinding.finding_id)
                .where(
                    Risk.organization_id == org_id,
                    Risk.kind == RiskKind.FINDING,
                    Finding.status.in_(open_statuses),
                )
                .group_by(
                    Risk.risk_level,
                    func.coalesce(Risk.known_risk_level, Risk.risk_level),
                )
            )
        ).all()

        paths = (
            await session.execute(
                select(func.count())
                .select_from(Risk)
                .where(
                    Risk.organization_id == org_id,
                    Risk.kind == RiskKind.ATTACK_PATH,
                    Risk.status != RiskStatus.RESOLVED,
                )
            )
        ).scalar_one()

        bands: dict[Level, int] = {}
        open_levels: list[Level] = []
        for level, known, count in band_rows:
            bands[Level(level)] = bands.get(Level(level), 0) + int(count)
            open_levels.extend([Level(known)] * int(count))

        return {
            "security_score": default_scorer.security_score(open_levels),
            # Findings, from the findings. It used to be the width of the band
            # query, which was the same number only while every risk had
            # exactly one member.
            "open_finding_count": sum(int(count) for _, count in severity_rows),
            "findings_by_severity": {
                str(severity): int(count) for severity, count in severity_rows
            },
            "risk_bands": {level.value: count for level, count in bands.items()},
            "attack_path_count": int(paths),
        }

    # ------------------------------------------------------------ correlation
    async def _correlate_paths(
        self,
        session: AsyncSession,
        org_id: UUID,
        scan: Scan,
        merged: NormalizedState,
        id_map: dict[str, UUID],
    ) -> None:
        """Turn each route through this environment into one risk.

        Five findings across a jump box, an identity and a storage account rank
        by severity and get worked top-down, which is the right order for "what
        is wrong" and the wrong one for "what is wrong together". The same five
        as a route rank by how few hops separate the internet from customer
        data, and name the one change that severs it.

        **Only where the route has at least one failing check on it.** A path
        with nothing misconfigured along it is architecture rather than a
        mistake, and minting a risk for it would mean inventing a severity for
        something no rule objected to -- the made-up number this engine exists
        to avoid.

        Built from this scan's own normalized state rather than from the
        database, so the route and the findings it groups describe one reading
        of one environment.
        """
        graph = AssetGraph.build(merged.resources, merged.relationships)

        open_findings = {
            (finding.resource_id): finding
            for finding in (
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
            if finding.resource_id is not None
        }

        await self._correlate_template(
            session,
            org_id,
            graph,
            id_map,
            open_findings,
            kind=RiskKind.ATTACK_PATH,
            paths=graph.attack_paths(),
            scan=scan,
        )
        # The second template. A route to an identity that can hand out roles is
        # a different question from a route to data -- not what an attacker
        # reaches, but what they could be given once they arrive -- so it is
        # correlated separately and ranks on its own.
        await self._correlate_template(
            session,
            org_id,
            graph,
            id_map,
            open_findings,
            kind=RiskKind.ESCALATION,
            paths=graph.escalation_chains(),
            scan=scan,
        )
        await session.commit()

    async def _correlate_template(
        self,
        session: AsyncSession,
        org_id: UUID,
        graph: AssetGraph,
        id_map: dict[str, UUID],
        open_findings: dict[UUID, Finding],
        *,
        kind: RiskKind,
        paths: list[Path],
        scan: Scan,
    ) -> None:
        """One correlation template: routes of a kind, in and out of existence.

        Shared by both templates rather than written twice, because everything
        except the sentence and the score is the same discipline -- a route with
        no failing check on it creates nothing, a route that closes is resolved
        rather than deleted, and a route seen again keeps the risk it already
        had.
        """
        existing = {
            risk.scenario_key: risk
            for risk in (
                await session.execute(
                    select(Risk).where(
                        Risk.organization_id == org_id,
                        Risk.kind == kind,
                    )
                )
            )
            .scalars()
            .all()
            if risk.scenario_key
        }

        seen: set[str] = set()
        for path in paths:
            key = self._scenario_key(kind, path)
            members = self._members_on(path, open_findings, id_map)
            if not members:
                # Nothing on this route is misconfigured. Real reach, and not a
                # finding -- it stays on the attack-paths page and creates no
                # risk here.
                continue

            seen.add(key)
            # What is at stake at the far end. For a route to data that is the
            # data; for an escalation it is the most sensitive thing under the
            # scope being escalated over, because that is what the escalation
            # would be an escalation *to*. Read from the graph rather than
            # assumed, and UNKNOWN where the scope holds nothing CloudGuard can
            # put a level on.
            target_sensitivity = (
                path.target.data_sensitivity
                if kind is RiskKind.ATTACK_PATH
                else self._sensitivity_under(graph, path.target)
            )
            scored = default_scorer.scenario_score(
                [float(m.risk_score or 0) for m in members],
                hops=path.hops,
                entry_exposure=path.entry.public_exposure,
                target_sensitivity=target_sensitivity,
            )
            risk = existing.get(key)
            if risk is None:
                risk = Risk(
                    organization_id=org_id,
                    kind=kind,
                    scenario_key=key,
                )
                session.add(risk)

            step = path.cheapest_break()
            if kind is RiskKind.ATTACK_PATH:
                risk.title = f"{path.entry.name} can reach {path.target.name}"
                risk.description = (
                    f"{path.entry.name} is reachable from the internet and, in "
                    f"{path.hops} steps, reaches {path.target.name}. "
                    + (f"Severing it: {step.describe()}." if step else "")
                )
            else:
                risk.title = (
                    f"{path.entry.name} leads to control of {path.target.name}"
                )
                risk.description = (
                    f"{path.entry.name} is reachable from the internet and, in "
                    f"{path.hops} steps, reaches an identity that can assign "
                    f"roles over {path.target.name} -- so whatever it holds "
                    "today is not the limit of what it could hold. "
                    + (f"Severing it: {step.describe()}." if step else "")
                )
            risk.path = [
                {
                    "source": s.source.name,
                    "source_id": s.source.provider_resource_id,
                    "relationship": s.relationship.value,
                    "target": s.target.name,
                    "target_id": s.target.provider_resource_id,
                    "description": s.describe(),
                }
                for s in path.steps
            ]
            risk.risk_score = scored.score
            risk.risk_level = scored.level
            # None, and deliberately. A scenario is a statement about a route
            # rather than about one asset's context, and it never reaches the
            # org security score -- the findings it groups are already counted
            # there. A second band for it would be a number nobody claimed.
            risk.known_risk_level = scored.known_level
            risk.severity = Severity.HIGH.value
            risk.asset_criticality = path.target.criticality
            risk.data_sensitivity = target_sensitivity
            risk.internet_exposure = path.entry.public_exposure
            risk.exploitability = 0
            risk.business_impact = scored.business_impact
            risk.score_breakdown = scored.breakdown
            risk.status = RiskStatus.OPEN
            risk.resolved_at = None
            # Which reading saw it. Written on every observation rather than
            # only at creation: the useful question about a route is not when it
            # first appeared but whether anything has looked since, and a value
            # frozen at creation would answer the first while looking like the
            # second.
            risk.observed_scan_id = scan.id

            await session.flush()
            await self._link_members(session, org_id, risk, members)

        # Routes that are gone. Resolved rather than deleted: a scenario that
        # was closed is the record of a fix, exactly as a resolved finding is,
        # and deleting it would erase the evidence that the remediation worked.
        now = datetime.now(UTC)
        for key, risk in existing.items():
            if key not in seen and risk.status != RiskStatus.RESOLVED:
                risk.status = RiskStatus.RESOLVED
                risk.resolved_at = now

    @staticmethod
    def _scenario_key(kind: RiskKind, path: Path) -> str:
        """What makes a route the same route between scans.

        Namespaced per template, except for attack paths, which keep the bare
        form they were written with. The unique index covers (organization,
        key) across every kind, so a second template needs its own namespace --
        and re-keying the first would orphan every scenario risk a customer
        already has, resolving them all and raising identical new ones with no
        history.
        """
        ends = f"{path.entry.provider_resource_id}->{path.target.provider_resource_id}"
        return ends if kind is RiskKind.ATTACK_PATH else f"{kind.value.lower()}:{ends}"

    @staticmethod
    def _sensitivity_under(graph: AssetGraph, scope: CloudResource) -> Level:
        """The most sensitive thing a scope holds.

        What an escalation over that scope would reach. Taken over known levels
        only: an UNKNOWN is CloudGuard failing to work out a sensitivity, and
        letting it win here would score a scope full of unclassified assets
        above one holding a database everyone agrees is critical.
        """
        levels = [
            asset.data_sensitivity
            for asset in graph.contained_by(scope.provider_resource_id)
            if asset.data_sensitivity.is_known
        ]
        return max(levels, key=lambda level: level.rank, default=Level.UNKNOWN)

    def _members_on(
        self,
        path: "Path",
        open_findings: dict[UUID, Finding],
        id_map: dict[str, UUID],
    ) -> list[Finding]:
        """The open findings sitting on any asset this route passes through.

        Every node, not just the ends. A route is only as real as the weakest
        thing along it, and the misconfiguration that makes it walkable is
        frequently in the middle -- the over-broad role assignment rather than
        the exposed host or the sensitive store.
        """
        node_ids = {path.entry.provider_resource_id, path.target.provider_resource_id}
        for step in path.steps:
            node_ids.add(step.source.provider_resource_id)
            node_ids.add(step.target.provider_resource_id)

        members: list[Finding] = []
        for provider_id in node_ids:
            resource_uuid = id_map.get(provider_id)
            finding = open_findings.get(resource_uuid) if resource_uuid else None
            if finding is not None:
                members.append(finding)
        return members

    async def _link_members(
        self, session: AsyncSession, org_id: UUID, risk: Risk, members: list[Finding]
    ) -> None:
        """Join a scenario to the findings it is made of.

        The junction has always allowed this -- ``RiskFinding`` was built as a
        junction precisely so several findings could become one risk later
        without a migration. This is that later.
        """
        linked = {
            link.finding_id
            for link in (
                await session.execute(
                    select(RiskFinding).where(RiskFinding.risk_id == risk.id)
                )
            )
            .scalars()
            .all()
        }
        for member in members:
            if member.id not in linked:
                session.add(
                    RiskFinding(
                        risk_id=risk.id,
                        finding_id=member.id,
                        organization_id=org_id,
                    )
                )

    # ----------------------------------------------------------- verification
    async def _verify_remediations(
        self,
        session: AsyncSession,
        org_id: UUID,
        scan: Scan,
        report: EvaluationReport,
        id_map: dict[str, UUID],
        *,
        account_ids: list[UUID],
        connection_id: UUID | None,
    ) -> None:
        """Auto-resolve findings this scan proved fixed.

        The scan result *is* the verification. A finding resolves only on an
        explicit PASS -- an UNKNOWN this time round leaves it open, because
        failing to look is not the same as looking and finding nothing.

        Scoped to what this scan actually read, which is a correctness point as
        much as a cost one. Unscoped, a rescan of one subscription loaded every
        open finding in the tenant and compared them against its own passes --
        harmless only because a key from another subscription could not match.
        The scope says the intent instead of relying on that.
        """
        passed: set[tuple[str, UUID | None]] = {
            (rule_id, id_map.get(provider_id) if provider_id else None)
            for rule_id, provider_id in report.passes
        }
        now = datetime.now(UTC)
        # Settled first, and regardless of whether anything passed. A scan that
        # proves nothing is still an observation: it is how a claimed fix that
        # did not work eventually gets told so, and how one CloudGuard cannot
        # see gets called insufficient evidence rather than left in silence.
        await self._settle_verifications(
            session,
            org_id,
            scan,
            report,
            id_map,
            now=now,
            account_ids=account_ids,
            connection_id=connection_id,
        )

        if not passed:
            await session.commit()
            return
        open_findings = (
            (
                await session.execute(
                    select(Finding)
                    .outerjoin(ResourceRecord, ResourceRecord.id == Finding.resource_id)
                    .where(
                        Finding.organization_id == org_id,
                        Finding.status.in_(
                            [FindingStatus.OPEN, FindingStatus.IN_PROGRESS]
                        ),
                        self._finding_scope(account_ids, connection_id),
                    )
                )
            )
            .scalars()
            .all()
        )

        resolved = [
            finding
            for finding in open_findings
            if (finding.rule_id, finding.resource_id) in passed
        ]
        if not resolved:
            # Nothing to close, but the verifications settled above are still
            # this scan's work. Returning without committing would throw away
            # the attempt it just spent, and the customer would be told nothing
            # for a scan that did look.
            await session.commit()
            return

        # Both lookups batched. They ran inside the loop -- one statement for the
        # risk link and another for the risk -- so proving twenty fixes cost
        # forty round trips, on the one path the product is sold on.
        links = (
            (
                await session.execute(
                    select(RiskFinding).where(
                        RiskFinding.organization_id == org_id,
                        RiskFinding.finding_id.in_([f.id for f in resolved]),
                    )
                )
            )
            .scalars()
            .all()
        )
        risks = {
            risk.id: risk
            for risk in (
                await session.execute(
                    select(Risk).where(Risk.id.in_([link.risk_id for link in links]))
                )
            )
            .scalars()
            .all()
        } if links else {}

        for finding in resolved:
            session.add(
                FindingEventRecord(
                    organization_id=org_id,
                    finding_id=finding.id,
                    scan_id=scan.id,
                    event=FindingEvent.RESOLVED,
                    previous_status=finding.status,
                    current_status=FindingStatus.RESOLVED,
                    detail=(
                        "A scan observed the check passing on the same asset, "
                        "so CloudGuard closed it."
                    ),
                    observed_at=now,
                )
            )
            finding.status = FindingStatus.RESOLVED
            finding.resolved_at = now
            finding.resolved_by_scan_id = scan.id
            log.info(
                "finding.auto_resolved",
                finding_id=str(finding.id),
                rule_id=finding.rule_id,
                verified_by_scan=str(scan.id),
            )

        # A risk closes when nothing it groups is still open, which for a risk
        # with one finding is the same sentence as before. For a grouped one it
        # is the difference between "the policy is written" and "one of the
        # forty administrators registered an authenticator app": closing on the
        # first member would report the whole problem fixed while thirty-nine
        # accounts still had no second factor.
        #
        # The findings resolved above are excluded by id rather than by status.
        # They are mutated in the session and not yet flushed, so the database
        # still reports them open and would keep every risk alive.
        resolved_ids = [finding.id for finding in resolved]
        risk_ids = {link.risk_id for link in links}
        still_open = set(
            (
                await session.execute(
                    select(RiskFinding.risk_id)
                    .join(Finding, Finding.id == RiskFinding.finding_id)
                    .where(
                        RiskFinding.organization_id == org_id,
                        RiskFinding.risk_id.in_(risk_ids),
                        Finding.status.in_(
                            [FindingStatus.OPEN, FindingStatus.IN_PROGRESS]
                        ),
                        Finding.id.notin_(resolved_ids),
                    )
                )
            )
            .scalars()
            .all()
        )

        for risk_id in risk_ids:
            risk = risks.get(risk_id)
            if risk is not None and risk_id not in still_open:
                risk.status = RiskStatus.RESOLVED
                risk.resolved_at = now

        await session.commit()

    async def _settle_verifications(
        self,
        session: AsyncSession,
        org_id: UUID,
        scan: Scan,
        report: EvaluationReport,
        id_map: dict[str, UUID],
        *,
        now: datetime,
        account_ids: list[UUID],
        connection_id: UUID | None,
    ) -> None:
        """Apply this scan's verdicts to the fixes customers say they have made.

        Every scan does this, not only one started to verify something. A
        nightly scan that happens to pass the rule a customer fixed this morning
        has answered their question, and making them wait for a scan with the
        right label on it would be ceremony.

        Scoped to what this scan read. A verification about a subscription this
        scan never opened has not been observed by it, and spending one of its
        attempts would burn the customer's answer on a scan that never looked.

        A pending verification this scan reached no verdict on **still counts as
        an attempt**, recorded as UNKNOWN. That is the honest reading -- the
        scan covered the scope and produced nothing about that asset, usually
        because the asset is no longer in the environment being returned -- and
        without it a verification whose asset vanished would stay pending for
        ever, with the scheduler starting scans to settle a question that can no
        longer be answered.
        """
        pending = (
            (
                await session.execute(
                    select(RemediationVerification).where(
                        RemediationVerification.organization_id == org_id,
                        RemediationVerification.status == VerificationStatus.PENDING,
                        self._verification_scope(account_ids, connection_id),
                    )
                )
            )
            .scalars()
            .all()
        )
        if not pending:
            return

        observed: dict[tuple[str, UUID | None], RuleState] = {}
        # Least specific first, so an explicit verdict always wins: a rule can
        # produce a gap for one asset and a pass for another in the same run.
        for gap in report.gaps:
            observed[self._verdict_key(gap, id_map)] = RuleState.UNKNOWN
        for failure in report.failures:
            observed[self._verdict_key(failure, id_map)] = RuleState.FAIL
        for rule_id, provider_id in report.passes:
            observed[(rule_id, id_map.get(provider_id) if provider_id else None)] = (
                RuleState.PASS
            )

        for verification in pending:
            state = observed.get(
                (verification.rule_id, verification.resource_id), RuleState.UNKNOWN
            )
            outcome = verification_service.observe(
                verification, state, scan_id=scan.id, now=now
            )
            log.info(
                "verification.observed",
                verification_id=str(verification.id),
                rule_id=verification.rule_id,
                state=state.value,
                attempts=verification.attempts,
                outcome=outcome.value,
            )

    @staticmethod
    def _verdict_key(
        result: EvaluatedResult, id_map: dict[str, UUID]
    ) -> tuple[str, UUID | None]:
        provider_id = (
            result.resource.provider_resource_id if result.resource is not None else None
        )
        return result.rule.rule_id, id_map.get(provider_id) if provider_id else None

    def _verification_scope(
        self, account_ids: list[UUID], connection_id: UUID | None
    ) -> ColumnElement[bool]:
        """The verifications this scan is entitled to have an opinion about."""
        clauses: list[ColumnElement[bool]] = []
        if account_ids:
            clauses.append(RemediationVerification.cloud_account_id.in_(account_ids))
        if connection_id is not None:
            # Directory findings belong to no subscription. They are settled by
            # any scan that read the tenant through the same connection, which
            # is every scan under it.
            clauses.append(
                and_(
                    RemediationVerification.cloud_account_id.is_(None),
                    RemediationVerification.connection_id == connection_id,
                )
            )
        if not clauses:
            return RemediationVerification.id.is_(None)
        return or_(*clauses) if len(clauses) > 1 else clauses[0]

    def _title(self, rule_name: str, resource: CloudResource | None) -> str:
        """Plain language, naming the asset.

        "Internet-exposed RDP on production-vm-01", not "NSG rule ID 94 permits
        0.0.0.0/0:3389" (PRODUCT_SPEC.md section 4).
        """
        if resource is None:
            return rule_name
        return f"{rule_name} — {resource.name}"
