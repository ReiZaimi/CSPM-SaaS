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

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.base import CloudConnector, NormalizedState, RawSnapshot
from app.connectors.registry import get_connector
from app.core.db import service_session
from app.core.enums import (
    FindingStatus,
    Level,
    RelationshipType,
    RiskStatus,
    ScanStatus,
    Severity,
)
from app.core.logging import get_logger
from app.domain.resource import CloudResource
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.models.finding import Finding
from app.models.resource import ResourceRecord, ResourceRelationship
from app.models.risk import Risk, RiskFinding
from app.models.scan import CloudSnapshot, Scan, ScanEvaluationGap, ScanRuleResult
from app.risk.scorer import RiskInputs, ScoredRisk, default_scorer
from app.rules.base import RuleContext, SecurityRule
from app.rules.engine import EvaluationReport, RuleEngine
from app.services.cloud_connections import degraded_categories

log = get_logger(__name__)


class ScanPipeline:
    def __init__(self, scan_id: UUID) -> None:
        self.scan_id = scan_id
        self.engine = RuleEngine()

    async def run(self) -> None:
        """Collect the customer's current state, then evaluate it."""
        async with service_session() as session:
            scan = await session.get(Scan, self.scan_id)
            if scan is None:
                log.error("scan.missing", scan_id=str(self.scan_id))
                return

            account = await session.get(CloudAccount, scan.cloud_account_id)
            if account is None:
                await self._fail(session, scan, "Cloud account no longer exists")
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
                connector = get_connector(
                    account.provider,
                    tenant_id=account.tenant_id,
                    subscription_id=account.subscription_id,
                )
                snapshot = await connector.collect()
                await self._explain_role_drift(session, account, snapshot)

                # Persisted before interpretation, always.
                session.add(
                    CloudSnapshot(
                        organization_id=org_id,
                        cloud_account_id=account.id,
                        scan_id=scan.id,
                        snapshot_version=snapshot.version,
                        data=snapshot.to_json(),
                    )
                )
                scan.collection_errors = dict(snapshot.errors)
                await session.commit()

                await self._evaluate(
                    session,
                    scan,
                    account,
                    connector,
                    snapshot,
                    observed_at=datetime.now(UTC),
                    mutate_findings=True,
                )

                account.last_scan_at = scan.completed_at
                await session.commit()

            except Exception as exc:
                log.exception("scan.failed", scan_id=str(scan.id))
                await session.rollback()
                await self._fail(session, scan, str(exc))

    async def replay(self) -> None:
        """Re-evaluate an earlier scan's stored snapshot against today's rules.

        No collection, no Azure call, no consent required: everything after the
        snapshot is a pure function of it, which is what the raw capture was
        kept for.

        The dangerous case is why ``evaluation_only`` exists. Replaying a
        month-old snapshot that now produces PASS where a finding was FAIL would
        otherwise reach the auto-resolve path and stamp that finding "verified
        fixed" -- on the strength of data collected before anyone was even told
        about it. Nothing was observed, so nothing may be resolved. Only a
        replay of the newest snapshot for the account, which is CloudGuard's
        current picture of that environment, may touch findings at all; every
        older one writes coverage and reports counts, and stops there.
        """
        async with service_session() as session:
            scan = await session.get(Scan, self.scan_id)
            if scan is None:
                log.error("scan.missing", scan_id=str(self.scan_id))
                return

            account = await session.get(CloudAccount, scan.cloud_account_id)
            if account is None:
                await self._fail(session, scan, "Cloud account no longer exists")
                return

            if scan.status == ScanStatus.CANCELLED:
                log.info("scan.cancelled_before_start", scan_id=str(self.scan_id))
                return

            scan.started_at = datetime.now(UTC)
            org_id = scan.organization_id

            try:
                stored = await self._stored_snapshot(session, org_id, scan)
                if stored is None:
                    await self._fail(
                        session,
                        scan,
                        "That scan has no stored snapshot to replay. Snapshots are "
                        "written when collection succeeds, so a scan that failed "
                        "before that point has nothing to re-evaluate.",
                    )
                    return

                snapshot = RawSnapshot.from_json(stored.data)
                newest = await self._newest_snapshot_id(session, org_id, account.id)
                is_current = stored.id == newest

                scan.evaluation_only = not is_current
                scan.collection_errors = dict(snapshot.errors)
                await session.commit()

                connector = get_connector(
                    account.provider,
                    tenant_id=account.tenant_id,
                    subscription_id=account.subscription_id,
                )
                await self._evaluate(
                    session,
                    scan,
                    account,
                    connector,
                    snapshot,
                    # The observation happened when the snapshot was taken.
                    # Stamping findings with the replay time would date
                    # month-old evidence to today.
                    observed_at=stored.created_at,
                    mutate_findings=is_current,
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
        account: CloudAccount,
        connector: CloudConnector,
        snapshot: RawSnapshot,
        *,
        observed_at: datetime,
        mutate_findings: bool,
    ) -> None:
        """Everything downstream of a snapshot: normalize, evaluate, persist.

        Shared verbatim by a fresh scan and a replay, and the sharing is the
        point. If the two paths diverged, a replay would stop being evidence
        about the pipeline a real scan runs.
        """
        org_id = scan.organization_id

        # --- normalize ------------------------------------------------------
        await self._set_status(session, scan, ScanStatus.NORMALIZING)
        state = connector.normalize(snapshot)
        id_map = await self._persist_resources(
            session, org_id, account.id, state, observed_at
        )
        scan.resource_count = len(state.resources)

        # Now the size of the job is known, so progress can be a count
        # rather than a phase name. Committed here so a long evaluation
        # shows a denominator immediately rather than at the end.
        scan.progress_total = len(state.resources)
        scan.progress_done = len(state.resources)
        await session.commit()

        # --- evaluate -------------------------------------------------------
        await self._set_status(session, scan, ScanStatus.EVALUATING)
        context = RuleContext(
            resources=state.resources,
            relationships=self._group_edges(state),
            collection_errors=state.collection_errors,
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
            # reported as a number without being written down as fact.
            finding_count = len(report.failures)

        scan.finding_count = finding_count
        scan.completed_at = datetime.now(UTC)
        scan.status = ScanStatus.PARTIAL if snapshot.errors else ScanStatus.COMPLETED
        await session.commit()

        log.info(
            "scan.completed",
            scan_id=str(scan.id),
            status=scan.status.value,
            resources=scan.resource_count,
            findings=finding_count,
            coverage=round(report.coverage_ratio, 3),
            evaluation_only=scan.evaluation_only,
        )

    # --------------------------------------------------------------- snapshots
    async def _stored_snapshot(
        self, session: AsyncSession, org_id: UUID, scan: Scan
    ) -> CloudSnapshot | None:
        """The snapshot this replay was asked to re-evaluate.

        Scoped by organization as well as scan id: the id arrives on the scan
        row rather than from a request, but a tenant boundary that is only
        enforced where input is untrusted is one nobody can reason about.
        """
        if scan.replay_of_scan_id is None:
            return None
        return (
            await session.execute(
                select(CloudSnapshot).where(
                    CloudSnapshot.scan_id == scan.replay_of_scan_id,
                    CloudSnapshot.organization_id == org_id,
                )
            )
        ).scalar_one_or_none()

    async def _newest_snapshot_id(
        self, session: AsyncSession, org_id: UUID, account_id: UUID
    ) -> UUID | None:
        return (
            await session.execute(
                select(CloudSnapshot.id)
                .where(
                    CloudSnapshot.organization_id == org_id,
                    CloudSnapshot.cloud_account_id == account_id,
                )
                .order_by(CloudSnapshot.created_at.desc(), CloudSnapshot.id.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

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
        account_id: UUID,
        state: NormalizedState,
        observed_at: datetime,
    ) -> dict[str, UUID]:
        """Upsert assets, returning provider id -> database id.

        Resources are updated rather than replaced so ``first_seen_at`` survives
        and a finding keeps pointing at the same asset row across scans.

        ``observed_at`` is when the state was *captured*, not when it was
        processed. The two are the same for a live scan and months apart for a
        replay, and ``last_seen_at`` means nothing if a replay of an old
        snapshot can report a deleted resource as seen today.
        """
        now = observed_at
        existing = {
            row.provider_resource_id: row
            for row in (
                await session.execute(
                    select(ResourceRecord).where(
                        ResourceRecord.organization_id == org_id,
                        ResourceRecord.cloud_account_id == account_id,
                    )
                )
            )
            .scalars()
            .all()
        }

        id_map: dict[str, UUID] = {}
        for resource in state.resources:
            row = existing.get(resource.provider_resource_id)
            if row is None:
                row = ResourceRecord(
                    organization_id=org_id,
                    cloud_account_id=account_id,
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
            # Never moved backwards. A replay carries the capture's own time,
            # which is older than a detection already recorded against a live
            # scan -- and "last seen" going backwards would be a lie in the one
            # direction that matters, making a present resource look stale.
            row.last_seen_at = max(row.last_seen_at or now, now)

        await session.flush()
        for resource in state.resources:
            row = existing.get(resource.provider_resource_id)
            if row is None:
                row = (
                    await session.execute(
                        select(ResourceRecord).where(
                            ResourceRecord.cloud_account_id == account_id,
                            ResourceRecord.provider_resource_id
                            == resource.provider_resource_id,
                        )
                    )
                ).scalar_one()
            id_map[resource.provider_resource_id] = row.id

        await self._persist_relationships(session, org_id, state, id_map)
        await session.commit()
        return id_map

    async def _persist_relationships(
        self,
        session: AsyncSession,
        org_id: UUID,
        state: NormalizedState,
        id_map: dict[str, UUID],
    ) -> None:
        wanted = {
            (id_map[s], rel, id_map[t])
            for s, rel, t in state.relationships
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
        now = observed_at
        open_count = 0

        for failure in report.failures:
            rule = failure.rule
            resource = failure.resource
            resource_uuid = id_map.get(resource.provider_resource_id) if resource else None

            finding = (
                await session.execute(
                    select(Finding).where(
                        Finding.organization_id == org_id,
                        Finding.rule_id == rule.rule_id,
                        Finding.resource_id == resource_uuid,
                    )
                )
            ).scalar_one_or_none()

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
            await session.flush()

            await self._upsert_risk(session, org_id, finding, rule, resource, scored, title)

            if finding.status.is_open:
                open_count += 1

        await session.commit()
        return open_count

    async def _upsert_risk(
        self,
        session: AsyncSession,
        org_id: UUID,
        finding: Finding,
        rule: SecurityRule,
        resource: CloudResource | None,
        scored: ScoredRisk,
        title: str,
    ) -> None:
        """One risk per finding for the MVP, joined through ``risk_findings``.

        Grouping several findings into a single risk later is a change in this
        method, not a migration -- which is exactly why the junction table is
        there from the start (RISK_ENGINE.md section 2).
        """
        link = (
            await session.execute(
                select(RiskFinding).where(RiskFinding.finding_id == finding.id)
            )
        ).scalar_one_or_none()

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

        risk = await session.get(Risk, link.risk_id) if link else None
        if risk is None:
            # Fully populated before the flush: several of these columns are
            # NOT NULL, so an empty insert would never reach the database.
            risk = Risk(organization_id=org_id, **values)
            session.add(risk)
            await session.flush()
            session.add(
                RiskFinding(
                    risk_id=risk.id, finding_id=finding.id, organization_id=org_id
                )
            )
        else:
            for key, value in values.items():
                setattr(risk, key, value)

        if finding.status.is_open:
            risk.status = RiskStatus.OPEN
            risk.resolved_at = None

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
