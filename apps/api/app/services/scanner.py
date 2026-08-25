"""The scan pipeline.

    collect -> snapshot -> normalize -> persist assets -> evaluate
            -> findings -> risks -> verify fixes -> summarize

Two things here are the product, not plumbing:

* **Every scan writes a snapshot** before anything is interpreted, so a scan can
  be re-evaluated later against improved rules.
* **A rescan verifies remediation by itself.** Where a previous scan produced
  FAIL and this one produces PASS, the finding is resolved automatically and
  stamped with the scan that proved it. Nobody clicks "verified"
  (RULE_ENGINE.md section 3).

Runs in the Celery worker, which has no authenticated user, so it uses the
owner connection and scopes every write by the ``organization_id`` taken from
the scan record it was handed — never from client input.
"""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.base import NormalizedState
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
from app.models.finding import Finding
from app.models.resource import ResourceRecord, ResourceRelationship
from app.models.risk import Risk, RiskFinding
from app.models.scan import CloudSnapshot, Scan, ScanEvaluationGap, ScanRuleResult
from app.risk.scorer import RiskInputs, ScoredRisk, default_scorer
from app.rules.base import RuleContext, SecurityRule
from app.rules.engine import EvaluationReport, RuleEngine

log = get_logger(__name__)


class ScanPipeline:
    def __init__(self, scan_id: UUID) -> None:
        self.scan_id = scan_id
        self.engine = RuleEngine()

    async def run(self) -> None:
        async with service_session() as session:
            scan = await session.get(Scan, self.scan_id)
            if scan is None:
                log.error("scan.missing", scan_id=str(self.scan_id))
                return

            account = await session.get(CloudAccount, scan.cloud_account_id)
            if account is None:
                await self._fail(session, scan, "Cloud account no longer exists")
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

                # --- normalize ----------------------------------------------
                await self._set_status(session, scan, ScanStatus.NORMALIZING)
                state = connector.normalize(snapshot)
                id_map = await self._persist_resources(session, org_id, account.id, state)
                scan.resource_count = len(state.resources)

                # --- evaluate -----------------------------------------------
                await self._set_status(session, scan, ScanStatus.EVALUATING)
                context = RuleContext(
                    resources=state.resources,
                    relationships=self._group_edges(state),
                    collection_errors=state.collection_errors,
                )
                report = self.engine.evaluate(context)
                scan.rule_count = report.rules_run

                await self._persist_coverage(session, org_id, scan, report, id_map)

                # --- findings and risks -------------------------------------
                await self._set_status(session, scan, ScanStatus.CALCULATING_RISK)
                finding_count = await self._persist_findings(
                    session, org_id, scan, report, id_map, context
                )
                await self._verify_remediations(session, org_id, scan, report, id_map)

                scan.finding_count = finding_count
                scan.completed_at = datetime.now(UTC)
                scan.status = (
                    ScanStatus.PARTIAL if snapshot.errors else ScanStatus.COMPLETED
                )
                account.last_scan_at = scan.completed_at
                await session.commit()

                log.info(
                    "scan.completed",
                    scan_id=str(scan.id),
                    status=scan.status.value,
                    resources=scan.resource_count,
                    findings=finding_count,
                    coverage=round(report.coverage_ratio, 3),
                )

            except Exception as exc:
                log.exception("scan.failed", scan_id=str(scan.id))
                await session.rollback()
                await self._fail(session, scan, str(exc))

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
    ) -> dict[str, UUID]:
        """Upsert assets, returning provider id -> database id.

        Resources are updated rather than replaced so ``first_seen_at`` survives
        and a finding keeps pointing at the same asset row across scans.
        """
        now = datetime.now(UTC)
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
            row.last_seen_at = now

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
        context: RuleContext,
    ) -> int:
        now = datetime.now(UTC)
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
            finding.last_detected_at = now

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
