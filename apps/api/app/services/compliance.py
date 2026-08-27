"""Compliance coverage: catalogue x rules x this organization's latest scan.

The chain, in the order ROADMAP.md sets out:

    rule -> finding (evidence) -> control (requirement) -> framework

This service walks it backwards -- from a framework's controls to the rules
mapped to them to what those rules found -- and stops there. It produces
evidence attributed to a requirement, never a statement that a requirement is
satisfied in law.

Note where the mappings come from: the ``rules`` table, not the Python
registry. The table is the read-mirror the API already joins findings against,
and a rule removed from the registry keeps its row (disabled) so the controls
it used to answer for do not silently become uncovered.
"""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.compliance.catalog import FRAMEWORKS, Framework, get_framework
from app.compliance.coverage import (
    ControlStatus,
    RuleEvidence,
    coverage_ratio,
    resolve_control_status,
    status_counts,
)
from app.core.enums import FindingStatus, ScanStatus
from app.models.finding import Finding
from app.models.rule import Rule
from app.models.scan import Scan, ScanRuleResult

OPEN_STATUSES = [FindingStatus.OPEN, FindingStatus.IN_PROGRESS]


class _Snapshot:
    """Everything the per-control resolution needs, fetched once.

    Assembled up front because a control-by-control query would be ~50 round
    trips per framework, and every control in every framework draws on the same
    three tables.
    """

    def __init__(
        self,
        rules: list[Rule],
        open_findings: dict[str, int],
        rule_results: dict[str, int],
        has_completed_scan: bool,
    ) -> None:
        self.rules = rules
        self.open_findings = open_findings
        self.rule_results = rule_results
        self.has_completed_scan = has_completed_scan

    def evidence_for(self, framework_id: str, control_id: str) -> list[RuleEvidence]:
        """Every rule claiming to produce evidence toward this control."""
        matched = [
            rule
            for rule in self.rules
            if control_id in (rule.compliance_mappings or {}).get(framework_id, [])
        ]
        return [
            RuleEvidence(
                rule_id=rule.rule_id,
                name=rule.name,
                severity=str(rule.severity),
                open_finding_count=self.open_findings.get(rule.rule_id, 0),
                unknown_count=self.rule_results.get(rule.rule_id, 0),
                evaluated=rule.rule_id in self.rule_results,
            )
            for rule in matched
        ]


async def _snapshot(session: AsyncSession, organization_id: UUID) -> _Snapshot:
    rules = list(
        (await session.execute(select(Rule).where(Rule.enabled.is_(True)))).scalars().all()
    )

    open_rows = (
        await session.execute(
            select(Finding.rule_id, func.count())
            .where(
                Finding.organization_id == organization_id,
                Finding.status.in_(OPEN_STATUSES),
            )
            .group_by(Finding.rule_id)
        )
    ).all()
    open_findings = {rule_id: int(count) for rule_id, count in open_rows}

    last_scan = (
        await session.execute(
            select(Scan)
            .where(
                Scan.organization_id == organization_id,
                Scan.status.in_([ScanStatus.COMPLETED, ScanStatus.PARTIAL]),
            )
            .order_by(Scan.completed_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    # Presence in this dict is "the rule ran"; the value is how often it could
    # not tell. A rule absent from the latest scan is not passing, it is
    # unevaluated -- resolve_control_status treats the two the same way.
    rule_results: dict[str, int] = {}
    if last_scan is not None:
        rows = (
            await session.execute(
                select(ScanRuleResult.rule_id, ScanRuleResult.unknown_count).where(
                    ScanRuleResult.scan_id == last_scan.id
                )
            )
        ).all()
        rule_results = {rule_id: int(unknown) for rule_id, unknown in rows}

    return _Snapshot(
        rules=rules,
        open_findings=open_findings,
        rule_results=rule_results,
        has_completed_scan=last_scan is not None,
    )


def _framework_header(framework: Framework) -> dict:
    return {
        "id": framework.id,
        "name": framework.name,
        "short_name": framework.short_name,
        "version": framework.version,
        "authority": framework.authority,
        "url": framework.url,
        "summary": framework.summary,
        "scope_note": framework.scope_note,
    }


def _resolve(framework: Framework, snapshot: _Snapshot) -> list[tuple[dict, ControlStatus]]:
    resolved: list[tuple[dict, ControlStatus]] = []
    for control in framework.controls:
        evidence = snapshot.evidence_for(framework.id, control.id)
        status = resolve_control_status(evidence, has_completed_scan=snapshot.has_completed_scan)
        resolved.append(
            (
                {
                    "id": control.id,
                    "title": control.title,
                    "group": control.group,
                    "technically_assessable": control.technically_assessable,
                    "status": status.value,
                    "open_finding_count": sum(e.open_finding_count for e in evidence),
                    "rules": [
                        {
                            "rule_id": e.rule_id,
                            "name": e.name,
                            "severity": e.severity,
                            "open_finding_count": e.open_finding_count,
                            "unknown_count": e.unknown_count,
                            "evaluated": e.evaluated,
                        }
                        for e in evidence
                    ],
                },
                status,
            )
        )
    return resolved


async def list_frameworks(session: AsyncSession, organization_id: UUID) -> list[dict]:
    """One summary card per framework."""
    snapshot = await _snapshot(session, organization_id)

    summaries = []
    for framework in FRAMEWORKS:
        resolved = _resolve(framework, snapshot)
        statuses = [status for _, status in resolved]
        summaries.append(
            {
                **_framework_header(framework),
                "control_count": len(statuses),
                "status_counts": status_counts(statuses),
                "coverage_ratio": coverage_ratio(statuses),
                "open_finding_count": sum(c["open_finding_count"] for c, _ in resolved),
            }
        )
    return summaries


async def get_framework_detail(
    session: AsyncSession, organization_id: UUID, framework_id: str
) -> dict | None:
    framework = get_framework(framework_id)
    if framework is None:
        return None

    snapshot = await _snapshot(session, organization_id)
    resolved = _resolve(framework, snapshot)
    statuses = [status for _, status in resolved]

    return {
        **_framework_header(framework),
        "control_count": len(statuses),
        "status_counts": status_counts(statuses),
        "coverage_ratio": coverage_ratio(statuses),
        "open_finding_count": sum(c["open_finding_count"] for c, _ in resolved),
        "assessed": snapshot.has_completed_scan,
        "controls": [control for control, _ in resolved],
    }
