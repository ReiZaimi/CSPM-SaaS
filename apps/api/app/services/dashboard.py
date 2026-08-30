"""Dashboard aggregation.

The security score deducts against each finding's **risk band**, not the rule's
raw severity. That is the difference between a CSPM that says "you have 3
criticals" and one that says "you have 3 criticals, and this is the one on your
production database" (RISK_ENGINE.md section 3).
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import FindingStatus, Level, RiskKind, ScanStatus
from app.models.finding import Finding
from app.models.resource import ResourceRecord
from app.models.risk import Risk, RiskFinding
from app.models.scan import Scan, ScanRuleResult
from app.risk.scorer import default_scorer


async def build_dashboard(session: AsyncSession, organization_id: UUID) -> dict:
    open_statuses = [FindingStatus.OPEN, FindingStatus.IN_PROGRESS]

    # Risk bands of open findings drive the score.
    #
    # Finding risks only. A scenario risk groups findings that are already
    # counted here, and this query joins through the junction -- so a scenario
    # with four members would deduct four times, and even once would charge the
    # customer twice for one problem. A scenario re-ranks and explains; it does
    # not add a fault to the tally.
    band_rows = (
        await session.execute(
            select(Risk.risk_level, func.count())
            .join(RiskFinding, RiskFinding.risk_id == Risk.id)
            .join(Finding, Finding.id == RiskFinding.finding_id)
            .where(
                Risk.organization_id == organization_id,
                Risk.kind == RiskKind.FINDING,
                Finding.status.in_(open_statuses),
            )
            .group_by(Risk.risk_level)
        )
    ).all()
    band_counts = {Level(level): int(count) for level, count in band_rows}

    open_levels: list[Level] = []
    for level, count in band_counts.items():
        open_levels.extend([level] * count)
    security_score = default_scorer.security_score(open_levels)

    severity_rows = (
        await session.execute(
            select(Finding.severity, func.count())
            .where(
                Finding.organization_id == organization_id,
                Finding.status.in_(open_statuses),
            )
            .group_by(Finding.severity)
        )
    ).all()
    severity_counts = {str(sev): int(count) for sev, count in severity_rows}

    status_rows = (
        await session.execute(
            select(Finding.status, func.count())
            .where(Finding.organization_id == organization_id)
            .group_by(Finding.status)
        )
    ).all()
    status_counts = {str(st): int(count) for st, count in status_rows}

    top_risks = (
        (
            await session.execute(
                select(Risk)
                .join(RiskFinding, RiskFinding.risk_id == Risk.id)
                .join(Finding, Finding.id == RiskFinding.finding_id)
                .where(
                    Risk.organization_id == organization_id,
                    Finding.status.in_(open_statuses),
                )
                .order_by(Risk.risk_score.desc())
                .limit(5)
            )
        )
        .scalars()
        .all()
    )

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

    asset_count = (
        await session.execute(
            select(func.count()).where(ResourceRecord.organization_id == organization_id)
        )
    ).scalar_one()

    resolved_recently = (
        await session.execute(
            select(func.count()).where(
                Finding.organization_id == organization_id,
                Finding.status == FindingStatus.RESOLVED,
                Finding.resolved_at >= datetime.now(UTC) - timedelta(days=30),
            )
        )
    ).scalar_one()

    return {
        "security_score": security_score,
        "score_delta": await _score_delta(session, organization_id, security_score),
        "findings_by_severity": severity_counts,
        "findings_by_status": status_counts,
        "risk_bands": {level.value: count for level, count in band_counts.items()},
        "open_finding_count": sum(band_counts.values()),
        "asset_count": int(asset_count),
        "verified_resolved_last_30_days": int(resolved_recently),
        "remediation_rate": _remediation_rate(status_counts),
        "top_risks": [
            {
                "id": str(r.id),
                "title": r.title,
                "risk_score": float(r.risk_score),
                "risk_level": r.risk_level,
            }
            for r in top_risks
        ],
        "coverage": await _coverage(session, organization_id, last_scan),
        "last_scan": (
            {
                "id": str(last_scan.id),
                "status": last_scan.status,
                "completed_at": last_scan.completed_at.isoformat()
                if last_scan.completed_at
                else None,
                "resource_count": last_scan.resource_count,
                "rule_count": last_scan.rule_count,
                "finding_count": last_scan.finding_count,
                "collection_errors": last_scan.collection_errors,
            }
            if last_scan
            else None
        ),
    }


def _remediation_rate(status_counts: dict[str, int]) -> float:
    """Share of findings ever raised that are now verified fixed."""
    resolved = status_counts.get(FindingStatus.RESOLVED.value, 0)
    total = sum(status_counts.values())
    return round(resolved / total, 3) if total else 0.0


async def _score_delta(
    session: AsyncSession, organization_id: UUID, current: int
) -> int | None:
    """Movement since the previous scan -- the number that tells a user whether
    what they did last week worked."""
    previous = (
        await session.execute(
            select(Finding.resolved_by_scan_id, func.count())
            .where(
                Finding.organization_id == organization_id,
                Finding.status == FindingStatus.RESOLVED,
                Finding.resolved_by_scan_id.isnot(None),
            )
            .group_by(Finding.resolved_by_scan_id)
        )
    ).all()
    if not previous:
        return None

    # Each verified fix gave back its band's deduction; approximate the prior
    # score by adding those back.
    resolved_risks = (
        await session.execute(
            select(Risk.risk_level, func.count())
            .join(RiskFinding, RiskFinding.risk_id == Risk.id)
            .join(Finding, Finding.id == RiskFinding.finding_id)
            .where(
                Risk.organization_id == organization_id,
                Finding.status == FindingStatus.RESOLVED,
            )
            .group_by(Risk.risk_level)
        )
    ).all()

    recovered = sum(
        default_scorer.config.score_deductions.get(Level(level), 0) * int(count)
        for level, count in resolved_risks
    )
    if not recovered:
        return None
    prior = max(0, current - recovered)
    return current - prior


async def _coverage(
    session: AsyncSession, organization_id: UUID, last_scan: Scan | None
) -> dict:
    """Kept out of the security score, on purpose."""
    if last_scan is None:
        return {"ratio": None, "unknown": 0, "conclusive": 0}

    totals = (
        await session.execute(
            select(
                func.coalesce(func.sum(ScanRuleResult.passed_count), 0),
                func.coalesce(func.sum(ScanRuleResult.failed_count), 0),
                func.coalesce(func.sum(ScanRuleResult.unknown_count), 0),
            ).where(ScanRuleResult.scan_id == last_scan.id)
        )
    ).one()
    passed, failed, unknown = (int(v) for v in totals)
    conclusive = passed + failed
    denominator = conclusive + unknown
    return {
        "ratio": round(conclusive / denominator, 4) if denominator else 1.0,
        "unknown": unknown,
        "conclusive": conclusive,
    }
