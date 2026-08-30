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
from app.models.risk import Risk, RiskFinding, RiskHistory
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
        # The line behind the number. A delta says something moved; the series
        # says whether that is a trend or a wobble, which is the difference
        # between a customer acting on it and ignoring it.
        "history": await posture_history(session, organization_id),
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
    what they did last week worked.

    Measured now rather than estimated. This used to reconstruct a prior score
    by adding back the deduction for every finding ever verified fixed, which
    answers "how much better than when we started" while being labelled
    "movement since the last scan" -- two numbers that diverge on the second fix
    and never reconverge. It also double-counted the moment a finding could
    belong to two risks, because it counted deductions through the junction and
    a member of a scenario is joined twice.

    ``None`` where there is no previous reading, which is honest: a first scan
    has nothing to have moved from, and showing 0 would read as "no change"
    rather than "no comparison".
    """
    previous = (
        await session.execute(
            select(RiskHistory.security_score)
            .where(RiskHistory.organization_id == organization_id)
            .order_by(RiskHistory.observed_at.desc())
            # Two, because the newest entry is this scan's own: the pipeline
            # records posture before anything reads the dashboard, so comparing
            # against the first row would compare a scan with itself and report
            # no movement, always.
            .limit(2)
        )
    ).scalars().all()

    if len(previous) < 2:
        return None
    return current - int(previous[1])


async def posture_history(
    session: AsyncSession, organization_id: UUID, limit: int = 30
) -> list[dict]:
    """The posture, each time CloudGuard looked. Oldest first, for plotting.

    Read straight off the stored rows without joining anything. That is the
    point of keeping them: these counts are what was true at each moment, and
    recomputing them from today's findings would answer a different question
    every time somebody reclassifies one.
    """
    rows = list(
        (
            await session.execute(
                select(RiskHistory)
                .where(RiskHistory.organization_id == organization_id)
                .order_by(RiskHistory.observed_at.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "observed_at": entry.observed_at.isoformat(),
            "security_score": entry.security_score,
            "open_finding_count": entry.open_finding_count,
            "findings_by_severity": entry.findings_by_severity,
            "risk_bands": entry.risk_bands,
            "attack_path_count": entry.attack_path_count,
        }
        for entry in reversed(rows)
    ]


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
