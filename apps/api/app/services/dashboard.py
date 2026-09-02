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

from app.core.enums import (
    FindingEvent,
    FindingStatus,
    Level,
    RiskKind,
    RiskStatus,
    ScanStatus,
    TaskOutcome,
)
from app.models.finding import Finding
from app.models.history import FindingEventRecord
from app.models.resource import ResourceRecord
from app.models.risk import Risk, RiskFinding, RiskHistory
from app.models.scan import Evidence, Scan, ScanRuleResult
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
    #
    # Distinct for the same reason one layer down: the join fans a risk out
    # across its findings, and a rule that groups its findings has one risk with
    # forty. Counting join rows would take the score to zero over the single
    # unwritten policy that grouping exists to state once.
    band_rows = (
        await session.execute(
            select(Risk.risk_level, func.count(func.distinct(Risk.id)))
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

    # What is live, whichever kind it is. A finding risk counts while its
    # finding is open; a scenario counts until the route closes.
    #
    # ``distinct`` is load-bearing rather than defensive. The join fans a risk
    # out across its findings, which was harmless while every risk had exactly
    # one -- and a scenario grouping four findings would otherwise fill four of
    # the five places in this list with itself.
    live_finding_risks = (
        select(Risk.id)
        .join(RiskFinding, RiskFinding.risk_id == Risk.id)
        .join(Finding, Finding.id == RiskFinding.finding_id)
        .where(
            Risk.organization_id == organization_id,
            Risk.kind == RiskKind.FINDING,
            Finding.status.in_(open_statuses),
        )
    )
    live_scenarios = select(Risk.id).where(
        Risk.organization_id == organization_id,
        Risk.kind == RiskKind.ATTACK_PATH,
        Risk.status != RiskStatus.RESOLVED,
    )

    top_risks = (
        (
            await session.execute(
                select(Risk)
                .where(Risk.id.in_(live_finding_risks.union(live_scenarios)))
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
        # Findings, from the findings. The band query counts risks, and those
        # stopped being the same number the moment a risk could group several.
        "open_finding_count": sum(severity_counts.values()),
        "asset_count": int(asset_count),
        "verified_resolved_last_30_days": int(resolved_recently),
        "remediation_rate": _remediation_rate(status_counts),
        # What actually happened week by week, rather than the standing total.
        # A rate cannot tell a team that fixed everything last year from one
        # fixing things this week, and "did it come back" is invisible in both.
        "remediation_activity": await _remediation_activity(session, organization_id),
        "top_risks": [
            {
                "id": str(r.id),
                "title": r.title,
                "risk_score": float(r.risk_score),
                "risk_level": r.risk_level,
                # The terms the score was built from, carried with it. A ranked
                # risk with no context is a number a reader has to open a page
                # to understand; "internet-facing, holds sensitive data" is why
                # it outranks the row beneath it, and it costs no extra query --
                # these columns are already on the row.
                "kind": r.kind,
                "internet_exposure": r.internet_exposure,
                "data_sensitivity": r.data_sensitivity,
                "asset_criticality": r.asset_criticality,
            }
            for r in top_risks
        ],
        "coverage": await _coverage(session, organization_id, last_scan),
        # How old the readings behind all of the above are. Coverage says what
        # fraction of the checks reached a verdict; this says how recently the
        # provider was asked -- and a posture can be fully covered and three
        # weeks out of date.
        "evidence_freshness": await _evidence_freshness(session, organization_id),
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


REMEDIATION_WEEKS = 8


async def _remediation_activity(
    session: AsyncSession, organization_id: UUID
) -> list[dict]:
    """Findings raised, fixed and *come back*, by week.

    Read from the transition log rather than from the findings themselves.
    ``first_detected_at`` and ``resolved_at`` are two points on a line: a
    finding raised, fixed, regressed and fixed again is indistinguishable from
    one raised and fixed once, and the second is a very different week's work.

    Reopenings are counted separately and never subtracted from fixes. A fix
    that did not hold happened; netting the two would hide exactly the pattern
    a security team needs to see.
    """
    since = datetime.now(UTC) - timedelta(weeks=REMEDIATION_WEEKS)
    week = func.date_trunc("week", FindingEventRecord.observed_at)

    rows = (
        await session.execute(
            select(week, FindingEventRecord.event, func.count())
            .where(
                FindingEventRecord.organization_id == organization_id,
                FindingEventRecord.observed_at >= since,
                FindingEventRecord.event.in_(
                    [
                        FindingEvent.DETECTED,
                        FindingEvent.RESOLVED,
                        FindingEvent.REOPENED,
                    ]
                ),
            )
            .group_by(week, FindingEventRecord.event)
            .order_by(week)
        )
    ).all()

    weeks: dict[str, dict] = {}
    for start, event, count in rows:
        key = _aware(start).date().isoformat()
        entry = weeks.setdefault(
            key, {"week": key, "detected": 0, "resolved": 0, "reopened": 0}
        )
        entry[str(event).lower()] = int(count)

    return list(weeks.values())


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


async def _evidence_freshness(session: AsyncSession, organization_id: UUID) -> dict:
    """How recently the provider was actually read, per unit of evidence.

    Measured over the newest reading of each (scope, evidence key), not over
    the last scan. Those differ, and the difference is the reason this exists:
    a scan may carry a reading forward rather than re-take it, and a reading
    carried forward keeps the time it was *collected* rather than the time it
    was reused (``DECISIONS.md`` §16). A freshness figure taken from
    ``scans.completed_at`` would therefore report a posture as current when
    part of it is a week old.

    The headline is the **oldest** of those readings, because that is the
    honest answer to "how current is this picture". An average would let a
    hundred fresh listings hide the one subscription nobody has been able to
    read since Tuesday.
    """
    rows = (
        (
            await session.execute(
                select(Evidence)
                .where(Evidence.organization_id == organization_id)
                .order_by(
                    Evidence.cloud_account_id,
                    Evidence.evidence_key,
                    Evidence.collected_at.desc(),
                )
                .distinct(Evidence.cloud_account_id, Evidence.evidence_key)
            )
        )
        .scalars()
        .all()
    )
    if not rows:
        return {
            "readings": 0,
            "oldest_at": None,
            "newest_at": None,
            "stale_hours": None,
            "unusable": 0,
        }

    now = datetime.now(UTC)
    times = [_aware(row.collected_at) for row in rows]
    oldest, newest = min(times), max(times)
    return {
        "readings": len(rows),
        "oldest_at": oldest.isoformat(),
        "newest_at": newest.isoformat(),
        "stale_hours": round((now - oldest).total_seconds() / 3600, 1),
        # Readings that came back unusable -- failed, truncated, or skipped
        # because their input never arrived. Counted here because a customer
        # reading a freshness figure is asking whether to trust the picture,
        # and "recent" and "usable" are two different halves of that.
        "unusable": sum(1 for row in rows if row.outcome is not TaskOutcome.COMPLETE),
    }


def _aware(moment: datetime) -> datetime:
    """PostgreSQL returns an aware datetime; a fixture may not."""
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


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
        return {"ratio": None, "unknown": 0, "conclusive": 0, "categories": []}

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
        "categories": await _coverage_categories(session, last_scan),
    }


async def _coverage_categories(session: AsyncSession, last_scan: Scan) -> list[dict]:
    """Which parts of the estate the last scan could actually read.

    A single ratio says how much of the picture is missing; it never says
    *which* part, and those call for different actions -- an unreadable identity
    directory is a consent problem for an administrator, an unreadable storage
    listing is usually a role assignment. The evidence table already records an
    outcome per category, so this is one grouped read rather than new bookkeeping.

    PARTIAL counts with FAILED rather than with COMPLETE, deliberately: a
    truncated listing cannot support "none of them are public", which is the
    same rule the engine applies one layer up.
    """
    rows = (
        await session.execute(
            select(
                Evidence.category,
                Evidence.outcome,
                func.count(),
            )
            .where(Evidence.scan_id == last_scan.id)
            .group_by(Evidence.category, Evidence.outcome)
        )
    ).all()

    categories: dict[str, dict] = {}
    for category, outcome, count in rows:
        entry = categories.setdefault(
            category, {"name": category, "readings": 0, "incomplete": 0}
        )
        entry["readings"] += int(count)
        if outcome != TaskOutcome.COMPLETE:
            entry["incomplete"] += int(count)

    # Worst first: a category that could not be read is the one worth reading.
    return sorted(
        categories.values(),
        key=lambda entry: (-entry["incomplete"], entry["name"]),
    )
