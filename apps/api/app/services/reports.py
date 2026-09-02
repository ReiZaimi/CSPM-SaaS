"""What goes in a report, assembled from what the product already knows.

Two audiences, one body of evidence. The executive report answers "how exposed
are we, and is it getting better"; the technical report answers that and then
lists every finding behind it. Neither computes anything of its own -- the
score, the coverage ratio and the compliance statuses all come from the
services that produce them for the screens, so a PDF and the dashboard cannot
disagree about the same organization on the same day.

Three things this module insists on carrying, because a document outlives the
screen it was taken from and nobody can ask it a follow-up question:

* **When the evidence was collected**, not when the PDF was printed. A report
  that says only "generated today" over three-week-old readings is the most
  confident kind of wrong.
* **What could not be read.** Collection gaps and UNKNOWN verdicts travel with
  the numbers. A report that silently drops them turns "we could not look" into
  "we looked and it was fine" -- the one transformation this product exists to
  refuse.
* **That compliance coverage is evidence, not a verdict.** The same sentence
  the compliance screen carries.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import FindingStatus, RemediationStatus, Severity
from app.models.finding import Finding
from app.models.organization import Organization
from app.models.remediation import RemediationTask
from app.models.resource import ResourceRecord
from app.services import compliance as compliance_service
from app.services import graph as graph_service
from app.services.dashboard import build_dashboard

# How many findings the technical report lists. A tenant with four thousand
# open findings does not want four thousand pages, and the ordering is worst
# first -- so a truncated report is the top of the list rather than an
# arbitrary slice. The count it was cut from is printed beside it, because a
# document that quietly shows 500 of 4000 is a lie of omission.
MAX_TECHNICAL_FINDINGS = 500

# Which parts of a report a reader can leave out.
#
# Not all of it: the posture block and the evidence caveats are the report, and
# a document that could omit "12% of checks reached no verdict" would let
# somebody produce a cleaner-looking PDF by unticking a box. What is optional is
# the parts that are additional detail rather than the terms the numbers are
# read on.
OPTIONAL_SECTIONS = ("top_risks", "attack_paths", "compliance", "remediation", "findings")

# What each section is called to somebody reading the document rather than
# calling the API.
SECTION_LABELS = {
    "top_risks": "top risks",
    "attack_paths": "attack paths",
    "compliance": "compliance coverage",
    "remediation": "remediation progress",
    "findings": "the full findings list",
}

# The activity window: how far back "verified fixed" and "work completed" look,
# and how much of the trend line is drawn. It does not filter the posture, which
# is a reading of now -- a score is not a thing that has a date range.
DEFAULT_WINDOW_DAYS = 30
MAX_WINDOW_DAYS = 365

# Routes carried into a report. The screen offers every path; a document wants
# the ones somebody will act on this quarter, shortest first.
MAX_REPORT_PATHS = 5

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
]


async def build_report(
    session: AsyncSession,
    organization_id: UUID,
    *,
    technical: bool,
    sections: frozenset[str] | None = None,
    window_days: int = DEFAULT_WINDOW_DAYS,
    now: datetime | None = None,
) -> dict:
    """Everything a report template renders, in one dictionary.

    The two reports share a body deliberately. An executive summary whose
    numbers were computed differently from the technical detail behind it is
    worse than no executive summary: the first question anyone asks of a
    security report is why two pages of it disagree.
    """
    chosen = frozenset(sections if sections is not None else OPTIONAL_SECTIONS)
    moment = now or datetime.now(UTC)
    since = moment - timedelta(days=window_days)

    dashboard = await build_dashboard(session, organization_id)
    organization = await session.get(Organization, organization_id)

    report = {
        "generated_at": moment.isoformat(),
        "organization": {
            "name": organization.name if organization else "Unknown organization",
            "industry": organization.industry if organization else None,
            "country": organization.country if organization else None,
        },
        "kind": "technical" if technical else "executive",
        # Which optional parts this document contains. Printed on the cover as
        # well as branched on here: a reader handed a report with no compliance
        # section should be told it was left out, not left to conclude that
        # CloudGuard assesses no frameworks.
        "sections": sorted(chosen),
        # Named on the cover. An omission somebody chose looks exactly like an
        # absence of evidence once a PDF has been forwarded twice, and only one
        # of those is true.
        "omitted_sections": [
            SECTION_LABELS[name]
            for name in OPTIONAL_SECTIONS
            if name not in chosen and (technical or name != "findings")
        ],
        "window_days": window_days,
        "posture": _posture(
            dashboard,
            window_days=window_days,
            since=since,
            resolved_in_window=await _verified_resolved(session, organization_id, since),
        ),
        "evidence": _evidence(dashboard),
    }

    if "top_risks" in chosen:
        report["top_risks"] = dashboard["top_risks"]

    if "attack_paths" in chosen:
        report["attack_paths"] = await _attack_paths(session, organization_id)

    if "remediation" in chosen:
        report["remediation"] = await _remediation(
            session, organization_id, since=since, dashboard=dashboard
        )

    if "compliance" in chosen:
        frameworks = await compliance_service.list_frameworks(session, organization_id)
        report["compliance"] = {
            "frameworks": frameworks,
            # Repeated in the document rather than left to the reader's memory
            # of the screen. A PDF gets forwarded to auditors and boards, and
            # this is the sentence that stops a green bar being read as a pass.
            "disclaimer": (
                "This is evidence, not a compliance verdict. A covered control "
                "means specific misconfigurations were absent at the last scan; "
                "it is not a statement that a requirement is met in law or that "
                "an audit would pass."
            ),
        }

    if technical and "findings" in chosen:
        findings, total = await _findings(session, organization_id)
        report["findings"] = findings
        report["finding_total"] = total
        report["findings_truncated"] = total > len(findings)

    return report


def _posture(
    dashboard: dict,
    *,
    window_days: int = DEFAULT_WINDOW_DAYS,
    since: datetime | None = None,
    resolved_in_window: int | None = None,
) -> dict:
    """The headline numbers, with the severity order fixed rather than sorted.

    A dictionary iterated in insertion order would put the severities in
    whatever order the aggregate query returned them, which on a quiet estate
    is "whatever happened to exist" -- so a report could open with LOW.

    The window touches only the activity counts and the trend. The score, the
    open findings and the severity split are a reading of now: giving them a
    date range would invite "our score over the last quarter", which is not a
    thing this product measures and not a thing a scan can answer.
    """
    severity = dashboard["findings_by_severity"]
    status = dashboard["findings_by_status"]
    return {
        "security_score": dashboard["security_score"],
        "score_delta": dashboard["score_delta"],
        "open_finding_count": dashboard["open_finding_count"],
        "asset_count": dashboard["asset_count"],
        "remediation_rate": dashboard["remediation_rate"],
        "window_days": window_days,
        "verified_resolved_in_window": (
            dashboard["verified_resolved_last_30_days"]
            if resolved_in_window is None
            else resolved_in_window
        ),
        "by_severity": [
            {"severity": level.value, "count": int(severity.get(level.value, 0))}
            for level in SEVERITY_ORDER
        ],
        "by_status": status,
        # Named separately because it is the one status a summary must not
        # quietly absorb: a finding accepted as risk is still in the
        # environment, and is counted neither as open nor as fixed.
        "accepted_risk_count": int(status.get(FindingStatus.ACCEPTED_RISK.value, 0)),
        # Cut to the window, so a report asked for the last 30 days does not
        # draw a line reaching back six months. Cut rather than resampled: each
        # point is a reading that happened, and inventing an evenly spaced
        # series would draw movement nobody measured.
        "history": _history_within(
            dashboard["history"],
            since or datetime.now(UTC) - timedelta(days=window_days),
        ),
    }


def _history_within(history: list[dict], cutoff: datetime) -> list[dict]:
    """The readings inside the window, in the order they were given.

    Taken from the same cutoff the counts use, rather than from a second call
    to the clock: a report whose trend and whose "verified fixed" count covered
    slightly different periods would be wrong in a way nobody could see.
    """
    kept = []
    for entry in history:
        observed = entry.get("observed_at")
        if not observed:
            continue
        try:
            moment = datetime.fromisoformat(observed)
        except ValueError:
            continue
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        if moment >= cutoff:
            kept.append(entry)
    return kept


async def _verified_resolved(
    session: AsyncSession, organization_id: UUID, since: datetime
) -> int:
    """Findings a later scan observed passing, inside the window.

    Counted here rather than taken from the dashboard's fixed thirty days,
    because the window is the one thing a reader chose about this document.
    """
    return int(
        (
            await session.execute(
                select(func.count()).where(
                    Finding.organization_id == organization_id,
                    Finding.status == FindingStatus.RESOLVED,
                    Finding.resolved_at >= since,
                )
            )
        ).scalar_one()
    )


async def _attack_paths(session: AsyncSession, organization_id: UUID) -> list[dict]:
    """The shortest routes from something exposed to something worth taking.

    Shortest first, because that ordering is the recommendation: fewer hops is
    both likelier to be walked and cheaper to sever. Each route carries the one
    link worth cutting, which is the only line in this section somebody can act
    on without opening CloudGuard.
    """
    graph = await graph_service.load_graph(session, organization_id)
    paths = graph.attack_paths()

    serialized = []
    for path in paths[:MAX_REPORT_PATHS]:
        cut = path.cheapest_break()
        serialized.append(
            {
                "entry": path.entry.name,
                "target": path.target.name,
                "hops": path.hops,
                "steps": path.describe(),
                "cheapest_break": cut.describe() if cut else None,
            }
        )
    return serialized


async def _remediation(
    session: AsyncSession,
    organization_id: UUID,
    *,
    since: datetime,
    dashboard: dict,
) -> dict:
    """Work in flight, work completed, and the only number that proves anything.

    Tasks completed and findings verified fixed are reported side by side and
    never added together. A task marked done is a claim; a verified fix is an
    observation, and a report that summed them would let the claim inflate the
    proof.
    """
    rows = (
        await session.execute(
            select(RemediationTask.status, func.count())
            .where(RemediationTask.organization_id == organization_id)
            .group_by(RemediationTask.status)
        )
    ).all()
    counts = {str(status): int(count) for status, count in rows}

    completed_in_window = int(
        (
            await session.execute(
                select(func.count()).where(
                    RemediationTask.organization_id == organization_id,
                    RemediationTask.status == RemediationStatus.DONE,
                    RemediationTask.completed_at >= since,
                )
            )
        ).scalar_one()
    )

    return {
        "open_tasks": counts.get(RemediationStatus.TODO.value, 0)
        + counts.get(RemediationStatus.IN_PROGRESS.value, 0),
        "done_tasks": counts.get(RemediationStatus.DONE.value, 0),
        "cancelled_tasks": counts.get(RemediationStatus.CANCELLED.value, 0),
        "completed_in_window": completed_in_window,
        "remediation_rate": dashboard["remediation_rate"],
    }


def _evidence(dashboard: dict) -> dict:
    """How much of the picture is real, and how old it is.

    Both questions, together, because either alone misleads. Full coverage of a
    three-week-old reading and a fresh reading of half the estate are different
    problems, and a single "last scanned" line cannot tell them apart.
    """
    coverage = dashboard["coverage"]
    freshness = dashboard.get("evidence_freshness") or {}
    last_scan = dashboard.get("last_scan")

    return {
        "coverage_ratio": coverage["ratio"],
        # Named rather than folded into the ratio. These are the checks that
        # reached no verdict, and they are never a pass.
        "unknown": coverage["unknown"],
        "conclusive": coverage["conclusive"],
        # The other half of coverage, and the half a reader of a PDF cannot go
        # and look up. The score in this document is charged only for context
        # CloudGuard established, so a document quoting the score without saying
        # how much of the estate is unclassified would be quoting half a
        # sentence.
        "unclassified_risks": coverage.get("context", {}).get("unclassified", 0),
        "classified_risks": coverage.get("context", {}).get("classified", 0),
        "oldest_reading_at": freshness.get("oldest_at"),
        "newest_reading_at": freshness.get("newest_at"),
        "stale_hours": freshness.get("stale_hours"),
        "unusable_readings": freshness.get("unusable", 0),
        "last_scan": last_scan,
        # A scan that could not read part of the estate says so on the cover.
        "collection_errors": (last_scan or {}).get("collection_errors") or {},
    }


async def _findings(
    session: AsyncSession, organization_id: UUID
) -> tuple[list[dict], int]:
    """Open findings, worst first, with the asset each was found on.

    Open only, and that is the report's claim rather than a filter left over
    from a screen: a document headed "what is wrong" that lists verified fixes
    among the problems makes the reader do the separating. The fixes are
    reported as a count in the posture summary, where they belong.
    """
    stmt = (
        select(Finding, ResourceRecord)
        .outerjoin(ResourceRecord, ResourceRecord.id == Finding.resource_id)
        .where(
            Finding.organization_id == organization_id,
            Finding.status.in_(
                [FindingStatus.OPEN.value, FindingStatus.IN_PROGRESS.value]
            ),
        )
        .order_by(Finding.risk_score.desc().nullslast(), Finding.last_detected_at.desc())
    )

    rows = (await session.execute(stmt.limit(MAX_TECHNICAL_FINDINGS))).all()
    total = len(
        (
            await session.execute(
                select(Finding.id).where(
                    Finding.organization_id == organization_id,
                    Finding.status.in_(
                        [FindingStatus.OPEN.value, FindingStatus.IN_PROGRESS.value]
                    ),
                )
            )
        )
        .scalars()
        .all()
    )

    return (
        [
            {
                "id": str(finding.id),
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity,
                "status": finding.status,
                "risk_score": (
                    float(finding.risk_score) if finding.risk_score is not None else None
                ),
                "first_detected_at": (
                    finding.first_detected_at.isoformat()
                    if finding.first_detected_at
                    else None
                ),
                "last_detected_at": (
                    finding.last_detected_at.isoformat()
                    if finding.last_detected_at
                    else None
                ),
                "remediation": finding.remediation,
                "asset": (
                    {
                        "name": resource.name,
                        "resource_type": resource.resource_type,
                        "environment": resource.environment,
                        "region": resource.region,
                    }
                    if resource
                    else None
                ),
            }
            for finding, resource in rows
        ],
        total,
    )
