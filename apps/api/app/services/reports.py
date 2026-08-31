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

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import FindingStatus, Severity
from app.models.finding import Finding
from app.models.organization import Organization
from app.models.resource import ResourceRecord
from app.services import compliance as compliance_service
from app.services.dashboard import build_dashboard

# How many findings the technical report lists. A tenant with four thousand
# open findings does not want four thousand pages, and the ordering is worst
# first -- so a truncated report is the top of the list rather than an
# arbitrary slice. The count it was cut from is printed beside it, because a
# document that quietly shows 500 of 4000 is a lie of omission.
MAX_TECHNICAL_FINDINGS = 500

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
    now: datetime | None = None,
) -> dict:
    """Everything a report template renders, in one dictionary.

    The two reports share a body deliberately. An executive summary whose
    numbers were computed differently from the technical detail behind it is
    worse than no executive summary: the first question anyone asks of a
    security report is why two pages of it disagree.
    """
    dashboard = await build_dashboard(session, organization_id)
    organization = await session.get(Organization, organization_id)
    frameworks = await compliance_service.list_frameworks(session, organization_id)

    report = {
        "generated_at": (now or datetime.now(UTC)).isoformat(),
        "organization": {
            "name": organization.name if organization else "Unknown organization",
            "industry": organization.industry if organization else None,
            "country": organization.country if organization else None,
        },
        "kind": "technical" if technical else "executive",
        "posture": _posture(dashboard),
        "evidence": _evidence(dashboard),
        "top_risks": dashboard["top_risks"],
        "compliance": {
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
        },
    }

    if technical:
        findings, total = await _findings(session, organization_id)
        report["findings"] = findings
        report["finding_total"] = total
        report["findings_truncated"] = total > len(findings)

    return report


def _posture(dashboard: dict) -> dict:
    """The headline numbers, with the severity order fixed rather than sorted.

    A dictionary iterated in insertion order would put the severities in
    whatever order the aggregate query returned them, which on a quiet estate
    is "whatever happened to exist" -- so a report could open with LOW.
    """
    severity = dashboard["findings_by_severity"]
    status = dashboard["findings_by_status"]
    return {
        "security_score": dashboard["security_score"],
        "score_delta": dashboard["score_delta"],
        "open_finding_count": dashboard["open_finding_count"],
        "asset_count": dashboard["asset_count"],
        "remediation_rate": dashboard["remediation_rate"],
        "verified_resolved_last_30_days": dashboard["verified_resolved_last_30_days"],
        "by_severity": [
            {"severity": level.value, "count": int(severity.get(level.value, 0))}
            for level in SEVERITY_ORDER
        ],
        "by_status": status,
        # Named separately because it is the one status a summary must not
        # quietly absorb: a finding accepted as risk is still in the
        # environment, and is counted neither as open nor as fixed.
        "accepted_risk_count": int(status.get(FindingStatus.ACCEPTED_RISK.value, 0)),
        "history": dashboard["history"],
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
