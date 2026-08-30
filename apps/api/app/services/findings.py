"""Finding queries and the workflow actions on a finding."""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import commit_unless_externally_managed
from app.core.deps import TenantContext
from app.core.enums import (
    ExceptionStatus,
    FindingEvent,
    FindingStatus,
    RiskKind,
    RiskStatus,
)
from app.core.errors import FindingNotFound, ValidationFailed
from app.models.finding import Finding
from app.models.history import FindingEventRecord
from app.models.remediation import AuditLog, RiskException
from app.models.resource import ResourceRecord
from app.models.risk import Risk, RiskFinding
from app.models.rule import Rule
from app.models.verification import RemediationVerification
from app.risk.scorer import default_scorer
from app.rules.registry import get_rule
from app.services import verification as verification_service


async def get_finding(
    session: AsyncSession, tenant: TenantContext, finding_id: UUID
) -> Finding:
    finding = (
        await session.execute(
            select(Finding).where(
                Finding.id == finding_id,
                Finding.organization_id == tenant.organization_id,
            )
        )
    ).scalar_one_or_none()
    if finding is None:
        raise FindingNotFound()
    return finding


async def load_detail(
    session: AsyncSession, tenant: TenantContext, finding: Finding
) -> dict:
    """Assemble everything the finding detail page asks for."""
    resource = (
        await session.get(ResourceRecord, finding.resource_id)
        if finding.resource_id
        else None
    )

    rule_row = (
        await session.execute(select(Rule).where(Rule.rule_id == finding.rule_id))
    ).scalar_one_or_none()

    risk = await own_risk(session, finding)

    effort = rule_row.estimated_effort_minutes if rule_row else 30
    score = float(finding.risk_score) if finding.risk_score is not None else 0.0

    return {
        "finding": finding,
        "resource": resource,
        "rule": rule_row,
        "risk": risk,
        "priority": default_scorer.priority(score, effort),
        "estimated_effort_minutes": effort,
        # Everything that has happened to it, which two timestamps could not
        # say: a finding raised, fixed, regressed and fixed again looked
        # exactly like one raised and fixed once.
        "timeline": await timeline(session, finding),
        # Where the claimed fix has got to, if somebody has claimed one. The
        # answer to "did my work count" belongs on the page where the work was
        # reported, and the interesting part of it is the sentence: "still
        # failing" and "CloudGuard could not read enough to tell" are the same
        # open finding and entirely different news.
        "verification": await latest_verification(session, finding),
    }


async def accept_risk(
    session: AsyncSession,
    tenant: TenantContext,
    finding: Finding,
    reason: str,
    expires_at: datetime | None,
) -> Finding:
    """Record a deliberate decision not to fix something.

    Accepted is not hidden: the finding keeps its risk score, stays queryable,
    and the decision is written to the audit log (SECURITY.md section 4).
    """
    if finding.status == FindingStatus.RESOLVED:
        raise ValidationFailed("This finding is already resolved")

    _record_event(
        session,
        tenant,
        finding,
        FindingEvent.RISK_ACCEPTED,
        FindingStatus.ACCEPTED_RISK,
        detail=reason,
    )
    finding.status = FindingStatus.ACCEPTED_RISK

    # A risk somebody has decided to live with is not a fix waiting to be
    # confirmed. Left pending, the scheduler would keep starting scans to settle
    # a question that has been answered by a decision instead of by evidence.
    await verification_service.abandon(
        session,
        tenant.organization_id,
        finding.id,
        reason="The risk was accepted, so CloudGuard stopped checking for a fix.",
    )

    session.add(
        RiskException(
            organization_id=tenant.organization_id,
            finding_id=finding.id,
            approved_by=tenant.user.id,
            reason=reason,
            expires_at=expires_at,
            status=ExceptionStatus.ACTIVE,
            created_at=datetime.now(UTC),
        )
    )

    risk = await own_risk(session, finding)
    if risk:
        risk.status = RiskStatus.ACCEPTED

    await record_audit(
        session,
        tenant,
        action="finding.accept_risk",
        resource_type="finding",
        resource_id=finding.id,
        metadata={"reason": reason, "rule_id": finding.rule_id},
    )
    await commit_unless_externally_managed(session)
    return finding


async def set_status(
    session: AsyncSession,
    tenant: TenantContext,
    finding: Finding,
    status: FindingStatus,
) -> Finding:
    """Move a finding through the workflow.

    RESOLVED is deliberately not settable here. A finding resolves when a scan
    observes the fix, never because someone said so (RULE_ENGINE.md section 3).
    """
    if status == FindingStatus.RESOLVED:
        raise ValidationFailed(
            "Findings cannot be marked resolved by hand. Fix the issue and run a "
            "rescan — CloudGuard resolves it once a scan confirms the fix."
        )

    _record_event(session, tenant, finding, FindingEvent.STATUS_CHANGED, status)
    finding.status = status
    await record_audit(
        session,
        tenant,
        action="finding.status_change",
        resource_type="finding",
        resource_id=finding.id,
        metadata={"status": status.value, "rule_id": finding.rule_id},
    )
    await commit_unless_externally_managed(session)
    return finding


def _record_event(
    session: AsyncSession,
    tenant: TenantContext,
    finding: Finding,
    event: FindingEvent,
    new_status: FindingStatus,
    *,
    detail: str | None = None,
) -> None:
    """Write the transition to the finding's own timeline.

    Beside the audit log rather than instead of it, and the difference is who
    is asking. The audit log answers "what has anybody in this organization
    done", for a security reviewer; this answers "what happened to *this
    finding*", for whoever is looking at it -- and only the second is complete,
    because it also holds the transitions a scan made, which no person did.
    """
    session.add(
        FindingEventRecord(
            organization_id=tenant.organization_id,
            finding_id=finding.id,
            scan_id=finding.scan_id,
            user_id=tenant.user.id,
            event=event,
            previous_status=finding.status,
            current_status=new_status,
            detail=detail,
            observed_at=datetime.now(UTC),
        )
    )


async def timeline(
    session: AsyncSession, finding: Finding, limit: int = 50
) -> list[FindingEventRecord]:
    """Everything that has happened to this finding, newest first."""
    return list(
        (
            await session.execute(
                select(FindingEventRecord)
                .where(FindingEventRecord.finding_id == finding.id)
                .order_by(FindingEventRecord.observed_at.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )


async def latest_verification(
    session: AsyncSession, finding: Finding
) -> RemediationVerification | None:
    """The most recent claim that this finding was fixed, settled or not.

    Newest rather than pending, because a settled verification is the more
    useful answer once there is one: a customer looking at a finding that is
    still open after they fixed it wants to be told why, not told nothing on
    the grounds that CloudGuard has finished asking.
    """
    return (
        await session.execute(
            select(RemediationVerification)
            .where(RemediationVerification.finding_id == finding.id)
            .order_by(RemediationVerification.claimed_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def own_risk(session: AsyncSession, finding: Finding) -> Risk | None:
    """The risk that is *about* this finding, rather than any risk containing it.

    A finding used to have at most one risk, so every caller here read the
    junction with ``scalar_one_or_none`` and got it. Scenario risks broke that
    assumption without breaking the query's shape: a finding on an attack path
    is linked twice -- once to its own risk and once to the route it is part of
    -- so those callers began raising ``MultipleResultsFound`` on exactly the
    findings the graph had found something interesting about.

    Filtering on the kind restores the guarantee rather than papering over it
    with ``first()``: there is exactly one FINDING risk per finding, and picking
    an arbitrary row would have quietly attached a remediation task, or an
    accepted-risk status, to a route instead of to the thing somebody clicked.
    """
    return (
        await session.execute(
            select(Risk)
            .join(RiskFinding, RiskFinding.risk_id == Risk.id)
            .where(
                RiskFinding.finding_id == finding.id,
                Risk.kind == RiskKind.FINDING,
            )
        )
    ).scalar_one_or_none()


async def record_audit(
    session: AsyncSession,
    tenant: TenantContext,
    action: str,
    resource_type: str,
    resource_id: UUID | None,
    metadata: dict | None = None,
) -> None:
    session.add(
        AuditLog(
            organization_id=tenant.organization_id,
            user_id=tenant.user.id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            audit_metadata=metadata or {},
            created_at=datetime.now(UTC),
        )
    )


def rule_metadata(rule_id: str) -> dict:
    """Rule detail straight from the registry, for fields the mirror omits."""
    rule = get_rule(rule_id)
    if rule is None:
        return {}
    return {
        "rule_name": rule.name,
        "rationale": rule.rationale,
        "category": rule.category,
        "compliance_mappings": rule.compliance_mappings,
        "estimated_effort_minutes": rule.estimated_effort_minutes,
    }
