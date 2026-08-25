"""Finding queries and the workflow actions on a finding."""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import TenantContext
from app.core.enums import ExceptionStatus, FindingStatus, RiskStatus
from app.core.errors import FindingNotFound, ValidationFailed
from app.models.finding import Finding
from app.models.remediation import AuditLog, RiskException
from app.models.resource import ResourceRecord
from app.models.risk import Risk, RiskFinding
from app.models.rule import Rule
from app.risk.scorer import default_scorer
from app.rules.registry import get_rule


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

    link = (
        await session.execute(
            select(RiskFinding).where(RiskFinding.finding_id == finding.id)
        )
    ).scalar_one_or_none()
    risk = await session.get(Risk, link.risk_id) if link else None

    effort = rule_row.estimated_effort_minutes if rule_row else 30
    score = float(finding.risk_score) if finding.risk_score is not None else 0.0

    return {
        "finding": finding,
        "resource": resource,
        "rule": rule_row,
        "risk": risk,
        "priority": default_scorer.priority(score, effort),
        "estimated_effort_minutes": effort,
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

    finding.status = FindingStatus.ACCEPTED_RISK

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

    link = (
        await session.execute(
            select(RiskFinding).where(RiskFinding.finding_id == finding.id)
        )
    ).scalar_one_or_none()
    if link:
        risk = await session.get(Risk, link.risk_id)
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
    await session.commit()
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

    finding.status = status
    await record_audit(
        session,
        tenant,
        action="finding.status_change",
        resource_type="finding",
        resource_id=finding.id,
        metadata={"status": status.value, "rule_id": finding.rule_id},
    )
    await session.commit()
    return finding


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
