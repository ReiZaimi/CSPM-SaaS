from fastapi import APIRouter
from sqlalchemy import select

from app.core.deps import DbSession, Tenant
from app.core.errors import NotFound, envelope
from app.models.rule import Rule
from app.services import findings as findings_service

router = APIRouter(prefix="/rules", tags=["rules"])


def _serialize(rule: Rule) -> dict:
    return {
        "rule_id": rule.rule_id,
        "name": rule.name,
        "description": rule.description,
        "category": rule.category,
        "provider": rule.provider,
        "severity": rule.severity,
        "version": rule.version,
        "exploitability": rule.exploitability,
        "scope": rule.scope,
        "applies_to": rule.applies_to,
        "enabled": rule.enabled,
        "remediation": rule.remediation,
        "rationale": rule.rationale,
        "estimated_effort_minutes": rule.estimated_effort_minutes,
        # Data-driven framework tagging, straight out of JSONB. No business
        # logic anywhere branches on these values.
        "compliance_mappings": rule.compliance_mappings,
        # What "fixed" means for this rule, and the artifacts generated from
        # that one statement: the commands, the Terraform arguments, and -- only
        # where one can genuinely enforce it -- an Azure Policy definition.
        # Read from the registry rather than the mirror because it is code, not
        # a row: a policy stored in the database could outlive the rule that
        # generated it.
        "remediation_spec": findings_service.remediation_detail(rule.rule_id),
    }


@router.get("")
async def list_rules(session: DbSession, tenant: Tenant) -> dict:
    rows = (
        (await session.execute(select(Rule).order_by(Rule.rule_id))).scalars().all()
    )
    return envelope([_serialize(r) for r in rows])


@router.get("/{rule_id}")
async def get_rule(rule_id: str, session: DbSession, tenant: Tenant) -> dict:
    rule = (
        await session.execute(select(Rule).where(Rule.rule_id == rule_id))
    ).scalar_one_or_none()
    if rule is None:
        raise NotFound("Rule not found")
    return envelope(_serialize(rule))
