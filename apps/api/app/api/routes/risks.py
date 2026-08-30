from uuid import UUID

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from app.core.deps import DbSession, Tenant
from app.core.enums import Level, RiskKind, RiskStatus
from app.core.errors import NotFound, envelope
from app.models.finding import Finding
from app.models.risk import Risk, RiskFinding
from app.schemas.finding import RiskOut

router = APIRouter(prefix="/risks", tags=["risks"])


@router.get("")
async def list_risks(
    session: DbSession,
    tenant: Tenant,
    risk_level: Level | None = None,
    risk_status: RiskStatus | None = Query(default=None, alias="status"),
    kind: RiskKind | None = None,
    limit: int = Query(default=100, le=500),
    offset: int = 0,
) -> dict:
    stmt = select(Risk).where(Risk.organization_id == tenant.organization_id)
    if risk_level:
        stmt = stmt.where(Risk.risk_level == risk_level)
    if risk_status:
        stmt = stmt.where(Risk.status == risk_status)
    # Unfiltered by default, so a scenario ranks against the findings it groups
    # rather than hiding on a page of its own. That is the whole point of
    # putting it in this table: the combination outranking its parts is only
    # visible where they are listed together.
    if kind:
        stmt = stmt.where(Risk.kind == kind)

    total = (
        await session.execute(select(func.count()).select_from(stmt.subquery()))
    ).scalar_one()

    rows = (
        (
            await session.execute(
                stmt.order_by(Risk.risk_score.desc()).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )

    return envelope(
        [
            {
                **RiskOut.model_validate(r).model_dump(mode="json"),
                "status": r.status,
            }
            for r in rows
        ],
        {"total": total, "limit": limit, "offset": offset},
    )


@router.get("/{risk_id}")
async def get_risk(risk_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    risk = (
        await session.execute(
            select(Risk).where(
                Risk.id == risk_id, Risk.organization_id == tenant.organization_id
            )
        )
    ).scalar_one_or_none()
    if risk is None:
        raise NotFound("Risk not found")

    # 1:1 with findings today; the join already supports many.
    findings = (
        (
            await session.execute(
                select(Finding)
                .join(RiskFinding, RiskFinding.finding_id == Finding.id)
                .where(RiskFinding.risk_id == risk_id)
            )
        )
        .scalars()
        .all()
    )

    return envelope(
        {
            **RiskOut.model_validate(risk).model_dump(mode="json"),
            "status": risk.status,
            "findings": [
                {
                    "id": str(f.id),
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "status": f.status,
                }
                for f in findings
            ],
        }
    )
