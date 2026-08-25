from uuid import UUID

from fastapi import APIRouter, Query
from sqlalchemy import func, select

from app.core.deps import DbSession, Tenant
from app.core.enums import FindingStatus, Level
from app.core.errors import NotFound, envelope
from app.models.finding import Finding
from app.models.resource import ResourceRecord

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("")
async def list_assets(
    session: DbSession,
    tenant: Tenant,
    resource_type: str | None = None,
    environment: str | None = None,
    criticality: Level | None = None,
    exposure: Level | None = None,
    search: str | None = None,
    limit: int = Query(default=100, le=500),
    offset: int = 0,
) -> dict:
    # Open findings per asset, counted in the database rather than by loading
    # every finding into Python.
    finding_counts = (
        select(Finding.resource_id, func.count().label("open_findings"))
        .where(
            Finding.organization_id == tenant.organization_id,
            Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS]),
        )
        .group_by(Finding.resource_id)
        .subquery()
    )

    stmt = (
        select(ResourceRecord, func.coalesce(finding_counts.c.open_findings, 0))
        .outerjoin(finding_counts, finding_counts.c.resource_id == ResourceRecord.id)
        .where(ResourceRecord.organization_id == tenant.organization_id)
    )

    if resource_type:
        stmt = stmt.where(ResourceRecord.resource_type == resource_type)
    if environment:
        stmt = stmt.where(ResourceRecord.environment == environment)
    if criticality:
        stmt = stmt.where(ResourceRecord.criticality == criticality)
    if exposure:
        stmt = stmt.where(ResourceRecord.public_exposure == exposure)
    if search:
        stmt = stmt.where(ResourceRecord.name.ilike(f"%{search}%"))

    total = (
        await session.execute(
            select(func.count()).select_from(stmt.subquery())
        )
    ).scalar_one()

    rows = (
        await session.execute(
            stmt.order_by(ResourceRecord.name).limit(limit).offset(offset)
        )
    ).all()

    return envelope(
        [
            {
                "id": str(r.id),
                "name": r.name,
                "resource_type": r.resource_type,
                "region": r.region,
                "environment": r.environment,
                "criticality": r.criticality,
                "data_sensitivity": r.data_sensitivity,
                "public_exposure": r.public_exposure,
                "open_findings": int(count),
                "first_seen_at": r.first_seen_at.isoformat(),
                "last_seen_at": r.last_seen_at.isoformat(),
            }
            for r, count in rows
        ],
        {"total": total, "limit": limit, "offset": offset},
    )


@router.get("/{asset_id}")
async def get_asset(asset_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    asset = (
        await session.execute(
            select(ResourceRecord).where(
                ResourceRecord.id == asset_id,
                ResourceRecord.organization_id == tenant.organization_id,
            )
        )
    ).scalar_one_or_none()
    if asset is None:
        raise NotFound("Asset not found")

    findings = (
        (
            await session.execute(
                select(Finding)
                .where(
                    Finding.organization_id == tenant.organization_id,
                    Finding.resource_id == asset_id,
                )
                .order_by(Finding.risk_score.desc().nullslast())
            )
        )
        .scalars()
        .all()
    )

    return envelope(
        {
            "id": str(asset.id),
            "name": asset.name,
            "resource_type": asset.resource_type,
            "provider": asset.provider,
            "provider_resource_id": asset.provider_resource_id,
            "region": asset.region,
            "environment": asset.environment,
            "criticality": asset.criticality,
            "data_sensitivity": asset.data_sensitivity,
            "public_exposure": asset.public_exposure,
            "metadata": asset.resource_metadata,
            "first_seen_at": asset.first_seen_at.isoformat(),
            "last_seen_at": asset.last_seen_at.isoformat(),
            "findings": [
                {
                    "id": str(f.id),
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "status": f.status,
                    "risk_score": float(f.risk_score) if f.risk_score is not None else None,
                }
                for f in findings
            ],
        }
    )
