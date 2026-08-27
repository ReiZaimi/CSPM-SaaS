from fastapi import APIRouter

from app.core.deps import DbSession, Tenant
from app.core.errors import NotFound, envelope
from app.services import compliance as service

router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("")
async def list_frameworks(session: DbSession, tenant: Tenant) -> dict:
    return envelope(await service.list_frameworks(session, tenant.organization_id))


@router.get("/{framework_id}")
async def get_framework(framework_id: str, session: DbSession, tenant: Tenant) -> dict:
    detail = await service.get_framework_detail(session, tenant.organization_id, framework_id)
    if detail is None:
        raise NotFound("Framework not found")
    return envelope(detail)
