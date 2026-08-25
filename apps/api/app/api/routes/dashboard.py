from fastapi import APIRouter

from app.core.deps import DbSession, Tenant
from app.core.errors import envelope
from app.services.dashboard import build_dashboard

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("")
async def get_dashboard(session: DbSession, tenant: Tenant) -> dict:
    return envelope(await build_dashboard(session, tenant.organization_id))
