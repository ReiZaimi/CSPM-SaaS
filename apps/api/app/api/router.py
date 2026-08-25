"""Aggregate API router. One place to see the whole surface (API.md section 1)."""

from fastapi import APIRouter

from app.api.routes import (
    assets,
    auth,
    cloud_accounts,
    dashboard,
    findings,
    organizations,
    remediation,
    risks,
    rules,
    scans,
)
from app.core.config import settings

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(organizations.router)
api_router.include_router(cloud_accounts.router)
api_router.include_router(scans.router)
api_router.include_router(assets.router)
api_router.include_router(findings.router)
api_router.include_router(risks.router)
api_router.include_router(remediation.router)
api_router.include_router(rules.router)
api_router.include_router(dashboard.router)

# Only present when there is no Supabase project to authenticate against.
if not settings.is_production and not settings.supabase_url:
    api_router.include_router(auth.router)
