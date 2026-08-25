"""Organization creation and membership."""

import re
import secrets

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role
from app.core.errors import OrganizationNotFound
from app.core.security import AuthenticatedUser
from app.models.organization import Organization, OrganizationMember
from app.schemas.organization import OrganizationCreate

_SLUG_STRIP = re.compile(r"[^a-z0-9]+")


def slugify(name: str) -> str:
    base = _SLUG_STRIP.sub("-", name.lower()).strip("-")[:40] or "org"
    # A short random suffix keeps slugs unique without a retry loop, and without
    # leaking how many organizations exist.
    return f"{base}-{secrets.token_hex(3)}"


async def create_organization(
    session: AsyncSession, user: AuthenticatedUser, payload: OrganizationCreate
) -> Organization:
    """Create an org and the caller's OWNER membership, atomically.

    Delegated to ``app.create_organization`` in the database because the creator
    is not yet a member and therefore cannot satisfy any membership-based RLS
    policy. Doing it in one SECURITY DEFINER function avoids widening the
    policies to a hole big enough to drive a tenant through.
    """
    result = await session.execute(
        text("SELECT app.create_organization(:name, :slug, :industry, :country) AS id"),
        {
            "name": payload.name,
            "slug": slugify(payload.name),
            "industry": payload.industry,
            "country": payload.country,
        },
    )
    org_id = result.scalar_one()
    await session.flush()

    org = await session.get(Organization, org_id)
    if org is None:  # pragma: no cover -- would mean the function lied to us
        raise OrganizationNotFound("Organization creation failed")
    return org


async def list_memberships(
    session: AsyncSession, user: AuthenticatedUser
) -> list[tuple[Organization, Role]]:
    stmt = (
        select(Organization, OrganizationMember.role)
        .join(OrganizationMember, OrganizationMember.organization_id == Organization.id)
        .where(OrganizationMember.user_id == user.id)
        .order_by(Organization.created_at)
    )
    rows = (await session.execute(stmt)).all()
    return [(org, Role(role)) for org, role in rows]
