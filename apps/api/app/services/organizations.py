"""Organization creation and membership."""

import re
import secrets
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Role
from app.core.errors import OrganizationNotFound, PermissionDenied
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


async def delete_organization(
    session: AsyncSession, user: AuthenticatedUser, organization_id: UUID
) -> None:
    """Delete an organization and everything under it. Owners only.

    The membership check here is not a duplicate of the RLS policy, it is the
    part that can *speak*. RLS filters rows rather than raising: a member who is
    not an owner issues a DELETE that matches nothing and gets a cheerful 200
    while the organization stands. Checking first turns that into a 403 that
    says why.

    Everything below an organization is removed with it -- connections,
    discovered subscriptions, assets, scans, findings, risks and audit history,
    fourteen tables in all, by ``ON DELETE CASCADE``. There is no soft delete
    and no undo.
    """
    membership = (
        await session.execute(
            select(OrganizationMember).where(
                OrganizationMember.organization_id == organization_id,
                OrganizationMember.user_id == user.id,
            )
        )
    ).scalar_one_or_none()

    # Indistinguishable from "does not exist", deliberately: a non-member
    # learning that an organization exists is a small leak, but a free one.
    if membership is None:
        raise OrganizationNotFound()

    if Role(membership.role) != Role.OWNER:
        raise PermissionDenied("Only an owner can delete an organization")

    organization = await session.get(Organization, organization_id)
    if organization is None:  # pragma: no cover -- membership implies existence
        raise OrganizationNotFound()

    await session.delete(organization)
    await session.commit()
