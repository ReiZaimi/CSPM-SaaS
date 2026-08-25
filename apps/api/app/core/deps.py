"""FastAPI dependencies: identity, tenant context, and the RLS-bound session.

The chain is deliberate and one-directional:

    Bearer token -> user id -> membership lookup -> organization_id -> session

``organization_id`` is the *output* of authentication, never an input to it. A
client can name an organization it wants to act in, but the server only honours
it if the membership lookup confirms it -- and PostgreSQL re-checks the same
thing through RLS regardless.
"""

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import rls_session
from app.core.enums import Role
from app.core.errors import NotAuthenticated, OrganizationNotFound, PermissionDenied
from app.core.security import AuthenticatedUser, decode_token
from app.models.organization import OrganizationMember


async def get_current_user(
    authorization: Annotated[str | None, Header()] = None,
) -> AuthenticatedUser:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise NotAuthenticated("Missing bearer token")
    return decode_token(authorization.split(" ", 1)[1].strip())


CurrentUser = Annotated[AuthenticatedUser, Depends(get_current_user)]


async def get_session(user: CurrentUser) -> AsyncIterator[AsyncSession]:
    """A database session PostgreSQL will constrain to this user's tenants."""
    async with rls_session(user.id) as session:
        yield session


DbSession = Annotated[AsyncSession, Depends(get_session)]


@dataclass(frozen=True)
class TenantContext:
    """Everything downstream code is allowed to know about "who is asking"."""

    user: AuthenticatedUser
    organization_id: UUID
    role: Role

    def require_role(self, *roles: Role) -> None:
        if self.role not in roles:
            raise PermissionDenied(
                f"This action requires one of: {', '.join(sorted(r.value for r in roles))}"
            )

    def require_write(self) -> None:
        """Anyone except VIEWER may change security workflow state."""
        if self.role == Role.VIEWER:
            raise PermissionDenied("Your role is read-only")


async def get_tenant(
    request: Request,
    user: CurrentUser,
    session: DbSession,
    x_organization_id: Annotated[str | None, Header()] = None,
) -> TenantContext:
    """Resolve the organization this request acts in.

    The ``X-Organization-Id`` header is a *preference*, not an authorization. It
    is only honoured when a membership row for this user backs it; otherwise the
    request is rejected rather than silently falling back to another tenant.
    """
    stmt = select(OrganizationMember).where(OrganizationMember.user_id == user.id)
    memberships = list((await session.execute(stmt)).scalars().all())
    if not memberships:
        raise OrganizationNotFound("You do not belong to any organization yet")

    requested = x_organization_id or request.query_params.get("organization_id")
    if requested:
        try:
            wanted = UUID(requested)
        except ValueError as exc:
            raise OrganizationNotFound("Invalid organization id") from exc
        for m in memberships:
            if m.organization_id == wanted:
                return TenantContext(user=user, organization_id=wanted, role=Role(m.role))
        raise OrganizationNotFound("Organization not found")

    # Single-organization users -- the overwhelmingly common case -- never have
    # to send the header at all.
    chosen = memberships[0]
    return TenantContext(
        user=user, organization_id=chosen.organization_id, role=Role(chosen.role)
    )


Tenant = Annotated[TenantContext, Depends(get_tenant)]
