from uuid import UUID

from fastapi import APIRouter, status

from app.core.deps import CurrentUser, DbSession, Tenant
from app.core.errors import OrganizationNotFound, envelope
from app.models.organization import Organization
from app.schemas.organization import (
    OrganizationCreate,
    OrganizationOut,
    OrganizationUpdate,
)
from app.services import organizations as service

router = APIRouter(prefix="/organizations", tags=["organizations"])


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_organization(
    payload: OrganizationCreate, user: CurrentUser, session: DbSession
) -> dict:
    org = await service.create_organization(session, user, payload)
    return envelope(OrganizationOut.model_validate(org).model_dump(mode="json"))


@router.get("")
async def list_organizations(user: CurrentUser, session: DbSession) -> dict:
    memberships = await service.list_memberships(session, user)
    return envelope(
        [
            {
                **OrganizationOut.model_validate(org).model_dump(mode="json"),
                "role": role.value,
            }
            for org, role in memberships
        ]
    )


@router.get("/{organization_id}")
async def get_organization(organization_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    # RLS would hide another tenant's row anyway; this returns the honest 404
    # rather than letting a NULL propagate.
    org = await session.get(Organization, organization_id)
    if org is None:
        raise OrganizationNotFound()
    return envelope(OrganizationOut.model_validate(org).model_dump(mode="json"))


@router.patch("")
async def update_organization(
    payload: OrganizationUpdate, session: DbSession, tenant: Tenant
) -> dict:
    """Correct how this organization describes itself.

    No id in the path, unlike DELETE. Deleting a different organization from
    the one on screen is a real thing to want; editing one is not, and taking
    the target from the tenant context means the membership check has already
    happened rather than being repeated here.
    """
    org = await service.update_organization(session, tenant, payload)
    return envelope(OrganizationOut.model_validate(org).model_dump(mode="json"))


@router.delete("/{organization_id}", status_code=status.HTTP_200_OK)
async def delete_organization(
    organization_id: UUID, user: CurrentUser, session: DbSession
) -> dict:
    """Delete an organization and everything under it.

    Takes the id from the path rather than the tenant header: this is the one
    operation whose target is not "the organization I am currently working in",
    and resolving it from the header would make deleting a *different* one
    impossible from a single screen.
    """
    await service.delete_organization(session, user, organization_id)
    return envelope({"deleted": str(organization_id)})
