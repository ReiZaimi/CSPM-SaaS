from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.enums import Role


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    industry: str | None = Field(default=None, max_length=120)
    country: str | None = Field(default=None, min_length=2, max_length=2)

    @field_validator("country")
    @classmethod
    def _upper(cls, v: str | None) -> str | None:
        return v.upper() if v else v


class OrganizationUpdate(BaseModel):
    """A correction to how an organization describes itself.

    Every field optional and applied only when present, which is the opposite
    of ``ContextDeclarationIn`` and deliberately so. That one is a *statement*
    about a subscription, replaced entire so a reader always knows what it
    currently claims. This is a profile: a form that saves only the name must
    not silently clear the country nobody touched.

    The slug is not here. It is an identifier that already appears in stored
    references, and quietly changing it when somebody fixes a typo in a display
    name would be renaming a thing rather than relabelling it.
    """

    name: str | None = Field(default=None, min_length=2, max_length=200)
    industry: str | None = Field(default=None, max_length=120)
    country: str | None = Field(default=None, min_length=2, max_length=2)

    @field_validator("country")
    @classmethod
    def _upper_country(cls, v: str | None) -> str | None:
        return v.upper() if v else v


class OrganizationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str
    industry: str | None = None
    country: str | None = None
    created_at: datetime


class MembershipOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    organization: OrganizationOut
    role: Role
