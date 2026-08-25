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
