"""Declarative base and the mixins every tenant-owned table shares."""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, MetaData, String, TypeDecorator, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class StrEnumType(TypeDecorator):
    """Stores an enum as a plain varchar, but hands back the enum on load.

    The columns are varchar rather than native PostgreSQL enums so that adding a
    value is a code change, not a migration with a lock. Without this decorator
    though, a ``Mapped[FindingStatus]`` column silently yields a ``str`` when
    read back, and helpers like ``FindingStatus.is_open`` fail at runtime on
    exactly the paths that matter most.
    """

    impl = String
    cache_ok = True

    def __init__(self, enum_class: type[enum.Enum], length: int = 32) -> None:
        self.enum_class = enum_class
        super().__init__(length)

    def process_bind_param(self, value: Any, dialect: Dialect) -> str | None:
        if value is None:
            return None
        return value.value if isinstance(value, enum.Enum) else str(value)

    def process_result_value(self, value: Any, dialect: Dialect) -> Any:
        if value is None:
            return None
        return self.enum_class(value)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class UUIDPrimaryKey:
    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )


class Timestamps:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class TenantOwned:
    """Every tenant-owned row carries organization_id.

    Never populated from client input -- always derived server-side from the
    authenticated user's membership (ARCHITECTURE.md section 4).
    """

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
