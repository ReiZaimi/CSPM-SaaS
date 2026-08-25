from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import Severity
from app.models.base import Base, StrEnumType, Timestamps, UUIDPrimaryKey


class Rule(UUIDPrimaryKey, Timestamps, Base):
    """Read-mirror of the Python rule registry.

    NOT tenant-owned: the rule catalogue is global product data, readable by any
    authenticated user and writable by nobody through the API. It is synced from
    ``app.rules.registry`` at startup -- changing a rule means changing code, not
    a database row (RULE_ENGINE.md section 4).
    """

    __tablename__ = "rules"

    rule_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    provider: Mapped[str] = mapped_column(String(16), nullable=False)
    severity: Mapped[Severity] = mapped_column(StrEnumType(Severity, 16), nullable=False)
    version: Mapped[str] = mapped_column(String(16), nullable=False)
    exploitability: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    applies_to: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    estimated_effort_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Data-driven framework tagging. No framework logic is ever hardcoded into
    # business logic (PRODUCT_SPEC.md requirement 15).
    compliance_mappings: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
