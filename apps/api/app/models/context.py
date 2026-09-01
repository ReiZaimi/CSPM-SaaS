import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import Level
from app.models.base import Base, StrEnumType, TenantOwned, Timestamps, UUIDPrimaryKey


class ContextDeclarationRecord(UUIDPrimaryKey, TenantOwned, Timestamps, Base):
    """What a customer has told CloudGuard about one subscription.

    Everything else in this schema is something CloudGuard observed. This is the
    one table holding something it was *told*, and that is why it exists
    separately rather than as three more columns on ``cloud_accounts``: a
    discovered subscription is a record of what Azure said, and overwriting
    fields of it with what a person believes would mix two kinds of fact that
    have to stay tellable apart -- not least because discovery runs again.

    Inference from tags is a guess. A person saying "this subscription is
    production" is not, and it beats any amount of tag archaeology
    (``ARCHITECTURE_REVIEW.md`` §12 item 11). The scan pipeline applies these as
    a *floor*: a declaration can raise an asset's criticality but never lower
    what the capture already showed, so the worst a mistaken declaration can do
    is over-rank something.

    Scoped to a subscription and nothing finer. Per-resource declarations are
    the obvious next ask and are deliberately a later migration rather than a
    nullable column nothing writes -- speculative scope on the one table whose
    job is to record what somebody actually said would be a poor joke.
    """

    __tablename__ = "context_declarations"
    __table_args__ = (
        UniqueConstraint(
            "cloud_account_id", name="uq_context_declarations_cloud_account_id"
        ),
    )

    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("cloud_accounts.id", ondelete="CASCADE"),
        nullable=False,
    )

    # All three nullable, because a customer who knows one thing should be able
    # to say that one thing. NULL means "not declared", which is different from
    # UNKNOWN: UNKNOWN is CloudGuard's own answer, and this table only ever
    # holds the customer's.
    environment: Mapped[str | None] = mapped_column(String(64))
    criticality: Mapped[Level | None] = mapped_column(StrEnumType(Level, 16))
    data_sensitivity: Mapped[Level | None] = mapped_column(StrEnumType(Level, 16))

    # Why they said so. Free text, shown beside the label rather than parsed --
    # "holds the payroll export" is the sentence that stops the next person
    # undoing this.
    note: Mapped[str | None] = mapped_column(Text)

    # Who said it. Not an FK: auth.users belongs to Supabase, exactly as with
    # ``scans.triggered_by_user_id``. Kept as a column rather than left to the
    # audit log because "who says this is production" is a current fact people
    # ask about the label, not an event to go looking for.
    declared_by_user_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))
    declared_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
