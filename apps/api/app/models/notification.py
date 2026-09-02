"""What happened that a person has not seen yet.

Deliberately not a second copy of ``/changes``. That answers "what moved in the
environment" and is a property of the estate; this answers "what happened since
you last looked" and is a property of a reader. Blur them and the bell becomes a
worse-laid-out changes feed, and two screens argue about the same estate.

Derived from the event rows a scan already writes rather than written by the
scanner itself. Two consequences worth stating:

* There is one source of truth about what happened. A second write path would
  mean the notification and the finding could disagree, and the notification is
  the one nobody would test.
* A replay generates nothing, for free. It writes no finding events, so there is
  nothing to derive -- which is the correct behaviour and would otherwise have
  had to be remembered.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import NotificationKind
from app.models.base import Base, StrEnumType, TenantOwned, UUIDPrimaryKey


class Notification(UUIDPrimaryKey, TenantOwned, Base):
    """One thing worth telling somebody, once."""

    __tablename__ = "notifications"
    __table_args__ = (
        Index("ix_notifications_org_event_at", "organization_id", "event_at"),
        # What the derivation asks before writing: has this already been said?
        # Unique rather than checked in application code, because two workers
        # deriving at once is ordinary and a duplicate notification is the
        # failure people actually notice.
        Index(
            "uq_notifications_subject",
            "organization_id",
            "kind",
            "subject_id",
            "event_at",
            unique=True,
        ),
    )

    kind: Mapped[NotificationKind] = mapped_column(
        StrEnumType(NotificationKind, 32), nullable=False
    )
    #: One line, already written for a person. Composed at derivation rather
    #: than at render, so what a reader saw is what was true when it happened --
    #: a title assembled now from a finding that has since been fixed would
    #: describe a state nobody was ever notified about.
    title: Mapped[str] = mapped_column(String(400), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    #: Where the row goes. A path rather than a URL: the client owns its own
    #: routing, and a stored absolute link would rot the day a route is renamed.
    link: Mapped[str | None] = mapped_column(String(500))
    #: The finding, scan or evidence key this is about. Half of the uniqueness
    #: key, so the same event cannot be announced twice.
    subject_id: Mapped[str] = mapped_column(String(200), nullable=False)
    #: When the thing happened, which is not when the row was written. The
    #: derivation runs on a timer, so the two differ by up to its interval --
    #: and every question a reader has is about the first.
    event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class NotificationRead(Base):
    """How far one person has read, as a watermark rather than per row.

    A watermark because the question the bell answers is "what happened since
    you last looked", which has one answer and one timestamp. Per-row read state
    would let a reader carry an unread row for months and would make the badge a
    number about their habits rather than about their estate.
    """

    __tablename__ = "notification_reads"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        primary_key=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    #: Everything with an ``event_at`` at or before this has been seen.
    read_through: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
