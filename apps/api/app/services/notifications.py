"""Turning what happened into what is worth saying.

Derived from the event rows a scan already writes, never produced beside them.
The scanner is the one source of truth about what happened; a second write path
would let a notification and a finding disagree, and the notification is the one
nobody would test. It also means a replay generates nothing for free -- it
writes no finding events, so there is nothing here to read.

**Three kinds, and the shortness is the design.** The bar is not severity:
severity is the rulebook's opinion, while the product's argument is that what
matters is what a finding means on *this* asset. The bar is whether somebody
would want to be interrupted.

  * a new finding on an asset an attacker can actually reach
  * a fix CloudGuard watched work
  * a reading that stopped arriving, because the score is then measuring
    something narrower than it was yesterday

Everything else belongs on a screen somebody chose to open. ``/changes`` already
answers "what moved in the environment"; this answers "what happened since you
last looked", and blurring the two would build a second changes feed with a
worse layout.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import FindingEvent, NotificationKind, TaskOutcome
from app.models.finding import Finding
from app.models.history import FindingEventRecord
from app.models.notification import Notification, NotificationRead
from app.models.resource import ResourceRecord
from app.models.scan import Evidence
from app.services import graph as graph_service

# How far back a sweep will look when an organization has no notifications yet.
#
# Bounded rather than unbounded: a customer onboarding today should not receive
# a month of history as news the first time the sweep runs, and an estate that
# has been quiet for a year should not generate one enormous batch the day this
# ships. Anything older than this is history, and history has screens.
COLD_START = timedelta(days=7)


async def derive(session: AsyncSession, organization_id: UUID) -> int:
    """Write anything that happened since the last thing we wrote.

    The watermark is the newest ``event_at`` already stored rather than a
    separate cursor. One less piece of state to keep in step, and it degrades
    correctly: a row that fails to insert leaves the watermark where it was, so
    the next sweep tries again rather than stepping over it.
    """
    since = await _watermark(session, organization_id)
    written = 0
    written += await _reachable_findings(session, organization_id, since)
    written += await _verified_fixes(session, organization_id, since)
    written += await _coverage_drops(session, organization_id, since)
    return written


async def _watermark(session: AsyncSession, organization_id: UUID) -> datetime:
    newest = (
        await session.execute(
            select(Notification.event_at)
            .where(Notification.organization_id == organization_id)
            .order_by(Notification.event_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    return newest or datetime.now(UTC) - COLD_START


async def _write(
    session: AsyncSession,
    organization_id: UUID,
    *,
    kind: NotificationKind,
    subject_id: str,
    event_at: datetime,
    title: str,
    detail: str | None = None,
    link: str | None = None,
) -> int:
    """Insert one, or do nothing if it has already been said.

    ``ON CONFLICT DO NOTHING`` against the unique index rather than a read
    followed by a write: two sweeps overlapping is ordinary, and a check-then-act
    would let both pass the check.
    """
    result = await session.execute(
        insert(Notification)
        .values(
            organization_id=organization_id,
            kind=kind,
            subject_id=subject_id,
            event_at=event_at,
            title=title,
            detail=detail,
            link=link,
        )
        .on_conflict_do_nothing(
            index_elements=["organization_id", "kind", "subject_id", "event_at"]
        )
    )
    return int(result.rowcount or 0)


async def _reachable_findings(
    session: AsyncSession, organization_id: UUID, since: datetime
) -> int:
    """New findings on assets that stand on a route.

    Reachability rather than severity, and this is the whole judgement. A
    CRITICAL on an isolated sandbox is a rulebook event; a finding on a host an
    attacker can walk to is the thing somebody would want to be told. It also
    keeps the bell quiet on estates where most findings are real and none of
    them are reachable -- which is a true and useful silence.

    The graph is built once for the sweep rather than per finding: it costs a
    traversal, and a per-row build would make a quiet week more expensive than a
    loud one.
    """
    rows = (
        (
            await session.execute(
                select(FindingEventRecord, Finding, ResourceRecord)
                .join(Finding, Finding.id == FindingEventRecord.finding_id)
                .join(ResourceRecord, ResourceRecord.id == Finding.resource_id)
                .where(
                    FindingEventRecord.organization_id == organization_id,
                    FindingEventRecord.observed_at > since,
                    FindingEventRecord.event.in_(
                        [FindingEvent.DETECTED, FindingEvent.REOPENED]
                    ),
                )
                .order_by(FindingEventRecord.observed_at)
                .limit(200)
            )
        )
        .all()
    )
    if not rows:
        return 0

    graph = await graph_service.load_graph(session, organization_id)
    written = 0
    for event, finding, resource in rows:
        if not graph.paths_through(resource.provider_resource_id):
            # Real, and not news. It stays on the findings list, which is where
            # somebody goes to ask "what is wrong" rather than to be told.
            continue
        reopened = event.event is FindingEvent.REOPENED
        written += await _write(
            session,
            organization_id,
            kind=NotificationKind.REACHABLE_FINDING,
            subject_id=str(finding.id),
            event_at=event.observed_at,
            title=(
                f"{finding.title} on {resource.name}"
                if not reopened
                else f"{finding.title} is back on {resource.name}"
            ),
            # Says why this one and not the forty others, so the bell reads as a
            # judgement rather than as a sample.
            detail=(
                "This asset stands on a route from somewhere an attacker could "
                "start to something worth taking."
            ),
            link=f"/findings/{finding.id}",
        )
    return written


async def _verified_fixes(
    session: AsyncSession, organization_id: UUID, since: datetime
) -> int:
    """Fixes CloudGuard observed working.

    The only positive notification, and the one a customer is actually waiting
    for: marking work done is a claim, and a scan returning PASS is the evidence.
    Until now the only way to learn the difference had been settled was to go
    back and look.

    Every resolution, not only the reachable ones. A fix is worth hearing about
    wherever it happened -- the reachability bar exists to keep bad news
    proportionate, and applying it to good news would report a narrower story
    than the true one.
    """
    rows = (
        (
            await session.execute(
                select(FindingEventRecord, Finding)
                .join(Finding, Finding.id == FindingEventRecord.finding_id)
                .where(
                    FindingEventRecord.organization_id == organization_id,
                    FindingEventRecord.observed_at > since,
                    FindingEventRecord.event == FindingEvent.RESOLVED,
                    # Verified by a scan, not moved by a person. A status change
                    # is intent; this notification is about evidence.
                    FindingEventRecord.scan_id.isnot(None),
                )
                .order_by(FindingEventRecord.observed_at)
                .limit(200)
            )
        )
        .all()
    )
    written = 0
    for event, finding in rows:
        written += await _write(
            session,
            organization_id,
            kind=NotificationKind.VERIFIED_FIX,
            subject_id=str(finding.id),
            event_at=event.observed_at,
            title=f"Fixed: {finding.title}",
            detail="A scan checked and the finding no longer holds.",
            link=f"/findings/{finding.id}",
        )
    return written


async def _coverage_drops(
    session: AsyncSession, organization_id: UUID, since: datetime
) -> int:
    """Readings that stopped arriving.

    The notification most products do not send, and the one this architecture is
    unusually placed to send honestly: a listing that fails degrades its rules to
    UNKNOWN rather than to PASS, so the score holds steady while the evidence
    under it thins out. Saying nothing would let a customer read an unchanged
    number as an unchanged estate.

    Keyed on the evidence key rather than the row, so a listing that fails on
    every scan is announced once and not once an hour. It becomes news again
    only when it recovers and fails afresh.
    """
    rows = (
        (
            await session.execute(
                select(Evidence)
                .where(
                    Evidence.organization_id == organization_id,
                    Evidence.collected_at > since,
                    Evidence.outcome.in_([TaskOutcome.FAILED, TaskOutcome.PARTIAL]),
                )
                .order_by(Evidence.collected_at)
                .limit(200)
            )
        )
        .scalars()
        .all()
    )
    written = 0
    for row in rows:
        partial = row.outcome is TaskOutcome.PARTIAL
        written += await _write(
            session,
            organization_id,
            kind=NotificationKind.COVERAGE_DROP,
            subject_id=row.evidence_key,
            event_at=row.collected_at,
            title=(
                f"Only part of {row.evidence_key} could be read"
                if partial
                else f"{row.evidence_key} could not be read"
            ),
            # PARTIAL is not a lesser failure. A listing missing an unknown
            # number of entries cannot support "none of them are public", which
            # is the same as not having read it -- and the sentence says so
            # rather than leaving a reader to infer it from a word.
            detail=(
                row.detail
                or (
                    "Checks that depend on it have no verdict, so the score "
                    "covers less of your estate than it did."
                )
            ),
            link="/scans",
        )
    return written


# ------------------------------------------------------------------- reading
async def unread_for(
    session: AsyncSession, organization_id: UUID, user_id: UUID, *, limit: int = 20
) -> tuple[list[Notification], int]:
    """The newest notifications, and how many of them this person has not seen.

    Both from one read of the same rows: a count computed by a second query
    could disagree with the list beside it, and a badge that says three above a
    panel showing two is the kind of thing people stop trusting the whole
    feature over.
    """
    rows = list(
        (
            await session.execute(
                select(Notification)
                .where(Notification.organization_id == organization_id)
                .order_by(Notification.event_at.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    watermark = (
        await session.execute(
            select(NotificationRead.read_through).where(
                NotificationRead.organization_id == organization_id,
                NotificationRead.user_id == user_id,
            )
        )
    ).scalar_one_or_none()

    if watermark is None:
        # Never opened the panel. Everything held is unread, which is the honest
        # answer -- and the cold-start bound above is what stops that being a
        # year of it.
        return rows, len(rows)
    return rows, sum(1 for row in rows if row.event_at > watermark)


async def mark_read(
    session: AsyncSession, organization_id: UUID, user_id: UUID
) -> datetime:
    """Move this person's watermark to now.

    Now rather than the newest notification's ``event_at``: the sweep runs on a
    timer, so a notification about something that happened a minute ago may not
    exist yet, and reading to the newest *stored* row would mark it seen before
    it was written.
    """
    read_through = datetime.now(UTC)
    await session.execute(
        insert(NotificationRead)
        .values(
            organization_id=organization_id,
            user_id=user_id,
            read_through=read_through,
        )
        .on_conflict_do_update(
            index_elements=["organization_id", "user_id"],
            set_={"read_through": read_through},
        )
    )
    return read_through
