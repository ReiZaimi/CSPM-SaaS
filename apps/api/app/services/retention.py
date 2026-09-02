"""Letting go of evidence without letting go of what it proved.

Two things grow without bound and neither has ever been pruned: the raw captures
in ``cloud_snapshots``, and the content-addressed payloads in
``evidence_blobs``. Both are kept for good reasons -- a capture is what lets a
scan be re-evaluated against improved rules, and a payload is what a citation
points at -- and both are the largest rows in the schema.

**The invariant this must not break.** The newest capture for each subscription
is what an *applied* replay reads: a replay of the newest snapshots may resolve
findings, and every older one is advisory and may not (``scanner.py``,
``evaluation_only``). Pruning a newest capture would not fail loudly -- it would
quietly turn "did the fix work" into an answer nobody can act on. So it is
excluded by construction here rather than by choosing a window long enough that
it probably will not happen.

**What is deliberately not pruned.** ``evidence`` rows are the provenance
record, and they are small: one row per key per subscription per scan, against a
payload that is the listing itself. They are also what a finding's citation
joins to. Deleting the record of what was read to save the size of the record of
what was read is the wrong trade, and it is the trade that would make a finding
raised last year unanswerable.

The order matters: captures first, then payloads. A payload is kept alive by
being re-read rather than by being referenced, so pruning captures cannot orphan
one -- but doing payloads first would leave a window where a capture points at
bytes that have just gone.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import CloudSnapshot, EvidenceBlob


async def prune_snapshots(
    session: AsyncSession, organization_id: UUID, *, keep_days: int
) -> int:
    """Delete raw captures past the window, never the newest of each scope.

    "Scope" is a subscription, or the tenant directory read through one
    connection. Both are kept because both are half of a replay: a tenant-wide
    scan restores its directory capture alongside each subscription's, and a
    directory pruned out from under it would leave the identity rules with
    nothing to read while the subscription rules carried on.
    """
    cutoff = datetime.now(UTC) - timedelta(days=keep_days)

    keep = set(await _newest_per_scope(session, organization_id))
    stale = (
        (
            await session.execute(
                select(CloudSnapshot.id).where(
                    CloudSnapshot.organization_id == organization_id,
                    CloudSnapshot.created_at < cutoff,
                )
            )
        )
        .scalars()
        .all()
    )
    doomed = [snapshot_id for snapshot_id in stale if snapshot_id not in keep]
    if not doomed:
        return 0

    await session.execute(
        delete(CloudSnapshot).where(
            CloudSnapshot.organization_id == organization_id,
            CloudSnapshot.id.in_(doomed),
        )
    )
    return len(doomed)


async def _newest_per_scope(
    session: AsyncSession, organization_id: UUID
) -> list[UUID]:
    """The capture that must survive for each subscription and each directory.

    Two ``DISTINCT ON`` queries rather than one over a coalesced key. The two
    scopes are different things -- a subscription's resources and a tenant's
    directory -- and a single query would have to invent a key that means
    "whichever of these is not null", which reads as a trick and breaks the day
    a third scope exists.

    Ties broken by id as well as time, matching ``_newest_snapshot_ids`` in the
    pipeline: two captures written in the same transaction share a timestamp,
    and the replay path and this one must agree on which of them is newest or
    retention would delete the one a replay is about to read.
    """
    accounts = (
        (
            await session.execute(
                select(CloudSnapshot.id)
                .where(
                    CloudSnapshot.organization_id == organization_id,
                    CloudSnapshot.cloud_account_id.is_not(None),
                )
                .distinct(CloudSnapshot.cloud_account_id)
                .order_by(
                    CloudSnapshot.cloud_account_id,
                    CloudSnapshot.created_at.desc(),
                    CloudSnapshot.id.desc(),
                )
            )
        )
        .scalars()
        .all()
    )
    directories = (
        (
            await session.execute(
                select(CloudSnapshot.id)
                .where(
                    CloudSnapshot.organization_id == organization_id,
                    CloudSnapshot.cloud_account_id.is_(None),
                )
                .distinct(CloudSnapshot.connection_id)
                .order_by(
                    CloudSnapshot.connection_id,
                    CloudSnapshot.created_at.desc(),
                    CloudSnapshot.id.desc(),
                )
            )
        )
        .scalars()
        .all()
    )
    return [*accounts, *directories]


async def prune_blobs(
    session: AsyncSession, organization_id: UUID, *, keep_days: int
) -> int:
    """Delete payloads nothing has re-read for a while.

    Measured from ``last_seen_at`` rather than ``first_stored_at``, which is the
    whole reason that column exists: an estate that has not changed in six
    months stores one copy and touches it on every scan, and a payload still
    being collected must not look like one whose last reference was months ago.

    **A pruned payload does not invalidate anything that cited it.** A
    finding's citation copies the hash rather than holding a foreign key
    precisely so this can happen: the citation still says truthfully what was
    read, when, and under which permission, and the API reports the payload as
    unavailable rather than offering a link that fails.
    """
    cutoff = datetime.now(UTC) - timedelta(days=keep_days)

    # **The interlock.** A capture used to be self-contained; since 0027 it is a
    # manifest naming the hashes of its readings, so a blob can be the only copy
    # of part of a capture that is still well inside its own window.
    #
    # Deleting one would not fail here. It would fail months later, at the one
    # moment somebody replays a capture to check whether a fix held, and the
    # replay would be of an estate missing whatever the pruned reading held --
    # a resolution reached by omission. So a hash any surviving manifest still
    # names is kept whatever its age says.
    spoken_for = {
        content_hash
        for (hashes,) in (
            await session.execute(
                select(CloudSnapshot.manifest["payload_hashes"]).where(
                    CloudSnapshot.organization_id == organization_id,
                    CloudSnapshot.manifest.is_not(None),
                )
            )
        ).all()
        for content_hash in (hashes or {}).values()
    }

    doomed = (
        (
            await session.execute(
                select(EvidenceBlob.content_hash).where(
                    EvidenceBlob.organization_id == organization_id,
                    EvidenceBlob.last_seen_at < cutoff,
                )
            )
        )
        .scalars()
        .all()
    )
    unreferenced = [h for h in doomed if h not in spoken_for]
    if not unreferenced:
        return 0

    result = await session.execute(
        delete(EvidenceBlob).where(
            EvidenceBlob.organization_id == organization_id,
            EvidenceBlob.content_hash.in_(unreferenced),
        )
    )
    return int(result.rowcount or 0)


async def prune(
    session: AsyncSession,
    organization_id: UUID,
    *,
    snapshot_days: int,
    evidence_days: int,
) -> dict[str, int]:
    """One organization's turn. Captures first, then payloads."""
    snapshots = await prune_snapshots(
        session, organization_id, keep_days=snapshot_days
    )
    blobs = await prune_blobs(session, organization_id, keep_days=evidence_days)
    return {"snapshots": snapshots, "blobs": blobs}
