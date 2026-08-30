"""Deciding what a scan collects, before it collects it.

Two questions, answered in that order.

**What does anything need?** The union of every enabled rule's
``requires_evidence``, plus the connector's ``baseline_evidence`` -- the
inventory and graph listings no rule judges but the product is built from. That
union is the requirement, and it is derived rather than written down, so a rule
added with a new dependency starts being collected for and the last rule to read
a listing taking it with it when it goes.

**What do we already hold?** Evidence carries provenance and a content hash, so
a complete reading from an earlier scan can be carried into this one instead of
being taken again. Almost none of it should be, and :attr:`EvidenceKey
.reuse_window` is where that judgement lives -- per key, off by default, granted
only where a stale reading cannot change a verdict. This module asks the
question; it does not decide the policy.

What comes out is a :class:`CollectionPlan`, which the provider's plan is
filtered through. Both halves are conservative in the same direction: an
unanswerable question -- a key with no window, a blob that retention has
already pruned, an evidence row that is anything other than COMPLETE -- means
read it again. Collecting something twice costs a request; concluding from
evidence that was not there costs the only thing this product sells.
"""

from collections.abc import Iterable, Sequence
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.evidence import EvidenceKey
from app.connectors.planning import CarriedReading, CollectionPlan
from app.core.enums import Provider, TaskOutcome
from app.core.logging import get_logger
from app.models.scan import Evidence, EvidenceBlob
from app.rules.base import SecurityRule
from app.rules.registry import enabled_rules

log = get_logger(__name__)


def required_evidence(
    provider: Provider,
    baseline: Iterable[EvidenceKey],
    rules: Sequence[SecurityRule] | None = None,
) -> frozenset[EvidenceKey]:
    """Every key this provider's scan has a reason to collect.

    Rules are filtered by provider, because their keys are: an AWS rule names
    AWS evidence, and running its requirements past the Azure plan would ask
    for listings Azure does not have. Harmless today -- the plan ignores what it
    cannot produce -- and a wrong answer to "what is this scan for" the moment a
    second provider exists.
    """
    considered = enabled_rules() if rules is None else rules
    required = set(baseline)
    for rule in considered:
        if rule.provider is not provider:
            continue
        required.update(rule.requires_evidence)
    return frozenset(required)


async def plan_collection(
    session: AsyncSession,
    *,
    organization_id: UUID,
    provider: Provider,
    required: frozenset[EvidenceKey],
    scan_id: UUID,
    cloud_account_id: UUID | None = None,
    connection_id: UUID | None = None,
    now: datetime | None = None,
) -> CollectionPlan:
    """What to read now for one scope, and what to carry forward into it.

    ``cloud_account_id`` names a subscription; its absence means the tenant
    directory, which is scoped to the connection instead. Evidence is looked up
    the same way it was written, so a reading of one subscription can never be
    carried into another -- the two are different environments that happen to
    share an owner.
    """
    moment = now or datetime.now(UTC)
    windows = {key: key.reuse_window for key in required}
    reusable = {key: window for key, window in windows.items() if window is not None}
    if not reusable:
        return CollectionPlan(collect=required)

    held = await _newest_readings(
        session,
        organization_id=organization_id,
        provider=provider,
        keys=set(reusable),
        oldest=moment - max(reusable.values()),
        scan_id=scan_id,
        cloud_account_id=cloud_account_id,
        connection_id=connection_id,
    )

    fresh: dict[EvidenceKey, Evidence] = {}
    for key, window in reusable.items():
        row = held.get(key.value)
        # A reading is carried only if it is complete, still inside its own
        # window, and still has its payload. Each of the three is a separate
        # way for the answer to be "no", and none of them is an error worth
        # reporting: the scan simply reads it again.
        if row is None or row.content_hash is None:
            continue
        if row.outcome is not TaskOutcome.COMPLETE:
            continue
        if _age(row.collected_at, moment) > window:
            continue
        fresh[key] = row

    payloads = await _payloads_for(
        session, organization_id, {row.content_hash for row in fresh.values() if row.content_hash}
    )

    carried: dict[EvidenceKey, CarriedReading] = {}
    for key, row in fresh.items():
        payload = payloads.get(row.content_hash or "")
        if payload is None:
            # The row says what was read; retention has taken what it read.
            # Provenance outlives the payload deliberately (see ``Evidence``),
            # so this is an ordinary state and not a broken reference.
            continue
        carried[key] = CarriedReading(
            key=key,
            payload=payload,
            collected_at=_aware(row.collected_at),
            item_count=row.item_count,
            permissions=tuple(row.permissions or ()),
        )

    if carried:
        log.info(
            "scan.evidence_carried",
            scan_id=str(scan_id),
            cloud_account_id=str(cloud_account_id) if cloud_account_id else None,
            keys=sorted(key.value for key in carried),
        )
    return CollectionPlan(collect=required, carried=carried)


async def _newest_readings(
    session: AsyncSession,
    *,
    organization_id: UUID,
    provider: Provider,
    keys: set[EvidenceKey],
    oldest: datetime,
    scan_id: UUID,
    cloud_account_id: UUID | None,
    connection_id: UUID | None,
) -> dict[str, Evidence]:
    """The most recent reading of each candidate key, for this scope alone.

    One query returning at most a handful of rows: only keys with a window are
    asked about, and the oldest window bounds the scan of the index. The
    per-key window is applied afterwards, in Python, because it differs by key
    and a query expressing that would be one CASE per key for no gain.
    """
    scope = (
        Evidence.cloud_account_id == cloud_account_id
        if cloud_account_id is not None
        else Evidence.cloud_account_id.is_(None)
    )
    statement = (
        select(Evidence)
        .where(
            Evidence.organization_id == organization_id,
            Evidence.provider == provider,
            Evidence.evidence_key.in_({key.value for key in keys}),
            Evidence.collected_at >= oldest,
            # This scan's own rows are not evidence of anything yet. A retried
            # collection step discards them before it runs again, so seeing one
            # here would mean carrying forward the attempt that is being
            # replaced.
            Evidence.scan_id != scan_id,
            scope,
        )
        .order_by(Evidence.collected_at.desc())
    )
    if cloud_account_id is None and connection_id is not None:
        statement = statement.where(Evidence.connection_id == connection_id)

    newest: dict[str, Evidence] = {}
    for row in (await session.execute(statement)).scalars():
        newest.setdefault(row.evidence_key, row)
    return newest


async def _payloads_for(
    session: AsyncSession, organization_id: UUID, hashes: set[str]
) -> dict[str, dict]:
    if not hashes:
        return {}
    rows = (
        await session.execute(
            select(EvidenceBlob).where(
                EvidenceBlob.organization_id == organization_id,
                EvidenceBlob.content_hash.in_(hashes),
            )
        )
    ).scalars()
    return {row.content_hash: row.payload for row in rows}


def _aware(moment: datetime) -> datetime:
    """PostgreSQL hands back an aware datetime; a fixture may not."""
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def _age(collected_at: datetime, now: datetime) -> timedelta:
    return now - _aware(collected_at)
