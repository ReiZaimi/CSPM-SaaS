import uuid
from datetime import UTC, datetime
from typing import ClassVar

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import (
    Provider,
    ScanStatus,
    ScanStepKind,
    ScanStepStatus,
    ScanTrigger,
    TaskOutcome,
)
from app.models.base import Base, StrEnumType, TenantOwned, Timestamps, UUIDPrimaryKey


class Scan(UUIDPrimaryKey, TenantOwned, Timestamps, Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index(
            "ix_scans_replay_of_scan_id",
            "replay_of_scan_id",
            postgresql_where=text("replay_of_scan_id IS NOT NULL"),
        ),
    )

    # One of these two says what the scan covers.
    #
    # ``connection_id`` is the tenant-wide form: every in-scope subscription
    # beneath that connection, collected into one scan. ``cloud_account_id`` is
    # the single-subscription form, which predates it and is still how a rescan
    # of one finding works.
    #
    # Nullable on both sides rather than a discriminator column, because the
    # honest statement is "a scan is scoped to one of these" and a third column
    # asserting which would be a second source of truth for a fact the first two
    # already carry.
    cloud_account_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_accounts.id", ondelete="CASCADE")
    )
    connection_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("cloud_connections.id", ondelete="CASCADE"),
        index=True,
    )
    status: Mapped[ScanStatus] = mapped_column(
        StrEnumType(ScanStatus, 24), nullable=False, default=ScanStatus.QUEUED, index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    resource_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rule_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    error_message: Mapped[str | None] = mapped_column(Text)

    # Who asked for this run. Not an FK: auth.users belongs to Supabase.
    triggered_by_user_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))
    # And why. A NULL user became ambiguous once scans could start themselves --
    # an old manual scan whose user record had gone looked exactly like a
    # scheduled one.
    trigger: Mapped[ScanTrigger] = mapped_column(
        StrEnumType(ScanTrigger, 16), nullable=False, default=ScanTrigger.MANUAL
    )

    # Set when this run re-evaluated an earlier scan's stored snapshot instead
    # of collecting. ``SET NULL`` so pruning the original execution log does not
    # take the replay with it.
    replay_of_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )
    # True when this run evaluated a snapshot that is no longer the newest for
    # its account, and therefore wrote coverage but touched no findings. A
    # month-old capture can say what the rules would have found; it cannot say
    # what is true now, and must never resolve or reopen anything.
    evaluation_only: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )

    # How far along a running scan is. Status moves in five coarse jumps, so a
    # large tenant sits on one of them long enough to look stalled.
    progress_done: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    progress_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    @property
    def covers_whole_connection(self) -> bool:
        """Whether this scan spans every in-scope subscription."""
        return self.connection_id is not None

    @property
    def duration_seconds(self) -> int | None:
        """Elapsed time, live while running and fixed once finished."""
        if self.started_at is None:
            return None
        end = self.completed_at or datetime.now(UTC)
        return max(0, int((end - self.started_at).total_seconds()))

    # Held by whichever worker is running this scan, and extended as it makes
    # progress. A worker that dies stops extending, which is what lets an
    # abandoned scan be reclaimed instead of blocking its connection for ever.
    # NULL while queued: nothing has claimed it yet.
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # How long a running scan's lease lasts. Long enough to cover the longest
    # stretch between two signs of life -- a large tenant's finding
    # reconciliation, which reports nothing while it runs -- and short enough
    # that a customer whose worker was redeployed is not locked out for an hour.
    LEASE_SECONDS: ClassVar[int] = 900

    # How long a scan may sit queued before nobody is coming for it. Much more
    # generous than the lease, because a deep queue is normal and a lost message
    # is not: the cost of waiting is a delayed scan, and the cost of reaping too
    # early is failing one that was about to run.
    QUEUE_GRACE_SECONDS: ClassVar[int] = 3600

    # How long a scan may sit unclaimed before the UI stops implying it is
    # about to start. A worker picks work up in seconds when one is running, so
    # minutes of silence means nothing is listening -- almost always the Celery
    # worker service not deployed, or unable to reach Redis.
    QUEUE_PATIENCE_SECONDS: ClassVar[int] = 120

    @property
    def stuck_in_queue(self) -> bool:
        """Queued long enough that waiting no longer explains it."""
        if self.status != ScanStatus.QUEUED or self.created_at is None:
            return False
        waited = datetime.now(UTC) - self.created_at
        return waited.total_seconds() > self.QUEUE_PATIENCE_SECONDS
    # Category-level collection failures, e.g. {"storage": "timeout"}. Drives
    # PARTIAL status and the UNKNOWN degradation path (AZURE_INTEGRATION.md section 5).
    collection_errors: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)


class CloudSnapshot(UUIDPrimaryKey, TenantOwned, Base):
    """The raw, pre-normalization capture. Every scan produces exactly one.

    Kept verbatim so a scan can be replayed against new rules, and so drift
    between two scans is a diff rather than an inference.
    """

    __tablename__ = "cloud_snapshots"
    # One per subscription per scan, not one per scan. A tenant-wide scan reads
    # several subscriptions and each provider payload is kept as its own
    # verbatim record -- merging them before storage would destroy the property
    # the snapshot exists for, which is that it is what Azure actually said.
    #
    # Plus at most one directory capture per scan, which is a reading of the
    # tenant rather than of any subscription in it. That one carries a NULL
    # account, so this constraint does not bound it; migration 0008's partial
    # unique index on (scan_id) WHERE cloud_account_id IS NULL does.
    __table_args__ = (
        UniqueConstraint(
            "scan_id", "cloud_account_id", name="uq_cloud_snapshots_scan_account"
        ),
    )

    # Exactly one subscription for an account capture, NULL for the scan's
    # directory capture.
    cloud_account_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_accounts.id", ondelete="CASCADE")
    )
    # Which connection this capture was taken through. Always set for a
    # directory capture, since that is the only thing left to attribute it to.
    connection_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_connections.id", ondelete="CASCADE")
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    snapshot_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    data: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ScanRuleResult(UUIDPrimaryKey, TenantOwned, Base):
    """Per-(scan, rule) aggregate. PASS/NOT_APPLICABLE live here rather than as
    millions of per-resource rows (RULE_ENGINE.md section 2)."""

    __tablename__ = "scan_rule_results"
    __table_args__ = (UniqueConstraint("scan_id", "rule_id"),)

    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(32), nullable=False)

    evaluated_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    passed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unknown_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    not_applicable_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ScanEvaluationGap(UUIDPrimaryKey, TenantOwned, Base):
    """One row per UNKNOWN evaluation -- why we could not tell.

    This is the coverage ledger. An UNKNOWN never becomes a Finding, but it must
    never vanish either, or "84/100" would silently mean "84/100 of what we
    happened to be able to look at".
    """

    __tablename__ = "scan_evaluation_gaps"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(32), nullable=False)
    # NULL for AGGREGATE-scope rules, which are not about any single resource.
    resource_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_resources.id", ondelete="CASCADE")
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Evidence(UUIDPrimaryKey, TenantOwned, Base):
    """One reading: what was collected, for which scope, and under what terms.

    The sibling of ``ScanRuleResult``. That table records what the rules
    concluded; this records whether they were entitled to conclude anything --
    and before it existed the answer lived only as a sentence in
    ``scans.collection_errors``, which could be read by a person and by nothing
    else.

    Structured because the interesting questions are not answerable from prose:
    which subscription is failing, whether a listing is *failing* or merely
    *truncated*, whether this has been happening for a week. A string that
    concatenates all of that is a report; these are the facts behind it.

    It now also records the successes, which is the half that was missing. A
    row says what was read, when it was read from the provider, which
    permissions the read was made under, and the hash of the payload it
    produced -- so a finding is traceable to a specific reading rather than to
    a scan holding one blob of everything.

    ``content_hash`` points into :class:`EvidenceBlob` without a foreign key,
    deliberately. Retention prunes payloads long before it prunes the record
    that they were collected, and a row whose blob has aged out still says
    truthfully what was read and what came of it.
    """

    __tablename__ = "evidence"
    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "cloud_account_id",
            "evidence_key",
            name="uq_evidence_scan_account_key",
        ),
        Index("ix_evidence_outcome", "organization_id", "outcome"),
        # What the evidence planner will ask: what do we already hold for this
        # scope, recent enough to reuse.
        Index(
            "ix_evidence_freshness",
            "organization_id",
            "cloud_account_id",
            "evidence_key",
            "collected_at",
        ),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    # Which subscription this reading is about. A tenant-wide scan reads each
    # one separately and they fail separately, so an outcome that did not name
    # its subscription would be unactionable in exactly the case the tenant-wide
    # scan was built for.
    #
    # NULL for the scan's directory tasks, which are a reading of the tenant.
    # Attributing those to a subscription would be the same mistake one layer
    # down: a directory read that failed did not fail *in* a subscription, and
    # naming one would send someone to check a subscription that is fine.
    cloud_account_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("cloud_accounts.id", ondelete="CASCADE"),
    )
    connection_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_connections.id", ondelete="CASCADE")
    )
    provider: Mapped[Provider] = mapped_column(
        StrEnumType(Provider, 16), nullable=False, default=Provider.AZURE
    )
    # Which unit of collection produced this, e.g. "storage_accounts". The same
    # value a rule declares in ``requires_evidence``.
    evidence_key: Mapped[str] = mapped_column(String(64), nullable=False)
    # The permission bucket it belongs to, e.g. "storage".
    category: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    outcome: Mapped[TaskOutcome] = mapped_column(
        StrEnumType(TaskOutcome, 16), nullable=False
    )
    detail: Mapped[str | None] = mapped_column(Text)
    # How much came back. Meaningful next to PARTIAL, where the useful question
    # is "some of what?".
    item_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # When the provider was read, not when this row was written. The two are the
    # same for a live scan and months apart for a replay, and every question
    # about freshness is about the first.
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # The actions the read was made under, copied from the task's own
    # declaration. Turns "we could not read storage" into "we could not read
    # storage, and this is the action your role is missing" without anyone
    # correlating two files by hand.
    permissions: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # The provider calls this reading was made with: ``[{"path", "api_version"}]``.
    #
    # The api-version is the load-bearing half. Azure's response shape is a
    # function of it, so a field missing from a stored capture is ambiguous
    # between "the customer did not set it" and "we asked a contract that does
    # not return it" -- and a rule reading the second as the first raises a
    # finding out of CloudGuard's own staleness. Recorded per reading rather
    # than looked up from today's collector, because the collector moves and
    # the reading does not.
    endpoints: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # SHA-256 of the payload, or NULL where there is no payload: a task that
    # failed outright collected nothing, and a hash of nothing would say
    # otherwise.
    content_hash: Mapped[str | None] = mapped_column(String(64))
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class EvidenceBlob(Base):
    """One stored copy of a payload, addressed by its content.

    A customer scanning daily whose network security groups have not changed in
    a month stored thirty identical copies of them. Keyed by hash, they store
    one -- and an unchanged environment costs almost nothing to keep looking at,
    which is what makes daily scanning affordable rather than merely possible.

    Scoped per organization, and that is a security decision rather than a
    modelling one. Content-addressed storage shared across tenants would
    deduplicate correctly and still be wrong: whether a write finds an existing
    row is observable, so a shared table would let one tenant learn that another
    holds identical bytes. Inside one tenant the saving is the same, because the
    repetition being removed is the same environment read again tomorrow.
    """

    __tablename__ = "evidence_blobs"
    __table_args__ = (
        Index("ix_evidence_blobs_last_seen", "organization_id", "last_seen_at"),
    )

    # Half the primary key rather than a plain tenant column, which is what
    # makes the isolation above structural: there is no way to address a blob
    # without naming whose it is.
    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        primary_key=True,
    )
    content_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_stored_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # Bumped every time a scan stores this content again. What retention reads:
    # the oldest payloads nothing has referenced lately.
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ScanStep(UUIDPrimaryKey, TenantOwned, Base):
    """One durably recorded stage of a scan.

    A scan used to be a single Celery task: resolve the scope, read every
    subscription in sequence, interpret the lot. A worker redeployed after
    reading nine subscriptions out of ten had read nothing, because nothing
    recorded that the nine were done; fifty subscriptions were fifty sequential
    collections inside one thirty-minute limit; and retrying one failure meant
    retrying everything that had already worked.

    A step is claimed under a lease, retried on its own, and settled
    independently of its siblings. The claim is the concurrency control: an
    ``UPDATE ... WHERE status = 'PENDING' RETURNING id`` that exactly one worker
    wins, so two workers advancing the same scan cannot both run a step.
    """

    __tablename__ = "scan_steps"
    __table_args__ = (
        Index("ix_scan_steps_scan_status", "scan_id", "status"),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[ScanStepKind] = mapped_column(
        StrEnumType(ScanStepKind, 16), nullable=False
    )
    # Which subscription a COLLECT step reads. NULL on the step that reads the
    # tenant directory, and on PLAN and ANALYZE, which are about the scan rather
    # than about any one scope.
    cloud_account_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_accounts.id", ondelete="CASCADE")
    )

    status: Mapped[ScanStepStatus] = mapped_column(
        StrEnumType(ScanStepStatus, 16), nullable=False, default=ScanStepStatus.PENDING
    )
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    worker_id: Mapped[str | None] = mapped_column(String(128))
    error: Mapped[str | None] = mapped_column(Text)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # How long a claimed step may go without a sign of life. Shorter than the
    # scan's own lease: a step is one subscription's collection or one
    # evaluation, and a worker that has stopped reporting for this long has
    # stopped.
    LEASE_SECONDS: ClassVar[int] = 600

    @property
    def is_directory(self) -> bool:
        """Whether this COLLECT step reads the tenant rather than a subscription."""
        return self.kind == ScanStepKind.COLLECT and self.cloud_account_id is None

    def describe(self) -> str:
        """What this step is, for a log line or an error message."""
        if self.kind != ScanStepKind.COLLECT:
            return self.kind.value.lower()
        return "the tenant directory" if self.is_directory else "one subscription"
