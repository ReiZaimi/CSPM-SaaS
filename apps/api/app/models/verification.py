import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import RuleState, VerificationStatus
from app.models.base import Base, StrEnumType, TenantOwned, Timestamps, UUIDPrimaryKey


class RemediationVerification(UUIDPrimaryKey, TenantOwned, Timestamps, Base):
    """A claim that something was fixed, and CloudGuard's attempt to confirm it.

    "Verified fixed" is the strongest thing this product says, and until now the
    machinery behind it was a coincidence: a customer marked a task done, ran a
    scan whenever they got round to it, and the pipeline resolved the finding if
    that scan happened to produce a PASS. Nothing recorded what was expected,
    nothing looked again on its own, and every way of not-being-verified came
    out as the same silence -- the finding simply stayed open.

    A row here is the expectation, written the moment the customer claims the
    fix: this rule, on this asset, should now PASS. Every scan that reaches a
    verdict on that pair settles it or spends an attempt, and the attempts run
    on a backoff because a cloud takes time to agree with itself -- a check run
    a minute after a change reports the environment as it was, and reporting
    that as "still failing" teaches the customer to distrust the answer.

    The outcomes are deliberately three rather than two. STILL_FAILING is
    CloudGuard looking and disagreeing; INSUFFICIENT_EVIDENCE is CloudGuard
    failing to look. The second is CloudGuard's problem to explain rather than
    the customer's to fix, and telling them apart is the same discipline that
    keeps UNKNOWN out of PASS everywhere else in this system.
    """

    __tablename__ = "remediation_verifications"
    __table_args__ = (
        # One live verification per finding. A customer marking the same task
        # done twice is restating one claim, not making a second, and two
        # pending rows would spend two sets of attempts on one question.
        Index(
            "uq_remediation_verifications_open",
            "finding_id",
            unique=True,
            postgresql_where=text("status = 'PENDING'"),
        ),
        # What the scheduler reads on every tick.
        Index(
            "ix_remediation_verifications_due",
            "next_attempt_at",
            postgresql_where=text("status = 'PENDING'"),
        ),
    )

    finding_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    # The task whose completion made the claim, when there was one. Nullable
    # because a verification can also be opened by someone simply saying a
    # finding is fixed, and because a task may be deleted while the question it
    # raised is still open.
    remediation_task_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("remediation_tasks.id", ondelete="SET NULL")
    )

    # What must be observed, spelled out rather than implied by the finding.
    # A finding can be reclassified or its rule retired; the expectation is a
    # statement about a moment and has to survive both.
    rule_id: Mapped[str] = mapped_column(String(32), nullable=False)
    resource_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_resources.id", ondelete="CASCADE")
    )
    # Which scope has to be read to answer the question. Carried here so the
    # scheduler can start the cheapest scan that could settle this -- one
    # subscription -- without walking back through the finding to the asset.
    cloud_account_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_accounts.id", ondelete="CASCADE")
    )
    connection_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_connections.id", ondelete="CASCADE")
    )

    status: Mapped[VerificationStatus] = mapped_column(
        StrEnumType(VerificationStatus, 24),
        nullable=False,
        default=VerificationStatus.PENDING,
        index=True,
    )
    # When the customer said it was fixed. Every "how long did this take"
    # question is measured from here, not from when the row was written.
    claimed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    claimed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))

    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # When it is worth looking again. NULL once settled.
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # What the rule said last time anyone looked, or NULL if nobody has yet.
    last_state: Mapped[RuleState | None] = mapped_column(StrEnumType(RuleState, 16))
    # Whether any attempt reached an explicit FAIL. Decides the terminal answer
    # when the attempts run out: having once seen the check fail is a stronger
    # and truer statement than "we could not tell", so a run of UNKNOWNs after
    # a definite failure still settles as STILL_FAILING.
    observed_failure: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    # The sentence a customer reads. Written for them, not for a log.
    detail: Mapped[str | None] = mapped_column(Text)

    # What has to be true for this to close, in the provider's own vocabulary.
    # Copied from the rule's declaration when the claim is made rather than read
    # back at display time, for the reason a finding copies its remediation
    # prose: a rule's declaration can change, and somebody looking at a two-week
    # -old claim should see what was expected of them when they made it.
    expected_state: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    verified_by_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )
    settled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
