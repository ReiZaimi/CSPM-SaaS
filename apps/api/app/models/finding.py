import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Numeric, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import FindingStatus, Severity
from app.models.base import Base, StrEnumType, TenantOwned, Timestamps, UUIDPrimaryKey


class Finding(UUIDPrimaryKey, TenantOwned, Timestamps, Base):
    """A technical observation: "we saw this, and it is wrong."

    Identity is (organization, rule, resource) -- a re-detection updates the
    existing row rather than piling up duplicates every scan. ``scan_id`` records
    the scan that most recently detected it.
    """

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "rule_id", "resource_id", name="uq_findings_org_rule_resource"
        ),
        Index("ix_findings_org_status", "organization_id", "status"),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    rule_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    # NULL for AGGREGATE-scope findings that are about the tenant, not a resource.
    resource_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_resources.id", ondelete="CASCADE")
    )

    severity: Mapped[Severity] = mapped_column(StrEnumType(Severity, 16), nullable=False)
    status: Mapped[FindingStatus] = mapped_column(
        StrEnumType(FindingStatus, 24), nullable=False, default=FindingStatus.OPEN
    )
    title: Mapped[str] = mapped_column(String(400), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Snapshot-copied from the rule at creation so later edits to a rule's
    # guidance do not rewrite the history of old findings.
    remediation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    rule_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")

    risk_score: Mapped[float | None] = mapped_column(Numeric(5, 2))

    first_detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # The scan whose PASS verified the fix. This IS the verification -- there is
    # no human "mark as verified" step (RULE_ENGINE.md section 3).
    resolved_by_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )


class FindingEvidence(Base):
    """Which readings a finding rests on, and enough about each to check one
    after the reading itself has been pruned.

    A finding already carries an *excerpt* of its evidence in ``evidence``. That
    is a copy, and a copy cannot be re-verified: it says what a rule saw, not
    where it came from. This says where it came from -- which listing, taken
    when, under which permissions, and the hash of the bytes it produced.

    Deriving this at read time from ``SecurityRule.requires_evidence`` is the
    thing it replaces, and the reason is that the derivation is wrong exactly
    where it matters. Evidence may be *carried* from an earlier scan when a key
    opts into reuse, and a replay evaluates a capture some other scan collected,
    so "the evidence rows of the scan that raised this finding" names the wrong
    reading in both cases -- confidently, and with no way to tell.

    Keyed on ``(finding_id, evidence_key)``, so each key is cited once and the
    row is replaced when the reading is. Keying on ``evidence_id`` would
    accumulate one row per scan for ever, and the history of what a finding used
    to rest on is ``finding_events``' job rather than this table's.
    """

    __tablename__ = "finding_evidence"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        primary_key=True,
    )
    evidence_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )

    # The reading itself, while it exists. ``SET NULL`` rather than ``CASCADE``
    # because findings outlive scans -- a pruned scan takes its evidence rows
    # with it, and a citation that vanished with them would leave the finding
    # claiming nothing rather than claiming something no longer inspectable.
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("evidence.id", ondelete="SET NULL")
    )

    # The citation, copied so it survives the row above. Same discipline
    # ``Evidence.content_hash`` follows toward ``EvidenceBlob``: retention
    # prunes payloads long before it prunes the record that they were
    # collected, and a record that outlives its payload still says truthfully
    # what was read.
    #
    # NULL where the reading produced nothing -- a failed collection is still
    # cited, because "we tried, at this time, under this permission" is
    # provenance too, and it is the provenance behind an UNKNOWN.
    content_hash: Mapped[str | None] = mapped_column(String(64))
    # When the *provider* was read. For a carried reading this is older than
    # the scan that raised the finding, which is the whole point: it lets a
    # finding say what it rests on and how old that is in one answer.
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # The scan that collected it, which is not necessarily the scan that raised
    # the finding. No foreign key: this survives that scan's deletion.
    source_scan_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))
