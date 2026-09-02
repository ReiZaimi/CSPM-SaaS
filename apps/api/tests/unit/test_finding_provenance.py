"""Answering "how do you know?".

The endpoint assembles a citation from three places -- the link, the reading it
points at, and whether the payload is still stored -- and each of the three can
be absent for a different reason. Conflating any two of them turns a checkable
claim back into one a customer has to take on trust, which is the thing the
whole evidence chain exists to avoid.

The distinction these are mostly about: ``None`` means CloudGuard recorded no
citation, ``[]`` would mean the rule reads nothing. A finding raised before the
link existed is the first, and reporting it as the second would be the product
asserting its rule needs no evidence.
"""

import uuid
from datetime import UTC, datetime, timedelta

from app.core.deps import TenantContext
from app.core.enums import Role, TaskOutcome
from app.core.security import AuthenticatedUser
from app.models.finding import Finding, FindingEvidence
from app.models.scan import Evidence
from app.services.findings import load_provenance

NOW = datetime.now(UTC)
ORG = uuid.uuid4()
SUB = uuid.uuid4()


class Result:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def scalars(self):
        return self

    def all(self) -> list:
        return self._rows


class FakeSession:
    """Answers each of the three queries by what it selects from."""

    def __init__(
        self,
        *,
        links: list[FindingEvidence],
        readings: list[Evidence],
        stored_hashes: list[str],
    ) -> None:
        self.links = links
        self.readings = readings
        self.stored = stored_hashes

    async def execute(self, statement: object) -> Result:
        text = str(statement)
        if "FROM finding_evidence" in text:
            return Result(self.links)
        if "FROM evidence_blobs" in text:
            return Result(self.stored)
        if "FROM evidence" in text:
            return Result(self.readings)
        return Result([])


def tenant() -> TenantContext:
    return TenantContext(
        user=AuthenticatedUser(id=uuid.uuid4()), organization_id=ORG, role=Role.OWNER
    )


def a_finding() -> Finding:
    finding = Finding(
        organization_id=ORG,
        rule_id="AZ-STO-001",
        rule_version="1.0",
        status="OPEN",  # type: ignore[arg-type]
    )
    finding.id = uuid.uuid4()
    return finding


def a_link(
    key: str,
    *,
    evidence_id: uuid.UUID | None,
    content_hash: str | None = "a" * 64,
    collected_at: datetime | None = None,
) -> FindingEvidence:
    return FindingEvidence(
        organization_id=ORG,
        finding_id=uuid.uuid4(),
        evidence_key=key,
        evidence_id=evidence_id,
        content_hash=content_hash,
        collected_at=collected_at or NOW,
        source_scan_id=uuid.uuid4(),
    )


def a_reading(evidence_id: uuid.UUID, key: str) -> Evidence:
    row = Evidence(
        organization_id=ORG,
        scan_id=uuid.uuid4(),
        cloud_account_id=SUB,
        evidence_key=key,
        category="storage",
        outcome=TaskOutcome.COMPLETE,
        item_count=41,
        collected_at=NOW,
        permissions=["Microsoft.Storage/storageAccounts/read"],
        content_hash="a" * 64,
        byte_size=900,
    )
    row.id = evidence_id
    return row


# ------------------------------------------------- nothing recorded vs nothing
async def test_a_finding_with_no_citations_answers_none_not_empty() -> None:
    """The one distinction the endpoint exists to preserve.

    A finding raised before provenance was recorded has no rows. Reporting that
    as ``[]`` would say its rule reads nothing -- a claim about the rule, made
    on the strength of a gap in CloudGuard's own history.
    """
    session = FakeSession(links=[], readings=[], stored_hashes=[])

    result = await load_provenance(session, tenant(), a_finding())  # type: ignore[arg-type]

    assert result is None


# --------------------------------------------------------------- the citation
async def test_a_citation_carries_the_permission_the_read_was_made_under() -> None:
    evidence_id = uuid.uuid4()
    session = FakeSession(
        links=[a_link("storage_accounts", evidence_id=evidence_id)],
        readings=[a_reading(evidence_id, "storage_accounts")],
        stored_hashes=["a" * 64],
    )

    rows = await load_provenance(session, tenant(), a_finding())  # type: ignore[arg-type]

    assert rows is not None
    assert rows[0]["permissions"] == ["Microsoft.Storage/storageAccounts/read"]
    assert rows[0]["item_count"] == 41
    assert rows[0]["outcome"] is TaskOutcome.COMPLETE
    assert rows[0]["cloud_account_id"] == SUB


async def test_age_is_computed_from_when_the_provider_was_read() -> None:
    """Not from when the scan ran, and not left to the client.

    A carried reading is older than the scan that raised the finding, which is
    the number a customer actually wants. Computing it server-side also stops a
    reading looking four days old on one machine and four hours old on another.
    """
    evidence_id = uuid.uuid4()
    four_days = NOW - timedelta(days=4)
    session = FakeSession(
        links=[
            a_link("storage_accounts", evidence_id=evidence_id, collected_at=four_days)
        ],
        readings=[a_reading(evidence_id, "storage_accounts")],
        stored_hashes=["a" * 64],
    )

    rows = await load_provenance(session, tenant(), a_finding())  # type: ignore[arg-type]

    assert rows is not None
    assert rows[0]["collected_at"] == four_days
    assert rows[0]["age_seconds"] >= 4 * 24 * 3600


# ------------------------------------------------------------ what has aged out
async def test_a_pruned_payload_is_reported_as_unavailable_not_omitted() -> None:
    """The citation is still true after the bytes are gone.

    Retention prunes payloads on its own schedule. A reading whose blob has aged
    out was still taken, at that time, under that permission -- and saying so
    beats both dropping the row and offering a link that 404s.
    """
    evidence_id = uuid.uuid4()
    session = FakeSession(
        links=[a_link("storage_accounts", evidence_id=evidence_id)],
        readings=[a_reading(evidence_id, "storage_accounts")],
        stored_hashes=[],  # the blob store no longer holds it
    )

    rows = await load_provenance(session, tenant(), a_finding())  # type: ignore[arg-type]

    assert rows is not None
    assert rows[0]["payload_available"] is False
    assert rows[0]["content_hash"] == "a" * 64


async def test_a_pruned_scan_leaves_the_citation_standing() -> None:
    """``evidence_id`` is SET NULL when a scan is deleted.

    What survives is the copied half: key, hash, collection time, source scan.
    The reading's own detail is gone and is reported as gone rather than as
    zero -- ``item_count: null`` is "we no longer hold that", while ``0`` would
    claim the listing came back empty.
    """
    session = FakeSession(
        links=[a_link("storage_accounts", evidence_id=None)],
        readings=[],
        stored_hashes=["a" * 64],
    )

    rows = await load_provenance(session, tenant(), a_finding())  # type: ignore[arg-type]

    assert rows is not None
    assert rows[0]["evidence_key"] == "storage_accounts"
    assert rows[0]["content_hash"] == "a" * 64
    assert rows[0]["item_count"] is None
    assert rows[0]["outcome"] is None
    assert rows[0]["permissions"] == []
    # Still followable to the bytes, which is the point of copying the hash.
    assert rows[0]["payload_available"] is True


async def test_a_failed_reading_has_no_hash_and_no_payload() -> None:
    session = FakeSession(
        links=[a_link("storage_accounts", evidence_id=None, content_hash=None)],
        readings=[],
        stored_hashes=[],
    )

    rows = await load_provenance(session, tenant(), a_finding())  # type: ignore[arg-type]

    assert rows is not None
    assert rows[0]["content_hash"] is None
    assert rows[0]["payload_available"] is False
