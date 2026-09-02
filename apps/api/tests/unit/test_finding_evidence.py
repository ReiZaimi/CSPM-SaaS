"""Citing the readings a finding rests on.

A finding has always carried an excerpt of its evidence. These cover the other
half -- where that excerpt came from -- and most of them exist because the
obvious implementation is wrong in a way nothing downstream would notice.

The obvious implementation resolves evidence by ``scan_id``: the scan that
raised the finding is the scan that read the provider. That holds for a plain
scan and fails for the two cases the pipeline actually has. A *carried* reading
was collected by an earlier scan and reused, so its age is not this scan's age.
A *replay* evaluates a capture some other scan collected and writes no evidence
rows at all, so resolving against its own id finds nothing -- and, because the
links are rewritten each scan, deletes every citation it touches.

Both failures are silent. A finding with no citation looks exactly like a
finding raised before this table existed.
"""

import uuid
from datetime import UTC, datetime, timedelta

from app.core.enums import Level, Provider, ResourceType, TaskOutcome
from app.domain.resource import CloudResource
from app.models.finding import Finding, FindingEvidence
from app.models.scan import Evidence, Scan
from app.rules.azure.identity.mfa import AzureMfaRule
from app.rules.azure.storage.public_access import AzurePublicStorageRule
from app.rules.base import RuleResult
from app.rules.engine import EvaluatedResult, EvaluationReport
from app.services.scanner import ScanPipeline

NOW = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)
SUB_A = uuid.uuid4()
SUB_B = uuid.uuid4()


class EvidenceResult:
    def __init__(self, rows: list[Evidence]) -> None:
        self._rows = rows

    def scalars(self):
        return self

    def all(self) -> list[Evidence]:
        return self._rows


class FakeSession:
    """Answers the evidence query with a fixed set, records everything written.

    Only the evidence SELECT is answered with rows; every other query the
    pipeline makes returns nothing, which is what an organization with no prior
    findings looks like.
    """

    def __init__(self, evidence: list[Evidence] | None = None) -> None:
        self.added: list[object] = []
        self.statements: list[object] = []
        self._evidence = evidence or []

    async def execute(self, statement: object) -> EvidenceResult:
        self.statements.append(statement)
        # Matched on the FROM clause, not on the word: ``findings`` has an
        # ``evidence`` column of its own, so a looser test answers the findings
        # query with evidence rows and fails several layers away from the cause.
        text = str(statement)
        if "FROM evidence" not in text:
            return EvidenceResult([])

        # The scan filter is honoured rather than ignored, and that is the
        # difference between this file testing something and testing nothing.
        # A fake that returns its rows whatever is asked cannot tell a replay
        # resolving against the scan that read the provider from one resolving
        # against itself -- which is the bug the replay case exists to catch,
        # and it passed against a fake that did not look.
        params = statement.compile().params  # type: ignore[attr-defined]
        wanted = {v for k, v in params.items() if k.startswith("scan_id")}
        return EvidenceResult(
            [row for row in self._evidence if not wanted or row.scan_id in wanted]
        )

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        for obj in self.added:
            if getattr(obj, "id", None) is None:
                obj.id = uuid.uuid4()  # type: ignore[attr-defined]

    async def commit(self) -> None:
        return None

    async def delete(self, obj: object) -> None:
        return None

    def of_type(self, kind: type) -> list:
        return [o for o in self.added if isinstance(o, kind)]


def reading(
    key: str,
    *,
    scan_id: uuid.UUID,
    account_id: uuid.UUID | None,
    collected_at: datetime = NOW,
    content_hash: str | None = "a" * 64,
    outcome: TaskOutcome = TaskOutcome.COMPLETE,
) -> Evidence:
    row = Evidence(
        organization_id=uuid.uuid4(),
        scan_id=scan_id,
        cloud_account_id=account_id,
        provider=Provider.AZURE,
        evidence_key=key,
        category="storage",
        outcome=outcome,
        item_count=3,
        collected_at=collected_at,
        permissions=["Microsoft.Storage/storageAccounts/read"],
        content_hash=content_hash,
        byte_size=128,
    )
    row.id = uuid.uuid4()
    return row


def storage_account(resource_id: str) -> CloudResource:
    return CloudResource(
        provider=Provider.AZURE,
        provider_resource_id=resource_id,
        resource_type=ResourceType.STORAGE_ACCOUNT,
        name=resource_id.rsplit("/", 1)[-1],
        criticality=Level.UNKNOWN,
        data_sensitivity=Level.UNKNOWN,
        public_exposure=Level.HIGH,
    )


async def link(
    *,
    evidence: list[Evidence],
    resource: CloudResource | None,
    account_of: dict[str, uuid.UUID],
    scan: Scan,
    rule: object | None = None,
) -> FakeSession:
    session = FakeSession(evidence)
    pipeline = ScanPipeline(uuid.uuid4())
    org_id = uuid.uuid4()
    chosen = rule or AzurePublicStorageRule()
    report = EvaluationReport(
        failures=[
            EvaluatedResult(rule=chosen, result=RuleResult.failed(), resource=resource)
        ],
        rules_run=1,
    )
    await pipeline._persist_findings(
        session,  # type: ignore[arg-type]
        org_id,
        scan,
        report,
        {resource.provider_resource_id: uuid.uuid4()} if resource else {},
        NOW,
        account_ids=[SUB_A],
        connection_id=None,
        account_of=account_of,
    )
    return session


def a_scan() -> Scan:
    scan = Scan(organization_id=uuid.uuid4(), status="QUEUED")  # type: ignore[arg-type]
    scan.id = uuid.uuid4()
    return scan


# ------------------------------------------------------------ what gets cited
async def test_finding_cites_the_keys_its_rule_declares() -> None:
    scan = a_scan()
    rule = AzurePublicStorageRule()
    asset = storage_account("/subscriptions/a/storage/sa1")
    rows = [
        reading(key.value, scan_id=scan.id, account_id=SUB_A)
        for key in rule.requires_evidence
    ]
    # A reading nothing declared, to prove the citation is the rule's
    # declaration rather than everything the scan happened to collect.
    rows.append(reading("virtual_machines", scan_id=scan.id, account_id=SUB_A))

    session = await link(
        evidence=rows,
        resource=asset,
        account_of={asset.provider_resource_id: SUB_A},
        scan=scan,
    )

    cited = {row.evidence_key for row in session.of_type(FindingEvidence)}
    assert cited == {key.value for key in rule.requires_evidence}
    assert "virtual_machines" not in cited


async def test_citation_points_at_the_finding_and_carries_the_hash() -> None:
    scan = a_scan()
    rule = AzurePublicStorageRule()
    asset = storage_account("/subscriptions/a/storage/sa1")
    rows = [
        reading(key.value, scan_id=scan.id, account_id=SUB_A, content_hash="b" * 64)
        for key in rule.requires_evidence
    ]

    session = await link(
        evidence=rows,
        resource=asset,
        account_of={asset.provider_resource_id: SUB_A},
        scan=scan,
    )

    finding = session.of_type(Finding)[0]
    links = session.of_type(FindingEvidence)
    assert links
    for row in links:
        assert row.finding_id == finding.id
        assert row.content_hash == "b" * 64
        assert row.source_scan_id == scan.id


# ------------------------------------------------------------------- scoping
async def test_a_finding_does_not_cite_another_subscriptions_reading() -> None:
    """The reason ``account_of`` is built before the merge.

    Two subscriptions read the same key. The finding is on an asset in A, so B's
    reading is the provenance of nothing here -- and offering it would be a
    citation that names a scope nobody looked at for this asset.
    """
    scan = a_scan()
    rule = AzurePublicStorageRule()
    asset = storage_account("/subscriptions/a/storage/sa1")
    rows: list[Evidence] = []
    for key in rule.requires_evidence:
        rows.append(
            reading(key.value, scan_id=scan.id, account_id=SUB_B, content_hash="b" * 64)
        )
        rows.append(
            reading(key.value, scan_id=scan.id, account_id=SUB_A, content_hash="a" * 64)
        )

    session = await link(
        evidence=rows,
        resource=asset,
        account_of={asset.provider_resource_id: SUB_A},
        scan=scan,
    )

    hashes = {row.content_hash for row in session.of_type(FindingEvidence)}
    assert hashes == {"a" * 64}


async def test_an_aggregate_finding_cites_the_directory_reading() -> None:
    """A tenant-wide rule has no asset and no subscription.

    Its readings are filed under ``cloud_account_id IS NULL``, which is how
    ``Evidence`` records a directory task: a tenant read did not happen *in* a
    subscription, and attributing it to one would send somebody to check a
    scope that is fine.
    """
    scan = a_scan()
    rule = AzureMfaRule()
    rows = [
        reading(key.value, scan_id=scan.id, account_id=None)
        for key in rule.requires_evidence
    ]

    session = await link(
        evidence=rows, resource=None, account_of={}, scan=scan, rule=rule
    )

    cited = {row.evidence_key for row in session.of_type(FindingEvidence)}
    assert cited == {key.value for key in rule.requires_evidence}


# ------------------------------------------------------------------ freshness
async def test_a_carried_reading_keeps_its_own_collection_time() -> None:
    """The whole reason a citation beats a derivation.

    Reuse means a finding can rest on a reading taken days before the scan that
    raised it. Recording the scan's time instead would let a carried reading be
    renewed by every scan that reused it, and the age question -- which is the
    one a customer actually asks -- would quietly always answer "just now".
    """
    scan = a_scan()
    rule = AzurePublicStorageRule()
    asset = storage_account("/subscriptions/a/storage/sa1")
    four_days_ago = NOW - timedelta(days=4)
    rows = [
        reading(
            key.value, scan_id=scan.id, account_id=SUB_A, collected_at=four_days_ago
        )
        for key in rule.requires_evidence
    ]

    session = await link(
        evidence=rows,
        resource=asset,
        account_of={asset.provider_resource_id: SUB_A},
        scan=scan,
    )

    assert {row.collected_at for row in session.of_type(FindingEvidence)} == {
        four_days_ago
    }


async def test_a_failed_reading_is_still_cited_with_no_hash() -> None:
    """"We tried, at this time, under this permission" is provenance too.

    A hash of nothing would claim there was something to point at, so the hash
    is NULL -- but the attempt is the record behind a degraded verdict, and
    dropping it would leave the gap unexplained.
    """
    scan = a_scan()
    rule = AzurePublicStorageRule()
    asset = storage_account("/subscriptions/a/storage/sa1")
    rows = [
        reading(
            key.value,
            scan_id=scan.id,
            account_id=SUB_A,
            content_hash=None,
            outcome=TaskOutcome.FAILED,
        )
        for key in rule.requires_evidence
    ]

    session = await link(
        evidence=rows,
        resource=asset,
        account_of={asset.provider_resource_id: SUB_A},
        scan=scan,
    )

    links = session.of_type(FindingEvidence)
    assert links
    assert all(row.content_hash is None for row in links)


# --------------------------------------------------------------- the replay
async def test_a_replay_cites_the_scan_that_did_the_reading() -> None:
    """The regression this whole method is shaped around.

    A replay evaluates a stored capture and calls ``_record_evidence`` nowhere,
    so it owns no evidence rows. Resolving against its own id would match
    nothing, write nothing, and -- because the links are rewritten each scan --
    remove the citations the original scan left. Silently, on the path that
    exists to verify that a fix held.
    """
    original = a_scan()
    replay = a_scan()
    replay.replay_of_scan_id = original.id

    rule = AzurePublicStorageRule()
    asset = storage_account("/subscriptions/a/storage/sa1")
    rows = [
        reading(key.value, scan_id=original.id, account_id=SUB_A)
        for key in rule.requires_evidence
    ]

    session = await link(
        evidence=rows,
        resource=asset,
        account_of={asset.provider_resource_id: SUB_A},
        scan=replay,
    )

    links = session.of_type(FindingEvidence)
    assert links, "a replay must keep citing the reading it replayed"
    assert {row.source_scan_id for row in links} == {original.id}


# --------------------------------------------------------------- replacement
async def test_links_are_cleared_before_being_rewritten() -> None:
    """A citation says what a finding rests on now, not what it ever rested on.

    Without the delete the table grows one row per scan per key for the life of
    a finding, and "which reading is this finding standing on" stops having one
    answer.
    """
    scan = a_scan()
    rule = AzurePublicStorageRule()
    asset = storage_account("/subscriptions/a/storage/sa1")
    rows = [
        reading(key.value, scan_id=scan.id, account_id=SUB_A)
        for key in rule.requires_evidence
    ]

    session = await link(
        evidence=rows,
        resource=asset,
        account_of={asset.provider_resource_id: SUB_A},
        scan=scan,
    )

    deletes = [
        str(s) for s in session.statements if str(s).lstrip().upper().startswith("DELETE")
    ]
    assert any("finding_evidence" in text for text in deletes)


async def test_a_rule_declaring_no_evidence_cites_nothing() -> None:
    scan = a_scan()
    asset = storage_account("/subscriptions/a/storage/sa1")

    class SilentRule(AzurePublicStorageRule):
        requires_evidence = ()

    session = await link(
        evidence=[reading("storage_accounts", scan_id=scan.id, account_id=SUB_A)],
        resource=asset,
        account_of={asset.provider_resource_id: SUB_A},
        scan=scan,
        rule=SilentRule(),
    )

    assert session.of_type(FindingEvidence) == []
