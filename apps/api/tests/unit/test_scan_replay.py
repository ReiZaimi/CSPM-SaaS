"""Replaying a stored snapshot, and the interlock that keeps it honest.

Every scan has always written the provider's own JSON to ``cloud_snapshots``
before interpreting any of it, on the promise that the scan could be
re-evaluated later against better rules. These tests cover the two halves of
keeping that promise: a snapshot must survive the round trip through the
database unchanged, and a replay of an old one must not be allowed to pass
itself off as an observation.

The second is the dangerous one. Auto-resolution treats a PASS where there was
a FAIL as proof of a fix. Replay a month-old capture against a newly written
rule and that machinery would happily stamp findings "verified fixed" on the
strength of data collected before anyone knew the rule existed -- nothing was
looked at, so nothing may be resolved.
"""

from datetime import UTC, datetime

import pytest

from app.connectors.base import NormalizedState, RawSnapshot
from app.core.enums import Provider, ScanStatus
from app.models.cloud_account import CloudAccount
from app.models.scan import Scan
from app.rules.base import RuleResult
from app.rules.engine import EvaluatedResult, EvaluationReport, RuleCoverage
from app.rules.registry import RULE_REGISTRY
from app.services.scanner import ScanPipeline


# ------------------------------------------------------------- round tripping
def test_a_snapshot_survives_the_round_trip() -> None:
    original = RawSnapshot(
        provider=Provider.AZURE,
        tenant_id="tenant-1",
        subscription_id="sub-1",
        data={"storage_accounts": [{"id": "/a", "name": "a"}]},
    )
    restored = RawSnapshot.from_json(original.to_json())

    assert restored.provider == original.provider
    assert restored.tenant_id == original.tenant_id
    assert restored.subscription_id == original.subscription_id
    assert restored.version == original.version
    assert restored.data == original.data


def test_collection_failures_survive_the_round_trip() -> None:
    """A category that failed at collection time must keep failing on replay.

    Dropping ``errors`` would let a rule that correctly degraded to UNKNOWN come
    back as a PASS the second time it is evaluated -- the exact confusion of
    "could not look" with "looked and it was fine" that the four rule states
    exist to prevent.
    """
    original = RawSnapshot(
        provider=Provider.AZURE,
        tenant_id="tenant-1",
        subscription_id="sub-1",
        data={},
        errors={"storage": "read tcp: i/o timeout"},
    )
    assert RawSnapshot.from_json(original.to_json()).errors == {
        "storage": "read tcp: i/o timeout"
    }


def test_a_snapshot_stored_before_optional_fields_existed_still_loads() -> None:
    """Snapshots outlive the code that wrote them; that is their whole purpose."""
    restored = RawSnapshot.from_json(
        {"provider": "azure", "tenant_id": "t", "subscription_id": None}
    )
    assert restored.data == {}
    assert restored.errors == {}
    assert restored.version == "1.0"


# ----------------------------------------------------------------- the fakes
class FakeSession:
    """Enough session to run ``_evaluate`` with every persistence step stubbed."""

    def __init__(self) -> None:
        self.commits = 0

    async def commit(self) -> None:
        self.commits += 1


class FakeEngine:
    def __init__(self, failures: int) -> None:
        rule = RULE_REGISTRY[0]
        self.report = EvaluationReport(
            failures=[
                EvaluatedResult(rule=rule, result=RuleResult.failed(), resource=None)
                for _ in range(failures)
            ],
            coverage={rule.rule_id: RuleCoverage(rule_id=rule.rule_id)},
            rules_run=len(RULE_REGISTRY),
        )

    def evaluate(self, context: object) -> EvaluationReport:
        return self.report


@pytest.fixture
def pipeline(monkeypatch: pytest.MonkeyPatch) -> ScanPipeline:
    """A pipeline whose every write is recorded rather than performed.

    Stubbing the four persistence steps leaves exactly the decision under test:
    which of them ``_evaluate`` chooses to run.
    """
    import uuid

    pipe = ScanPipeline(uuid.uuid4())
    pipe.engine = FakeEngine(failures=3)
    calls: list[str] = []
    pipe.calls = calls

    def recorder(name: str, result: object = None):
        async def record(*args: object, **kwargs: object) -> object:
            calls.append(name)
            return result

        return record

    monkeypatch.setattr(pipe, "_persist_resources", recorder("resources", {}))
    monkeypatch.setattr(pipe, "_existing_resource_ids", recorder("read_resources", {}))
    monkeypatch.setattr(pipe, "_persist_coverage", recorder("coverage"))
    monkeypatch.setattr(pipe, "_persist_findings", recorder("findings", 7))
    monkeypatch.setattr(pipe, "_verify_remediations", recorder("verify"))
    monkeypatch.setattr(pipe, "_would_be_open_count", recorder("would_be_open", 2))
    return pipe


def make_scan() -> Scan:
    import uuid

    return Scan(
        organization_id=uuid.uuid4(),
        cloud_account_id=uuid.uuid4(),
        status=ScanStatus.QUEUED,
        evaluation_only=False,
    )


def make_account() -> CloudAccount:
    import uuid

    account = CloudAccount(
        organization_id=uuid.uuid4(),
        provider=Provider.AZURE,
        tenant_id="t",
        subscription_id="s",
    )
    account.id = uuid.uuid4()
    return account


# ------------------------------------------------------------- the interlock
async def test_a_current_snapshot_writes_findings_and_verifies_fixes(
    pipeline: ScanPipeline,
) -> None:
    scan = make_scan()
    await pipeline._evaluate(
        FakeSession(),
        scan,
        [(make_account(), NormalizedState())],
        NormalizedState(),
        observed_at=datetime.now(UTC),
        mutate_findings=True,
        degraded=False,
    )

    assert "findings" in pipeline.calls
    assert "verify" in pipeline.calls
    assert "resources" in pipeline.calls, "a current capture updates the inventory"
    assert scan.status == ScanStatus.COMPLETED


async def test_a_stale_snapshot_writes_no_findings_and_resolves_nothing(
    pipeline: ScanPipeline,
) -> None:
    """The interlock. Coverage is still recorded -- what the rules could and
    could not determine about that capture is true regardless of its age -- but
    nothing is created, reopened or resolved."""
    scan = make_scan()
    await pipeline._evaluate(
        FakeSession(),
        scan,
        [(make_account(), NormalizedState())],
        NormalizedState(),
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        mutate_findings=False,
        degraded=False,
    )

    assert "findings" not in pipeline.calls
    assert "verify" not in pipeline.calls
    assert "coverage" in pipeline.calls
    # Reported, not recorded: the number the rules would have raised, counted
    # the way a real scan counts so the two are comparable.
    assert scan.finding_count == 2


async def test_a_replay_of_a_partial_snapshot_stays_partial(
    pipeline: ScanPipeline,
) -> None:
    scan = make_scan()
    await pipeline._evaluate(
        FakeSession(),
        scan,
        [(make_account(), NormalizedState())],
        NormalizedState(),
        observed_at=datetime.now(UTC),
        mutate_findings=True,
        # A category failed somewhere in the run, whichever subscription it
        # belonged to.
        degraded=True,
    )
    assert scan.status == ScanStatus.PARTIAL


async def test_a_stale_snapshot_does_not_touch_the_asset_inventory(
    pipeline: ScanPipeline,
) -> None:
    """``evaluation_only`` means the run changes nothing, and the asset
    inventory is part of nothing.

    Upserting from a superseded capture would write historical criticality,
    exposure and metadata over live rows -- the columns the risk scorer reads --
    and re-create resources deleted since, which nothing ever cleans up. The
    ids still have to be resolved for the coverage ledger, so they are read
    rather than written.
    """
    await pipeline._evaluate(
        FakeSession(),
        make_scan(),
        [(make_account(), NormalizedState())],
        NormalizedState(),
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        mutate_findings=False,
        degraded=False,
    )

    assert "resources" not in pipeline.calls, "a stale capture must not upsert assets"
    assert "read_resources" in pipeline.calls, "ids are still needed for coverage"


async def test_the_reported_count_uses_the_same_rule_as_a_real_scan(
    pipeline: ScanPipeline,
) -> None:
    """``len(report.failures)`` would have counted findings someone has already
    accepted, so an unchanged environment would report more findings on replay
    than on the scan it replayed, in the same column."""
    scan = make_scan()
    await pipeline._evaluate(
        FakeSession(),
        scan,
        [(make_account(), NormalizedState())],
        NormalizedState(),
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
        mutate_findings=False,
        degraded=False,
    )

    assert "would_be_open" in pipeline.calls
    # Three rules failed; the count is not simply three.
    assert len(pipeline.engine.report.failures) == 3
    assert scan.finding_count == 2


# ------------------------------------------------------- multiple subscriptions
def test_a_single_subscription_scan_keeps_bare_category_names() -> None:
    """One subscription, so there is nothing to disambiguate and a prefix would
    only add noise to the message a customer reads."""
    import uuid

    pipe = ScanPipeline(uuid.uuid4())
    account = make_account()
    account.display_name = "Production"

    assert pipe._scoped_key(account, "storage", 1) == "storage"


def test_several_subscriptions_qualify_the_category_by_name() -> None:
    """Two subscriptions can both fail to read storage, and "storage: timeout"
    twice over says nothing about which one to go and look at."""
    import uuid

    pipe = ScanPipeline(uuid.uuid4())
    account = make_account()
    account.display_name = "Production"

    assert pipe._scoped_key(account, "storage", 3) == "Production: storage"


def test_a_subscription_with_no_display_name_falls_back_to_its_id() -> None:
    import uuid

    pipe = ScanPipeline(uuid.uuid4())
    account = make_account()
    account.display_name = None

    assert pipe._scoped_key(account, "storage", 2).endswith(": storage")
    assert account.subscription_id in pipe._scoped_key(account, "storage", 2)


async def test_resources_from_every_subscription_reach_one_evaluation(
    pipeline: ScanPipeline,
) -> None:
    """The point of the change: a rule sees the tenant, not one slice of it."""
    from app.core.enums import Level, ResourceType
    from app.domain.resource import CloudResource

    def resource(name: str) -> CloudResource:
        return CloudResource(
            provider=Provider.AZURE,
            provider_resource_id=f"/subscriptions/{name}/x",
            resource_type=ResourceType.STORAGE_ACCOUNT,
            name=name,
            region="westeurope",
            criticality=Level.UNKNOWN,
            data_sensitivity=Level.UNKNOWN,
            public_exposure=Level.UNKNOWN,
        )

    merged = NormalizedState(resources=[resource("a"), resource("b")])
    scan = make_scan()

    await pipeline._evaluate(
        FakeSession(),
        scan,
        [(make_account(), NormalizedState()), (make_account(), NormalizedState())],
        merged,
        observed_at=datetime.now(UTC),
        mutate_findings=True,
        degraded=False,
    )

    assert scan.resource_count == 2, "both subscriptions counted in one scan"
    # Once for the whole scan, not once per subscription. Persisting per
    # subscription meant a full read of the organization's relationship table
    # for each one, plus a lookup per newly created resource -- tens of
    # thousands of statements on a large tenant to write what this does in four.
    assert pipeline.calls.count("resources") == 1, "assets persisted in one pass"
