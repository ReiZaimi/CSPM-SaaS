"""Writing findings: one row per finding, one junction row per risk.

Both invariants here were broken at once by a batching change and caught only
by CI, because nothing that runs without a database touched this code. A fake
session is enough to hold them: what matters is which objects are handed to
``session.add``, not what PostgreSQL does with them afterwards.

The duplicate case is not hypothetical. A rule may report the same resource
more than once in a single scan -- AZ-CMP-001 does, when one VM is guarded by
the same NSG through two interfaces -- while ``findings`` is unique on
(organization, rule, resource). Reading the existing findings once and then
forgetting to register newly created ones meant the second report built a rival
row for a key the first had already claimed.
"""

import uuid
from datetime import UTC, datetime

import pytest

from app.core.enums import Level, Provider, ResourceType, Severity
from app.domain.resource import CloudResource
from app.models.finding import Finding
from app.models.risk import Risk, RiskFinding
from app.models.scan import Scan
from app.rules.base import RuleResult
from app.rules.engine import EvaluatedResult, EvaluationReport
from app.rules.registry import RULE_REGISTRY
from app.services.scanner import ScanPipeline


class FakeResult:
    def scalars(self):
        return self

    def all(self):
        return []


class FakeSession:
    """Records what the pipeline writes, and hands out ids on flush."""

    def __init__(self) -> None:
        self.added: list[object] = []

    async def execute(self, statement: object) -> FakeResult:
        return FakeResult()

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def flush(self) -> None:
        # Stands in for the database assigning primary keys, which the junction
        # rows need before they can reference anything.
        for obj in self.added:
            if getattr(obj, "id", None) is None:
                obj.id = uuid.uuid4()  # type: ignore[attr-defined]

    async def commit(self) -> None:
        return None

    def of_type(self, kind: type) -> list:
        return [o for o in self.added if isinstance(o, kind)]


def resource() -> CloudResource:
    return CloudResource(
        provider=Provider.AZURE,
        provider_resource_id="/subscriptions/s/vm-jumpbox",
        resource_type=ResourceType.VIRTUAL_MACHINE,
        name="vm-jumpbox",
        region="westeurope",
        criticality=Level.UNKNOWN,
        data_sensitivity=Level.UNKNOWN,
        public_exposure=Level.UNKNOWN,
    )


def report_naming(target: CloudResource, times: int) -> EvaluationReport:
    rule = RULE_REGISTRY[0]
    return EvaluationReport(
        failures=[
            EvaluatedResult(rule=rule, result=RuleResult.failed(), resource=target)
            for _ in range(times)
        ],
        rules_run=1,
    )


async def persist(times: int) -> tuple[FakeSession, int]:
    target = resource()
    session = FakeSession()
    pipeline = ScanPipeline(uuid.uuid4())
    org_id = uuid.uuid4()
    scan = Scan(organization_id=org_id, status="QUEUED")  # type: ignore[arg-type]
    scan.id = uuid.uuid4()

    count = await pipeline._persist_findings(
        session,  # type: ignore[arg-type]
        org_id,
        scan,
        report_naming(target, times),
        {target.provider_resource_id: uuid.uuid4()},
        datetime.now(UTC),
    )
    return session, count


# ------------------------------------------------------------- the duplicate
async def test_one_failure_writes_one_finding() -> None:
    session, count = await persist(times=1)

    assert len(session.of_type(Finding)) == 1
    assert count == 1


async def test_the_same_resource_reported_twice_writes_one_finding() -> None:
    """The regression. Findings are unique on (organization, rule, resource),
    so a second report of the same key must update the first row rather than
    insert a rival for it."""
    session, _ = await persist(times=2)

    assert len(session.of_type(Finding)) == 1


async def test_a_repeated_failure_is_counted_once() -> None:
    """One row is one finding, however many times the rules named it."""
    _, count = await persist(times=3)
    assert count == 1


# ------------------------------------------------------------ the junction
async def test_each_new_finding_gets_one_risk_and_one_link() -> None:
    session, _ = await persist(times=2)

    assert len(session.of_type(Risk)) == 1
    assert len(session.of_type(RiskFinding)) == 1


async def test_the_junction_row_carries_both_ids() -> None:
    """``RiskFinding`` has no ORM relationships, only the two id columns, so
    the link can only be written after both sides have been flushed. Passing
    objects instead raised TypeError on every scan."""
    session, _ = await persist(times=1)

    link = session.of_type(RiskFinding)[0]
    finding = session.of_type(Finding)[0]
    risk = session.of_type(Risk)[0]

    assert link.risk_id == risk.id
    assert link.finding_id == finding.id
    assert link.organization_id == finding.organization_id


async def test_nothing_is_written_when_nothing_failed() -> None:
    session = FakeSession()
    pipeline = ScanPipeline(uuid.uuid4())
    org_id = uuid.uuid4()
    scan = Scan(organization_id=org_id, status="QUEUED")  # type: ignore[arg-type]
    scan.id = uuid.uuid4()

    count = await pipeline._persist_findings(
        session,  # type: ignore[arg-type]
        org_id,
        scan,
        EvaluationReport(rules_run=1),
        {},
        datetime.now(UTC),
    )

    assert count == 0
    assert session.added == []


def test_the_severity_enum_round_trips() -> None:
    """Guards the scorer's input: the rule's severity is fed to
    ``Severity(...)`` and a mismatch there would surface as a scan failure."""
    for rule in RULE_REGISTRY:
        assert Severity(rule.severity) is not None


@pytest.mark.parametrize("times", [1, 2, 5])
async def test_the_number_of_reports_never_changes_the_number_of_rows(
    times: int,
) -> None:
    session, _ = await persist(times=times)
    assert len(session.of_type(Finding)) == 1
    assert len(session.of_type(RiskFinding)) == 1
