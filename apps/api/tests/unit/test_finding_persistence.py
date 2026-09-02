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
from app.rules.azure.compute.exposure import AzureExposedComputeRule
from app.rules.azure.identity.mfa import AzureMfaRule
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
        self.deleted: list[object] = []

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

    async def delete(self, obj: object) -> None:
        self.deleted.append(obj)

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
    # Named rather than taken from the registry by index. These cases are about
    # the default -- one risk per finding -- and the first registered rule is
    # AZ-ID-001, which groups: the file would have gone on passing while
    # testing the opposite of what it says.
    rule = AzureExposedComputeRule()
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
        # The fake session answers every query with the same list whatever is
        # asked of it, so the scope is inert here. Passed because the signature
        # requires it, and because a real scan always has one.
        account_ids=[uuid.uuid4()],
        connection_id=None,
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
        account_ids=[uuid.uuid4()],
        connection_id=None,
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


# ------------------------------------------------------------- the grouping
def user(name: str) -> CloudResource:
    return CloudResource(
        provider=Provider.AZURE,
        provider_resource_id=f"/users/{name}",
        resource_type=ResourceType.USER,
        name=name,
        criticality=Level.CRITICAL,
        data_sensitivity=Level.HIGH,
        public_exposure=Level.HIGH,
    )


async def persist_mfa(count: int) -> FakeSession:
    """A rule that groups, failing on several accounts in one scan."""
    rule = AzureMfaRule()
    accounts = [user(f"admin-{i}") for i in range(count)]
    session = FakeSession()
    pipeline = ScanPipeline(uuid.uuid4())
    org_id = uuid.uuid4()
    scan = Scan(organization_id=org_id, status="QUEUED")  # type: ignore[arg-type]
    scan.id = uuid.uuid4()

    await pipeline._persist_findings(
        session,  # type: ignore[arg-type]
        org_id,
        scan,
        EvaluationReport(
            failures=[
                EvaluatedResult(rule=rule, result=RuleResult.failed(), resource=account)
                for account in accounts
            ],
            rules_run=1,
        ),
        {account.provider_resource_id: uuid.uuid4() for account in accounts},
        datetime.now(UTC),
        account_ids=[uuid.uuid4()],
        connection_id=None,
    )
    return session


async def test_a_grouping_rule_writes_one_risk_for_every_finding() -> None:
    """The point of the whole mechanism. Forty administrators without a second
    factor is one unwritten Conditional Access policy, and as forty Critical
    risks it takes the org security score to zero on the strength of it."""
    session = await persist_mfa(count=4)

    assert len(session.of_type(Finding)) == 4
    assert len(session.of_type(Risk)) == 1
    # Each account still joins the risk: the group is the members, and a detail
    # page that could not name them would be an assertion rather than evidence.
    assert len(session.of_type(RiskFinding)) == 4


async def test_the_group_is_keyed_so_a_later_scan_finds_it() -> None:
    """Without a key the next scan inserts a second row for a key the unique
    index already holds, which fails the scan rather than the assertion."""
    session = await persist_mfa(count=2)

    assert session.of_type(Risk)[0].scenario_key == "group:AZ-ID-001"


async def test_the_title_counts_the_accounts() -> None:
    assert (
        session_title(await persist_mfa(count=3))
        == "3 privileged accounts have no multi-factor authentication"
    )


async def test_one_account_is_not_written_as_a_plural() -> None:
    assert (
        session_title(await persist_mfa(count=1))
        == "A privileged account has no multi-factor authentication"
    )


def session_title(session: FakeSession) -> str:
    return str(session.of_type(Risk)[0].title)


async def test_the_group_is_scored_as_its_worst_member_not_their_sum() -> None:
    """A group cannot be less serious than the worst thing in it, and must not
    be more serious either: the same mistake repeated is one mistake."""
    one = await persist_mfa(count=1)
    many = await persist_mfa(count=6)

    assert float(many.of_type(Risk)[0].risk_score) == float(one.of_type(Risk)[0].risk_score)


async def test_an_ungrouped_rule_still_gets_a_risk_each() -> None:
    """The default is unchanged: two storage accounts left public are two
    mistakes, not one made twice."""
    session, _ = await persist(times=1)

    assert session.of_type(Risk)[0].scenario_key is None


# --------------------------------------------------------- the exploitability
async def test_a_stepped_down_exploitability_reaches_the_score() -> None:
    """The tag is a ceiling, and the ceiling is not always what gets scored.

    A rule that establishes this instance is less exploitable than its worst
    case -- an NSG rule protecting nothing, a storage account open to every
    network but not to anonymous readers -- must have that reach the risk row,
    or the distinction is computed and thrown away.
    """
    rule = AzureExposedComputeRule()
    target = resource()
    session = FakeSession()
    pipeline = ScanPipeline(uuid.uuid4())
    org_id = uuid.uuid4()
    scan = Scan(organization_id=org_id, status="QUEUED")  # type: ignore[arg-type]
    scan.id = uuid.uuid4()

    await pipeline._persist_findings(
        session,  # type: ignore[arg-type]
        org_id,
        scan,
        EvaluationReport(
            failures=[
                EvaluatedResult(
                    rule=rule,
                    result=RuleResult.failed(exploitability=1),
                    resource=target,
                )
            ],
            rules_run=1,
        ),
        {target.provider_resource_id: uuid.uuid4()},
        datetime.now(UTC),
        account_ids=[uuid.uuid4()],
        connection_id=None,
    )

    risk = session.of_type(Risk)[0]
    assert int(risk.exploitability) == 1
    assert rule.exploitability > 1, "the class tag is the ceiling it stepped down from"
    # And the arithmetic on the detail page is the arithmetic that ran.
    assert risk.score_breakdown["components"]["exploitability"]["value"] == 1.0
