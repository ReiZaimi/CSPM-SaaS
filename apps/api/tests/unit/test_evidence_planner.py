"""What a scan decides to collect, before it collects anything.

Two halves, and they fail in opposite directions. The requirement half can
collect too little -- a key no rule happens to name is a key a derived plan
stops gathering, which is how an asset inventory disappears without a single
test going red. The freshness half can collect too little *and lie about it*: a
reading carried forward from yesterday answers today's question with yesterday's
environment, and a customer who has just fixed something is told it is still
broken, or worse, told a stale PASS.

So the tests here are mostly about refusing to reuse. Every way a reading can
fail to qualify gets its own case, because each is a separate line of policy and
the cost of any one of them silently inverting is a verdict CloudGuard did not
earn.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from app.connectors.azure.evidence import BASELINE_EVIDENCE, AzureEvidence
from app.connectors.evidence import EvidenceCategory, EvidenceKey
from app.core.enums import Provider, Severity, TaskOutcome
from app.core.payloads import compress, decompress
from app.rules.base import RuleContext, RuleResult, SecurityRule
from app.services.evidence_planner import plan_collection, required_evidence

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
ORG = uuid4()
SCAN = uuid4()
ACCOUNT = uuid4()


class Keys(EvidenceKey):
    """Keys for these tests, with windows chosen here rather than Azure's."""

    ALWAYS_FRESH = "always_fresh"
    WEEKLY = "weekly"
    DAILY = "daily"

    @property
    def category(self) -> EvidenceCategory:
        return EvidenceCategory.RESOURCES

    @property
    def reuse_window(self) -> timedelta | None:
        if self is Keys.WEEKLY:
            return timedelta(days=7)
        if self is Keys.DAILY:
            return timedelta(days=1)
        return None


class Rule(SecurityRule):
    rule_id = "TEST-001"
    name = "test"
    description = ""
    category = "test"
    severity = Severity.LOW

    def evaluate(self, resource, context: RuleContext) -> RuleResult:  # pragma: no cover
        raise NotImplementedError


def rule(*evidence: EvidenceKey, provider: Provider = Provider.AZURE) -> SecurityRule:
    made = Rule()
    made.provider = provider
    made.requires_evidence = evidence  # type: ignore[misc]
    return made


class Reading:
    """An evidence row, reduced to what the planner reads off one."""

    def __init__(
        self,
        key: EvidenceKey,
        *,
        age: timedelta = timedelta(hours=1),
        outcome: TaskOutcome = TaskOutcome.COMPLETE,
        content_hash: str | None = "hash-1",
        scan_id: UUID | None = None,
        source_scan_id: UUID | None = None,
    ) -> None:
        self.evidence_key = key.value
        self.collected_at = NOW - age
        self.outcome = outcome
        self.content_hash = content_hash
        self.item_count = 3
        self.permissions = ["Microsoft.Test/read"]
        # Which scan holds the row, and which scan made the call. The second is
        # NULL on a row that is itself the reading, which is most of them.
        self.scan_id = scan_id or uuid4()
        self.source_scan_id = source_scan_id


class Blob:
    """A stub of the stored row, compressed the way the real one is.

    ``content`` rather than a plain attribute because the column holds bytes
    now, and a stub that handed back a dict directly would keep passing if the
    planner ever started reading the raw column again.
    """

    def __init__(self, content_hash: str, payload: dict) -> None:
        self.content_hash = content_hash
        self.payload_compressed = compress(payload)

    @property
    def content(self) -> dict:
        return decompress(self.payload_compressed)


class FakeResult:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def scalars(self) -> list:
        return self._rows


class FakeSession:
    """Answers the planner's two queries in the order it asks them.

    A stub rather than a database because everything under test here is
    judgement -- which readings qualify -- and none of it is SQL. The query
    itself is exercised against real PostgreSQL in the integration suite, where
    the scoping that keeps one subscription's evidence out of another's plan can
    actually be violated.
    """

    def __init__(self, readings: list, blobs: list | None = None) -> None:
        self.queued = [readings, blobs or []]
        self.executed = 0

    async def execute(self, statement) -> FakeResult:
        self.executed += 1
        return FakeResult(self.queued.pop(0) if self.queued else [])


class ExplodingSession:
    """A session that fails the test if the planner queries it at all."""

    async def execute(self, statement) -> FakeResult:
        raise AssertionError("the planner asked about evidence it can never reuse")


async def plan(readings: list, blobs: list | None = None, *, required=None, now=NOW):
    return await plan_collection(
        FakeSession(readings, blobs),  # type: ignore[arg-type]
        organization_id=ORG,
        provider=Provider.AZURE,
        required=required if required is not None else frozenset(Keys),
        scan_id=SCAN,
        cloud_account_id=ACCOUNT,
        now=now,
    )


# ----------------------------------------------------- what a scan is collecting for
def test_the_requirement_is_the_rules_plus_the_baseline() -> None:
    required = required_evidence(
        Provider.AZURE,
        baseline={AzureEvidence.RESOURCES},
        rules=[
            rule(AzureEvidence.STORAGE_ACCOUNTS),
            rule(AzureEvidence.USERS, AzureEvidence.DIRECTORY_ROLES),
        ],
    )
    assert required == {
        AzureEvidence.RESOURCES,
        AzureEvidence.STORAGE_ACCOUNTS,
        AzureEvidence.USERS,
        AzureEvidence.DIRECTORY_ROLES,
    }


def test_evidence_no_rule_reads_is_still_required_when_it_is_baseline() -> None:
    """The whole reason a baseline exists.

    Inventory and the authorization listings are named by no rule. A plan
    derived from the rule set alone would drop all three, and the customer would
    lose their asset list and every privilege path in the graph while every
    check carried on passing.
    """
    required = required_evidence(Provider.AZURE, baseline=BASELINE_EVIDENCE, rules=[])
    assert required == BASELINE_EVIDENCE


def test_another_providers_rules_do_not_shape_this_providers_plan() -> None:
    """An AWS rule names AWS evidence, which Azure cannot produce.

    Harmless while the plan ignores keys it does not offer, and a wrong answer
    to "what is this scan for" the moment a second connector exists.
    """
    required = required_evidence(
        Provider.AZURE,
        baseline=set(),
        rules=[
            rule(AzureEvidence.STORAGE_ACCOUNTS),
            rule(Keys.WEEKLY, provider=Provider.AWS),
        ],
    )
    assert required == {AzureEvidence.STORAGE_ACCOUNTS}


# ------------------------------------------------------------- carrying evidence over
async def test_a_key_with_no_window_is_never_even_asked_about() -> None:
    made = await plan_collection(
        ExplodingSession(),  # type: ignore[arg-type]
        organization_id=ORG,
        provider=Provider.AZURE,
        required=frozenset({Keys.ALWAYS_FRESH}),
        scan_id=SCAN,
        cloud_account_id=ACCOUNT,
        now=NOW,
    )
    assert made.carried == {}
    assert made.collect == {Keys.ALWAYS_FRESH}
    assert made.wants(Keys.ALWAYS_FRESH)


async def test_a_fresh_complete_reading_is_carried_instead_of_re_read() -> None:
    made = await plan(
        [Reading(Keys.WEEKLY, age=timedelta(days=2))],
        [Blob("hash-1", {"weekly": ["a"]})],
    )

    carried = made.carried[Keys.WEEKLY]
    assert carried.payload == {"weekly": ["a"]}
    assert carried.item_count == 3
    assert carried.permissions == ("Microsoft.Test/read",)
    # The moment the provider was read, not the moment it was reused. Recording
    # the second would renew a reading every time it was carried, and one
    # reading would be carried for ever.
    assert carried.collected_at == NOW - timedelta(days=2)
    # And the run is told not to read it again.
    assert not made.wants(Keys.WEEKLY)


async def test_a_reading_older_than_its_own_window_is_read_again() -> None:
    made = await plan(
        [Reading(Keys.DAILY, age=timedelta(days=2))],
        [Blob("hash-1", {"daily": ["a"]})],
    )
    assert made.carried == {}
    assert made.wants(Keys.DAILY)


async def test_each_key_is_measured_against_its_own_window() -> None:
    """One query bounded by the longest window, one judgement per key.

    A two-day-old reading is inside the weekly window and outside the daily one,
    and a single cut-off applied to both would carry the wrong one.
    """
    made = await plan(
        [
            Reading(Keys.WEEKLY, age=timedelta(days=2)),
            Reading(Keys.DAILY, age=timedelta(days=2)),
        ],
        [Blob("hash-1", {"weekly": ["a"]})],
    )
    assert set(made.carried) == {Keys.WEEKLY}


async def test_a_reading_that_was_not_complete_is_never_carried() -> None:
    """PARTIAL and FAILED are not weaker evidence, they are absent evidence.

    A truncated listing cannot support a verdict on the day it is taken, so
    carrying it into a later scan would launder it into one that can.
    """
    for outcome in (TaskOutcome.PARTIAL, TaskOutcome.FAILED, TaskOutcome.SKIPPED):
        made = await plan(
            [Reading(Keys.WEEKLY, outcome=outcome)],
            [Blob("hash-1", {"weekly": ["a"]})],
        )
        assert made.carried == {}, outcome
        assert made.wants(Keys.WEEKLY)


async def test_a_reading_whose_payload_has_been_pruned_is_read_again() -> None:
    """Provenance outlives the payload deliberately.

    Retention removes blobs long before it removes the record that they were
    collected, so a row with no blob behind it is an ordinary state rather than
    a broken reference -- and the only sound response is to read the provider.
    """
    made = await plan([Reading(Keys.WEEKLY)], blobs=[])
    assert made.carried == {}
    assert made.wants(Keys.WEEKLY)


async def test_a_row_with_no_content_hash_is_read_again() -> None:
    made = await plan([Reading(Keys.WEEKLY, content_hash=None)])
    assert made.carried == {}


async def test_only_the_newest_reading_of_a_key_is_considered() -> None:
    """The query orders by collection time; the planner takes the first.

    Two rows for one key is the ordinary case -- one per scan -- and reaching
    past the newest one would carry an older environment forward while a newer
    reading of it sat in the same table.
    """
    made = await plan(
        [
            Reading(Keys.DAILY, age=timedelta(hours=2)),
            Reading(Keys.DAILY, age=timedelta(days=30)),
        ],
        [Blob("hash-1", {"daily": ["a"]})],
    )
    assert made.carried[Keys.DAILY].collected_at == NOW - timedelta(hours=2)


async def test_a_key_nothing_requires_is_neither_collected_nor_carried() -> None:
    made = await plan(
        [Reading(Keys.WEEKLY)],
        [Blob("hash-1", {"weekly": ["a"]})],
        required=frozenset({Keys.DAILY}),
    )
    assert made.collect == {Keys.DAILY}
    assert Keys.WEEKLY not in made.carried


# ------------------------------------------------------- who took the reading
async def test_a_carried_reading_names_the_scan_that_read_the_provider() -> None:
    """Otherwise the scan reusing it is recorded as having made the call.

    Every row a scan writes carries its own ``scan_id``, and a carried reading
    is written as such a row -- so the provenance chain a citation follows
    landed on a scan that never asked the provider for that key. The age
    survived, because ``collected_at`` is copied; the authorship did not.
    """
    original = uuid4()
    made = await plan(
        [Reading(Keys.WEEKLY, age=timedelta(days=2), scan_id=original)],
        [Blob("hash-1", {"weekly": ["a"]})],
    )

    assert made.carried[Keys.WEEKLY].source_scan_id == original


async def test_carrying_a_carried_reading_still_names_the_original() -> None:
    """The chain stays one hop long however many scans have reused a reading.

    A row that was itself carried already names its source; taking its
    ``scan_id`` instead would credit whichever scan last reused it, and the
    trail would drift one scan further from the truth on every reuse.
    """
    original = uuid4()
    reused_by = uuid4()
    made = await plan(
        [
            Reading(
                Keys.WEEKLY,
                age=timedelta(days=2),
                scan_id=reused_by,
                source_scan_id=original,
            )
        ],
        [Blob("hash-1", {"weekly": ["a"]})],
    )

    assert made.carried[Keys.WEEKLY].source_scan_id == original
