"""The collection executor.

Collection used to be a fixed call sequence, which could express neither "these
two are independent" nor "this one needs that one's output" nor "this list
stopped early". The executor exists to make all three ordinary, and the third is
the one that was silently wrong: a truncated listing reached the rule engine as
though it were the whole environment, and a rule returned PASS over resources
nobody had looked at.
"""

from datetime import UTC, datetime, timedelta

import pytest

from app.connectors.collection import (
    CollectionRun,
    CollectionTask,
    TaskData,
    TaskOutcome,
)
from app.connectors.evidence import EvidenceCategory, EvidenceKey
from app.connectors.planning import CarriedReading, CollectionPlan


class Evidence(EvidenceKey):
    """Keys for this test, not Azure's.

    The executor is provider-neutral and these prove it: it is handed an
    ``EvidenceKey`` implementation it has never seen, with categories chosen
    here, and it sorts, skips and degrades them exactly as it does Azure's.
    """

    A = "a"
    B = "b"
    C = "c"
    SOURCE = "source"
    DEPENDENT = "dependent"
    EARLY = "early"
    LATE = "late"
    NSGS = "nsgs"
    NICS = "nics"
    PUBLIC_IPS = "public_ips"
    STORAGE_ACCOUNTS = "storage_accounts"
    DIAGNOSTIC_SETTINGS = "diagnostic_settings"
    READER = "reader"

    @property
    def category(self) -> EvidenceCategory:
        if self in (Evidence.NSGS, Evidence.NICS, Evidence.PUBLIC_IPS):
            return EvidenceCategory.NETWORK
        if self is Evidence.STORAGE_ACCOUNTS:
            return EvidenceCategory.STORAGE
        if self is Evidence.DIAGNOSTIC_SETTINGS:
            return EvidenceCategory.LOGGING
        return EvidenceCategory.RESOURCES


def task(key, depends_on=(), *, data=None, partial=None, boom=None):
    async def run(collected: dict) -> TaskData:
        if boom:
            raise RuntimeError(boom)
        return TaskData(
            data if data is not None else {key.value: [key.value]},
            partial_reason=partial,
        )

    return CollectionTask(key=key, run=run, depends_on=depends_on)


# ----------------------------------------------------------------- the happy path
async def test_every_task_contributes_to_the_collected_data() -> None:
    data: dict = {}
    report = await CollectionRun([task(Evidence.A), task(Evidence.B)]).execute(data)

    assert data == {"a": ["a"], "b": ["b"]}
    assert report.is_complete
    assert report.category_problems() == {}


async def test_independent_tasks_share_a_wave() -> None:
    run = CollectionRun([task(Evidence.A), task(Evidence.B), task(Evidence.C)])
    assert [len(w) for w in run.waves()] == [3]


async def test_a_dependency_forces_a_later_wave() -> None:
    """``diagnostic_settings`` needs the ids storage and SQL produce. That used
    to be expressed as "call it fifth"."""
    run = CollectionRun([task(Evidence.LATE, depends_on=(Evidence.EARLY,)), task(Evidence.EARLY)])
    waves = run.waves()

    assert [t.key for t in waves[0]] == [Evidence.EARLY]
    assert [t.key for t in waves[1]] == [Evidence.LATE]


async def test_a_dependent_task_sees_what_its_dependency_produced() -> None:
    seen: dict = {}

    async def reader(collected: dict) -> TaskData:
        seen.update(collected)
        return TaskData({"reader": []})

    await CollectionRun(
        [
            task(Evidence.SOURCE, data={"source": [1, 2, 3]}),
            CollectionTask(
                key=Evidence.READER, run=reader, depends_on=(Evidence.SOURCE,)
            ),
        ]
    ).execute({})

    assert seen["source"] == [1, 2, 3]


# ------------------------------------------------------------------- degrading
async def test_one_failure_does_not_cost_its_siblings() -> None:
    """The bug this granularity fixes: network gathered NSGs, NICs and public
    IPs under one try, so a public IP failure discarded the NSG data that had
    already arrived."""
    data: dict = {}
    report = await CollectionRun(
        [task(Evidence.NSGS), task(Evidence.PUBLIC_IPS, boom="throttled"), task(Evidence.NICS)]
    ).execute(data)

    assert data["nsgs"] == ["nsgs"]
    assert data["nics"] == ["nics"]
    assert report.results[Evidence.PUBLIC_IPS].outcome == TaskOutcome.FAILED
    assert report.results[Evidence.NSGS].outcome == TaskOutcome.COMPLETE


async def test_a_failed_dependency_skips_rather_than_fails_its_dependents() -> None:
    """Nothing is wrong with the dependent task. Reporting it as failed would
    send someone looking for a second problem one hop from the real one."""
    report = await CollectionRun(
        [
            task(Evidence.SOURCE, boom="gone"),
            task(Evidence.DEPENDENT, depends_on=(Evidence.SOURCE,)),
        ]
    ).execute({})

    assert report.results[Evidence.SOURCE].outcome == TaskOutcome.FAILED
    assert report.results[Evidence.DEPENDENT].outcome == TaskOutcome.SKIPPED
    assert "source" in report.results[Evidence.DEPENDENT].detail


async def test_a_skip_cascades_through_the_chain() -> None:
    report = await CollectionRun(
        [
            task(Evidence.A, boom="gone"),
            task(Evidence.B, depends_on=(Evidence.A,)),
            task(Evidence.C, depends_on=(Evidence.B,)),
        ]
    ).execute({})

    assert report.results[Evidence.C].outcome == TaskOutcome.SKIPPED


# ------------------------------------------------------------------ the point
async def test_a_partial_result_keeps_its_data_and_forfeits_its_verdict() -> None:
    """The defect the whole module exists for. The data is still useful for an
    inventory; it is not evidence that nothing is wrong."""
    data: dict = {}
    report = await CollectionRun(
        [task(Evidence.STORAGE_ACCOUNTS, partial="the listing stopped early")]
    ).execute(data)

    assert data["storage_accounts"] == ["storage_accounts"]
    assert report.results[Evidence.STORAGE_ACCOUNTS].outcome == TaskOutcome.PARTIAL
    assert not report.is_complete


async def test_a_partial_result_degrades_its_category_like_a_failure() -> None:
    """PARTIAL lands in ``errors`` beside FAILED on purpose: the existing
    degradation path then costs those rules their verdict, and no rule has to
    learn that truncation exists."""
    report = await CollectionRun(
        [task(Evidence.STORAGE_ACCOUNTS, partial="stopped early")]
    ).execute({})

    problems = report.category_problems()
    assert "storage" in problems
    assert "stopped early" in problems["storage"]


async def test_a_partial_dependency_does_not_let_dependents_run() -> None:
    """Half the storage accounts is half the ids, and diagnostic settings
    gathered over half an environment is another partial answer wearing a
    complete one's clothes."""
    report = await CollectionRun(
        [
            task(Evidence.STORAGE_ACCOUNTS, partial="stopped early"),
            task(Evidence.DIAGNOSTIC_SETTINGS, depends_on=(Evidence.STORAGE_ACCOUNTS,)),
        ]
    ).execute({})

    assert report.results[Evidence.DIAGNOSTIC_SETTINGS].outcome == TaskOutcome.SKIPPED


# --------------------------------------------------------------- plan sanity
async def test_progress_is_reported_against_a_known_total() -> None:
    """The plan's size is known before it runs, which is what lets collection
    show a denominator during the phase that actually takes the time."""
    seen: list[tuple[int, int]] = []

    async def record(done: int, total: int) -> None:
        seen.append((done, total))

    run = CollectionRun(
        [task(Evidence.A), task(Evidence.B, depends_on=(Evidence.A,))],
        on_progress=record,
    )
    await run.execute({})

    assert run.size == 2
    assert seen[-1] == (2, 2)


def test_a_dependency_on_a_key_nothing_produces_is_refused() -> None:
    """Silently skipping forever is the alternative, and it looks exactly like
    a permission problem from the outside."""
    with pytest.raises(ValueError, match="which no task produces"):
        CollectionRun([task(Evidence.A, depends_on=("typo",))])


def test_a_cycle_is_refused_rather_than_hung() -> None:
    with pytest.raises(ValueError, match="dependency cycle"):
        CollectionRun(
            [task(Evidence.A, depends_on=(Evidence.B,)), task(Evidence.B, depends_on=(Evidence.A,))]
        ).waves()


def test_duplicate_keys_are_refused() -> None:
    """Two tasks writing one key means one silently wins."""
    with pytest.raises(ValueError, match="Duplicate collection task keys: a"):
        CollectionRun([task(Evidence.A), task(Evidence.A)])


# ------------------------------------------------------------- running a plan
def carried(key, payload, *, age_hours: int = 3) -> CarriedReading:
    return CarriedReading(
        key=key,
        payload=payload,
        collected_at=datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
        - timedelta(hours=age_hours),
        item_count=len(payload),
        permissions=("Microsoft.Test/read",),
    )


async def test_a_plan_narrows_what_is_read_from_the_provider() -> None:
    """The provider still declares every task; the plan says which to run."""
    run = CollectionRun(
        [task(Evidence.A), task(Evidence.B), task(Evidence.C)],
        plan=CollectionPlan(collect=frozenset({Evidence.A, Evidence.C})),
    )
    data: dict = {}
    report = await run.execute(data)

    assert data == {"a": ["a"], "c": ["c"]}
    assert set(report.results) == {"a", "c"}


async def test_a_plan_naming_a_key_this_provider_lacks_asks_for_nothing() -> None:
    """A requirement set spans every scope a scan covers.

    The account plan holds no directory tasks and the directory plan holds no
    subscription ones, so each is handed keys it cannot produce every time. That
    is not a plan to refuse -- it is the other scope's half of the same scan.
    """
    run = CollectionRun(
        [task(Evidence.A)],
        plan=CollectionPlan(collect=frozenset({Evidence.A, Evidence.LATE})),
    )
    assert [t.key for t in run.tasks] == [Evidence.A]


async def test_a_carried_reading_is_not_read_again_but_is_still_in_the_capture() -> None:
    """The capture has to be whole however much of it was read just now.

    Replay reads the snapshot and the normalizer reads the merged data, so a
    hole where a task used to be would read as evidence that never arrived
    rather than as evidence already held.
    """
    run = CollectionRun(
        [task(Evidence.A), task(Evidence.B, boom="must not be called")],
        plan=CollectionPlan(
            collect=frozenset({Evidence.A, Evidence.B}),
            carried={Evidence.B: carried(Evidence.B, {"b": ["from-yesterday"]})},
        ),
    )
    data: dict = {}
    report = await run.execute(data)

    assert data == {"a": ["a"], "b": ["from-yesterday"]}
    assert report.is_complete
    assert report.payloads["b"] == {"b": ["from-yesterday"]}


async def test_a_carried_reading_is_complete_and_says_when_it_was_taken() -> None:
    """Age is not incompleteness.

    The reading is exactly what the provider said; ``carried_from`` says when it
    said it. Recording it as PARTIAL would tell every rule reading it to return
    UNKNOWN, which is how saving a request turns into knowing less.
    """
    reading = carried(Evidence.B, {"b": ["x"]})
    run = CollectionRun(
        [task(Evidence.B)],
        plan=CollectionPlan(collect=frozenset({Evidence.B}), carried={Evidence.B: reading}),
    )
    report = await run.execute({})

    result = report.results["b"]
    assert result.outcome == TaskOutcome.COMPLETE
    assert result.carried_from == reading.collected_at
    assert report.key_problems() == {}
    assert report.to_json()["b"]["carried_from"] == reading.collected_at.isoformat()


async def test_a_reading_taken_now_carries_no_timestamp() -> None:
    """A capture taken entirely by this run looks exactly as it always did."""
    report = await CollectionRun([task(Evidence.A)]).execute({})
    assert report.results["a"].carried_from is None
    assert "carried_from" not in report.to_json()["a"]


async def test_a_carried_reading_satisfies_what_depends_on_it() -> None:
    """Its payload is seeded before the first wave, so a dependent task reads
    its input without being able to tell where it came from."""
    seen: dict = {}

    async def dependent(collected: dict) -> TaskData:
        seen.update(collected)
        return TaskData({"dependent": ["ok"]})

    run = CollectionRun(
        [
            task(Evidence.SOURCE, boom="must not be called"),
            CollectionTask(
                key=Evidence.DEPENDENT, run=dependent, depends_on=(Evidence.SOURCE,)
            ),
        ],
        plan=CollectionPlan(
            collect=frozenset({Evidence.SOURCE, Evidence.DEPENDENT}),
            carried={Evidence.SOURCE: carried(Evidence.SOURCE, {"source": ["held"]})},
        ),
    )
    report = await run.execute({})

    assert seen["source"] == ["held"]
    assert report.results["dependent"].outcome == TaskOutcome.COMPLETE


async def test_a_plan_that_drops_an_input_still_collects_it() -> None:
    """Asking for diagnostic settings is asking for the ids they are read from.

    Dependencies are declared by the provider, on the tasks, so a planner that
    knows only what the rules asked for cannot know this. The closure is taken
    here rather than refused here -- the alternative is a scan that raises on a
    plan nobody could tell was incomplete.
    """
    run = CollectionRun(
        [
            task(Evidence.SOURCE),
            task(Evidence.DEPENDENT, depends_on=(Evidence.SOURCE,)),
        ],
        plan=CollectionPlan(collect=frozenset({Evidence.DEPENDENT})),
    )
    data: dict = {}
    await run.execute(data)

    assert {t.key for t in run.tasks} == {Evidence.SOURCE, Evidence.DEPENDENT}
    assert data["source"] == ["source"]


async def test_progress_counts_only_what_is_actually_read() -> None:
    """A carried reading is not work, and a denominator that counted it would
    stall at the fraction the run never has to do."""
    seen: list[tuple[int, int]] = []

    async def record(done: int, total: int) -> None:
        seen.append((done, total))

    run = CollectionRun(
        [task(Evidence.A), task(Evidence.B)],
        on_progress=record,
        plan=CollectionPlan(
            collect=frozenset({Evidence.A, Evidence.B}),
            carried={Evidence.B: carried(Evidence.B, {"b": ["held"]})},
        ),
    )
    await run.execute({})

    assert run.size == 1
    assert seen[-1] == (1, 1)
