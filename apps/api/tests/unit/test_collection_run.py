"""The collection executor.

Collection used to be a fixed call sequence, which could express neither "these
two are independent" nor "this one needs that one's output" nor "this list
stopped early". The executor exists to make all three ordinary, and the third is
the one that was silently wrong: a truncated listing reached the rule engine as
though it were the whole environment, and a rule returned PASS over resources
nobody had looked at.
"""

import pytest

from app.connectors.collection import (
    CollectionRun,
    CollectionTask,
    TaskData,
    TaskOutcome,
)


def task(key, category="things", depends_on=(), *, data=None, partial=None, boom=None):
    async def run(collected: dict) -> TaskData:
        if boom:
            raise RuntimeError(boom)
        return TaskData(data if data is not None else {key: [key]}, partial_reason=partial)

    return CollectionTask(key=key, category=category, run=run, depends_on=depends_on)


# ----------------------------------------------------------------- the happy path
async def test_every_task_contributes_to_the_collected_data() -> None:
    data: dict = {}
    report = await CollectionRun([task("a"), task("b")]).execute(data)

    assert data == {"a": ["a"], "b": ["b"]}
    assert report.is_complete
    assert report.category_problems() == {}


async def test_independent_tasks_share_a_wave() -> None:
    run = CollectionRun([task("a"), task("b"), task("c")])
    assert [len(w) for w in run.waves()] == [3]


async def test_a_dependency_forces_a_later_wave() -> None:
    """``diagnostic_settings`` needs the ids storage and SQL produce. That used
    to be expressed as "call it fifth"."""
    run = CollectionRun([task("late", depends_on=("early",)), task("early")])
    waves = run.waves()

    assert [t.key for t in waves[0]] == ["early"]
    assert [t.key for t in waves[1]] == ["late"]


async def test_a_dependent_task_sees_what_its_dependency_produced() -> None:
    seen: dict = {}

    async def reader(collected: dict) -> TaskData:
        seen.update(collected)
        return TaskData({"reader": []})

    await CollectionRun(
        [
            task("source", data={"source": [1, 2, 3]}),
            CollectionTask(
                key="reader", category="things", run=reader, depends_on=("source",)
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
        [task("nsgs"), task("public_ips", boom="throttled"), task("nics")]
    ).execute(data)

    assert data["nsgs"] == ["nsgs"]
    assert data["nics"] == ["nics"]
    assert report.results["public_ips"].outcome == TaskOutcome.FAILED
    assert report.results["nsgs"].outcome == TaskOutcome.COMPLETE


async def test_a_failed_dependency_skips_rather_than_fails_its_dependents() -> None:
    """Nothing is wrong with the dependent task. Reporting it as failed would
    send someone looking for a second problem one hop from the real one."""
    report = await CollectionRun(
        [task("source", boom="gone"), task("dependent", depends_on=("source",))]
    ).execute({})

    assert report.results["source"].outcome == TaskOutcome.FAILED
    assert report.results["dependent"].outcome == TaskOutcome.SKIPPED
    assert "source" in report.results["dependent"].detail


async def test_a_skip_cascades_through_the_chain() -> None:
    report = await CollectionRun(
        [
            task("a", boom="gone"),
            task("b", depends_on=("a",)),
            task("c", depends_on=("b",)),
        ]
    ).execute({})

    assert report.results["c"].outcome == TaskOutcome.SKIPPED


# ------------------------------------------------------------------ the point
async def test_a_partial_result_keeps_its_data_and_forfeits_its_verdict() -> None:
    """The defect the whole module exists for. The data is still useful for an
    inventory; it is not evidence that nothing is wrong."""
    data: dict = {}
    report = await CollectionRun(
        [task("storage_accounts", category="storage", partial="the listing stopped early")]
    ).execute(data)

    assert data["storage_accounts"] == ["storage_accounts"]
    assert report.results["storage_accounts"].outcome == TaskOutcome.PARTIAL
    assert not report.is_complete


async def test_a_partial_result_degrades_its_category_like_a_failure() -> None:
    """PARTIAL lands in ``errors`` beside FAILED on purpose: the existing
    requires_collection path then degrades those rules to UNKNOWN, and no rule
    has to learn that truncation exists."""
    report = await CollectionRun(
        [task("storage_accounts", category="storage", partial="stopped early")]
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
            task("storage_accounts", partial="stopped early"),
            task("diagnostic_settings", depends_on=("storage_accounts",)),
        ]
    ).execute({})

    assert report.results["diagnostic_settings"].outcome == TaskOutcome.SKIPPED


# --------------------------------------------------------------- plan sanity
async def test_progress_is_reported_against_a_known_total() -> None:
    """The plan's size is known before it runs, which is what lets collection
    show a denominator during the phase that actually takes the time."""
    seen: list[tuple[int, int]] = []

    async def record(done: int, total: int) -> None:
        seen.append((done, total))

    run = CollectionRun([task("a"), task("b", depends_on=("a",))], on_progress=record)
    await run.execute({})

    assert run.size == 2
    assert seen[-1] == (2, 2)


def test_a_dependency_on_a_key_nothing_produces_is_refused() -> None:
    """Silently skipping forever is the alternative, and it looks exactly like
    a permission problem from the outside."""
    with pytest.raises(ValueError, match="which no task produces"):
        CollectionRun([task("a", depends_on=("typo",))])


def test_a_cycle_is_refused_rather_than_hung() -> None:
    with pytest.raises(ValueError, match="dependency cycle"):
        CollectionRun(
            [task("a", depends_on=("b",)), task("b", depends_on=("a",))]
        ).waves()


def test_duplicate_keys_are_refused() -> None:
    """Two tasks writing one key means one silently wins."""
    with pytest.raises(ValueError, match="Duplicate collection task keys: a"):
        CollectionRun([task("a"), task("a")])
