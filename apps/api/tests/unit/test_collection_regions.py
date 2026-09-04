"""Collection where a listing is per region.

Azure's ARM answers for a whole subscription, so one evidence key meant one
reading and the executor could identify a task by its key alone. AWS reads
almost everything per region, so one key becomes seventeen readings that
succeed and fail independently -- and the question the rules ask does not
change at all. A rule depends on evidence, never on a region.

So the executor gained two halves that have to agree. Readings are kept apart,
one per region, because they are separate facts and separate evidence rows.
Verdicts are aggregated back to the bare key, because "no security group is
open" is not a conclusion a view missing a region can support.
"""

import asyncio

import pytest

from app.connectors.collection import (
    CollectionRun,
    CollectionTask,
    TaskData,
    TaskOutcome,
)
from app.connectors.evidence import EvidenceCategory, EvidenceKey


class Evidence(EvidenceKey):
    """Keys for this test, not any provider's."""

    REGIONS = "regions"
    SECURITY_GROUPS = "security_groups"
    INSTANCES = "instances"
    ACCOUNT = "account"

    @property
    def category(self) -> EvidenceCategory:
        if self is Evidence.SECURITY_GROUPS:
            return EvidenceCategory.NETWORK
        if self is Evidence.INSTANCES:
            return EvidenceCategory.COMPUTE
        return EvidenceCategory.RESOURCES


def task(key, region=None, depends_on=(), *, items=None, boom=None, partial=None):
    async def run(collected: dict) -> TaskData:
        if boom:
            raise RuntimeError(boom)
        return TaskData(
            {key.value: items if items is not None else [region or "global"]},
            partial_reason=partial,
        )

    return CollectionTask(key=key, run=run, region=region, depends_on=depends_on)


# ------------------------------------------------------------------- the capture
async def test_each_region_appends_a_block_naming_itself() -> None:
    """The provider's payload is untouched; the region sits beside it.

    Flattening the regions into one list would lose the only place the region
    is recorded for the services whose identifiers do not carry it.
    """
    data: dict = {}
    await CollectionRun(
        [
            task(Evidence.SECURITY_GROUPS, "eu-west-1", items=["sg-1"]),
            task(Evidence.SECURITY_GROUPS, "us-east-1", items=["sg-2"]),
        ]
    ).execute(data)

    assert sorted(data["security_groups"], key=lambda b: b["region"]) == [
        {"region": "eu-west-1", "items": ["sg-1"]},
        {"region": "us-east-1", "items": ["sg-2"]},
    ]


async def test_a_global_task_still_replaces_its_key() -> None:
    """Unchanged for every Azure task, which is the point of the default."""
    data: dict = {}
    await CollectionRun([task(Evidence.ACCOUNT, items=["one"])]).execute(data)

    assert data == {"account": ["one"]}


async def test_two_regions_are_two_readings_not_one_overwritten() -> None:
    data: dict = {}
    report = await CollectionRun(
        [
            task(Evidence.SECURITY_GROUPS, "eu-west-1"),
            task(Evidence.SECURITY_GROUPS, "us-east-1"),
        ]
    ).execute(data)

    assert set(report.results) == {
        "security_groups@eu-west-1",
        "security_groups@us-east-1",
    }
    entry = report.to_json()["security_groups@eu-west-1"]
    # The bare key is stated, so nothing downstream has to split the name back
    # apart to learn what the reading was a reading of.
    assert entry["key"] == "security_groups"
    assert entry["region"] == "eu-west-1"


async def test_a_global_reading_is_filed_under_its_bare_key() -> None:
    report = await CollectionRun([task(Evidence.ACCOUNT)]).execute({})

    assert set(report.results) == {"account"}
    assert report.to_json()["account"]["region"] is None


# --------------------------------------------------------- aggregating verdicts
async def test_one_failed_region_costs_the_whole_key() -> None:
    """Sixteen good regions do not make a listing trustworthy.

    A rule reading ``security_groups`` is asking about the estate. If one
    region never answered, the honest verdict is UNKNOWN -- exactly as it is
    for a listing truncated at the page cap.
    """
    report = await CollectionRun(
        [
            task(Evidence.SECURITY_GROUPS, "eu-west-1"),
            task(Evidence.SECURITY_GROUPS, "us-east-1", boom="AccessDenied"),
        ]
    ).execute({})

    assert report.key_is_trustworthy(Evidence.SECURITY_GROUPS) is False
    assert report.is_complete is False


async def test_every_region_succeeding_leaves_the_key_trustworthy() -> None:
    report = await CollectionRun(
        [
            task(Evidence.SECURITY_GROUPS, "eu-west-1"),
            task(Evidence.SECURITY_GROUPS, "us-east-1"),
        ]
    ).execute({})

    assert report.key_is_trustworthy(Evidence.SECURITY_GROUPS) is True
    assert report.is_complete


async def test_a_key_nothing_read_is_not_trustworthy() -> None:
    """False rather than vacuously true: there is nothing to rely on."""
    report = await CollectionRun([task(Evidence.ACCOUNT)]).execute({})

    assert report.key_is_trustworthy(Evidence.SECURITY_GROUPS) is False
    assert report.saw(Evidence.SECURITY_GROUPS) is False


async def test_the_gap_is_reported_once_and_names_the_region() -> None:
    """Rules degrade per key, so the gap is per key -- and still says where.

    Reporting it per region would hand the rule engine a key it has never
    heard of; reporting it without the region would tell a customer their
    security groups failed and leave them checking seventeen of them.
    """
    report = await CollectionRun(
        [
            task(Evidence.SECURITY_GROUPS, "eu-west-1"),
            task(Evidence.SECURITY_GROUPS, "us-east-1", boom="AccessDenied"),
            task(Evidence.SECURITY_GROUPS, "ap-south-1", partial="page cap"),
        ]
    ).execute({})

    problems = report.key_problems()
    assert set(problems) == {"security_groups"}
    assert "us-east-1: AccessDenied" in problems["security_groups"]
    assert "ap-south-1: page cap" in problems["security_groups"]
    assert "eu-west-1" not in problems["security_groups"]


async def test_the_category_view_names_the_reading_that_failed() -> None:
    report = await CollectionRun(
        [task(Evidence.SECURITY_GROUPS, "us-east-1", boom="AccessDenied")]
    ).execute({})

    assert (
        report.category_problems()["network"]
        == "security_groups@us-east-1: AccessDenied"
    )


# ------------------------------------------------------------------ dependencies
async def test_a_dependent_task_waits_for_every_region() -> None:
    """Scheduled after the last region, not after the first.

    A task that reads the instance listing to fan out from it would otherwise
    run against one region's worth and report the rest as absent.
    """
    run = CollectionRun(
        [
            task(Evidence.INSTANCES, "eu-west-1"),
            task(Evidence.INSTANCES, "us-east-1"),
            task(Evidence.ACCOUNT, depends_on=(Evidence.INSTANCES,)),
        ]
    )

    waves = [sorted(t.scoped_key for t in wave) for wave in run.waves()]
    assert waves == [["instances@eu-west-1", "instances@us-east-1"], ["account"]]


async def test_one_failed_region_skips_what_depended_on_the_listing() -> None:
    report = await CollectionRun(
        [
            task(Evidence.INSTANCES, "eu-west-1"),
            task(Evidence.INSTANCES, "us-east-1", boom="AccessDenied"),
            task(Evidence.ACCOUNT, depends_on=(Evidence.INSTANCES,)),
        ]
    ).execute({})

    assert report.results["account"].outcome == TaskOutcome.SKIPPED
    assert "instances" in report.results["account"].detail


async def test_a_regional_task_may_depend_on_a_global_one() -> None:
    """Which is how the region list itself is collected: a task like any other."""
    data: dict = {}
    report = await CollectionRun(
        [
            task(Evidence.REGIONS, items=["eu-west-1"]),
            task(Evidence.SECURITY_GROUPS, "eu-west-1", depends_on=(Evidence.REGIONS,)),
        ]
    ).execute(data)

    assert report.is_complete
    assert data["security_groups"] == [{"region": "eu-west-1", "items": ["eu-west-1"]}]


async def test_a_failed_region_list_skips_every_regional_task() -> None:
    report = await CollectionRun(
        [
            task(Evidence.REGIONS, boom="AccessDenied"),
            task(Evidence.SECURITY_GROUPS, "eu-west-1", depends_on=(Evidence.REGIONS,)),
        ]
    ).execute({})

    skipped = report.results["security_groups@eu-west-1"]
    assert skipped.outcome == TaskOutcome.SKIPPED
    assert skipped.region == "eu-west-1"


# ----------------------------------------------------------------- what is a typo
async def test_the_same_key_twice_in_one_region_is_still_a_duplicate() -> None:
    with pytest.raises(ValueError, match="Duplicate collection task keys"):
        CollectionRun(
            [
                task(Evidence.SECURITY_GROUPS, "eu-west-1"),
                task(Evidence.SECURITY_GROUPS, "eu-west-1"),
            ]
        )


# ------------------------------------------------------------------- concurrency
async def test_a_fan_out_is_capped_at_what_the_provider_will_take() -> None:
    """Unbounded was fine for eleven listings and is not for a hundred.

    AWS throttles per region per service, and a wave that opened every region
    at once would be shaped to be throttled. A provider that asks for no cap
    keeps the behaviour it had.
    """
    in_flight = 0
    peak = 0

    def watched(region: str) -> CollectionTask:
        async def run(collected: dict) -> TaskData:
            nonlocal in_flight, peak
            in_flight += 1
            peak = max(peak, in_flight)
            await asyncio.sleep(0)
            in_flight -= 1
            return TaskData({Evidence.SECURITY_GROUPS.value: [region]})

        return CollectionTask(
            key=Evidence.SECURITY_GROUPS, run=run, region=region
        )

    regions = [f"region-{n}" for n in range(10)]
    await CollectionRun(
        [watched(r) for r in regions], max_concurrency=3
    ).execute({})

    assert peak <= 3
