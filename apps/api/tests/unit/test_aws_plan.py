"""The AWS collection plan, and what its shape depends on.

The plan is the only one in this codebase whose *shape* is a function of a call.
Azure's eleven tasks are eleven tasks whatever the subscription holds; AWS emits
one task per listing per enabled region, so the region listing has to happen
before there is a plan at all.

The case worth the most care is the one where that listing fails. A key with no
reading at all raises no gap, so a rule would see no error, evaluate against an
empty payload and PASS -- reporting a clean estate it never looked at. The
skipped tasks are what stop that, and the tests below are what stop the skipped
tasks from being quietly removed as redundant.
"""

from typing import Any, ClassVar

import pytest

from app.connectors.aws import iam
from app.connectors.aws.client import AwsApiError
from app.connectors.aws.evidence import AwsEvidence
from app.connectors.aws.plan import ACTION_KEYS, AwsPlanBuilder
from app.connectors.collection import CollectionRun
from app.core.enums import TaskOutcome as Outcome


class FakeClient:
    """An AWS client that answers from a prepared account.

    Records what was called, so a test can assert that a global service was
    asked once and a regional one once per region -- which is the whole
    difference between this connector and the Azure one.
    """

    calls: ClassVar[list[tuple[str, str | None, str]]] = []
    responses: ClassVar[dict[str, Any]] = {}
    listings: ClassVar[dict[str, list[dict]]] = {}
    fails: ClassVar[dict[str, str]] = {}
    paginated: ClassVar[set[str]] = set()

    def __init__(self, service: str, region: str | None) -> None:
        self.service = service
        self.region = region
        self.truncated: set[str] = set()

    async def __aenter__(self) -> "FakeClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    def can_paginate(self, operation: str) -> bool:
        return operation in type(self).paginated

    async def call(self, operation: str, **kwargs: Any) -> dict:
        type(self).calls.append((self.service, self.region, operation))
        if operation in type(self).fails:
            raise AwsApiError(
                type(self).fails[operation], code="AccessDenied", operation=operation
            )
        return dict(type(self).responses.get(operation) or {})

    async def paginate(self, operation: str, key: str, **kwargs: Any) -> list[dict]:
        type(self).calls.append((self.service, self.region, operation))
        if operation in type(self).fails:
            raise AwsApiError(
                type(self).fails[operation], code="AccessDenied", operation=operation
            )
        return list(type(self).listings.get(operation) or [])

    async def optional(self, operation: str, **kwargs: Any) -> dict | None:
        try:
            return await self.call(operation, **kwargs)
        except AwsApiError:
            return None


@pytest.fixture(autouse=True)
def account(monkeypatch: pytest.MonkeyPatch) -> type[FakeClient]:
    FakeClient.calls = []
    FakeClient.fails = {}
    FakeClient.paginated = {
        "describe_security_groups",
        "describe_vpcs",
        "describe_subnets",
        "describe_network_interfaces",
        "describe_addresses",
        "describe_instances",
        "describe_db_instances",
        "list_users",
        "list_roles",
        "list_policies",
        "list_keys",
        "list_accounts",
    }
    FakeClient.responses = {
        "describe_regions": {
            "Regions": [{"RegionName": "eu-west-1"}, {"RegionName": "us-east-1"}]
        },
        "list_buckets": {"Buckets": [{"Name": "logs"}]},
        "get_bucket_location": {"LocationConstraint": "eu-west-1"},
        "get_account_summary": {"SummaryMap": {"AccountMFAEnabled": 1}},
        "get_ebs_encryption_by_default": {"EbsEncryptionByDefault": True},
        "list_detectors": {"DetectorIds": []},
        "describe_trails": {"trailList": []},
        "describe_configuration_recorders": {"ConfigurationRecorders": []},
        "get_account_password_policy": {"PasswordPolicy": {"MinimumPasswordLength": 8}},
        "get_credential_report": {"Content": b"user,arn\nroot,arn:aws:iam::1:root\n"},
        "generate_credential_report": {},
    }
    FakeClient.listings = {
        "describe_security_groups": [{"GroupId": "sg-1"}],
        "list_users": [{"UserName": "ana", "Arn": "arn:aws:iam::1:user/ana"}],
    }
    monkeypatch.setattr(
        AwsPlanBuilder,
        "client",
        lambda self, service, region=None: FakeClient(service, region or "us-east-1"),
    )
    return FakeClient


def builder() -> AwsPlanBuilder:
    return AwsPlanBuilder.__new__(AwsPlanBuilder)  # no assumer needed; client is faked


def prepared() -> AwsPlanBuilder:
    plan = builder()
    plan.assumer = object()  # type: ignore[assignment]
    plan.account_id = "111122223333"
    plan.session = None
    plan.home_region = "us-east-1"
    return plan


# --------------------------------------------------------------- the fan-out
async def test_a_regional_listing_becomes_one_task_per_enabled_region() -> None:
    tasks = await prepared().build_account_plan()

    groups = [t for t in tasks if t.key is AwsEvidence.SECURITY_GROUPS]
    assert sorted(t.region for t in groups) == ["eu-west-1", "us-east-1"]
    assert {t.scoped_key for t in groups} == {
        "security_groups@eu-west-1",
        "security_groups@us-east-1",
    }


async def test_a_global_listing_stays_one_task() -> None:
    """IAM and the bucket list answer the same thing in every region.

    Asking them per region would return the same answer seventeen times, pay
    for it seventeen times, and store it seventeen times.
    """
    tasks = await prepared().build_account_plan()

    for key in (AwsEvidence.IAM_USERS, AwsEvidence.S3_BUCKETS):
        listings = [t for t in tasks if t.key is key]
        assert len(listings) == 1
        assert listings[0].region is None


async def test_only_enabled_regions_are_read() -> None:
    """``AllRegions=False`` is the default and the one that matters.

    A customer with two regions enabled out of thirty must not pay for
    twenty-eight listings that answer nothing.
    """
    FakeClient.responses["describe_regions"] = {
        "Regions": [{"RegionName": "eu-west-1"}]
    }
    tasks = await prepared().build_account_plan()

    assert {t.region for t in tasks if t.region} == {"eu-west-1"}


# ------------------------------------------------- when the regions are unknown
async def test_a_failed_region_listing_still_names_every_regional_key() -> None:
    """The failure mode this whole arrangement exists to prevent.

    Without a task per regional key, ``security_groups`` would be absent from
    the coverage report entirely -- no reading, therefore no gap, therefore no
    rule degraded, therefore a PASS over an estate nobody looked at.
    """
    FakeClient.fails = {"describe_regions": "denied"}
    tasks = await prepared().build_account_plan()

    regional = {t.key for t in tasks if t.depends_on == (AwsEvidence.ENABLED_REGIONS,)}
    assert AwsEvidence.SECURITY_GROUPS in regional
    assert AwsEvidence.EC2_INSTANCES in regional
    assert AwsEvidence.RDS_INSTANCES in regional
    assert all(t.region is None for t in tasks if t.key in regional)


async def test_those_tasks_are_recorded_as_skipped_rather_than_never_run() -> None:
    FakeClient.fails = {"describe_regions": "denied"}
    tasks = await prepared().build_account_plan()

    report = await CollectionRun(tasks).execute({})

    assert report.results["enabled_regions"].outcome is Outcome.FAILED
    assert report.results["security_groups"].outcome is Outcome.SKIPPED
    # And the gap reaches the rules, which is the point of recording it.
    assert "security_groups" in report.key_problems()
    assert report.key_is_trustworthy(AwsEvidence.SECURITY_GROUPS) is False


async def test_an_account_reporting_no_regions_is_not_an_empty_estate() -> None:
    """An empty region list is a failure to answer, not an answer.

    Treating it as "this account has nothing" would report a clean posture for
    an account CloudGuard could not enumerate.
    """
    FakeClient.responses["describe_regions"] = {"Regions": []}
    tasks = await prepared().build_account_plan()

    report = await CollectionRun(tasks).execute({})
    assert report.results["enabled_regions"].outcome is Outcome.FAILED


# ------------------------------------------------------------- the two plans
def test_the_organization_plan_reads_the_account_list_and_nothing_else() -> None:
    """AWS keeps identity in each account, unlike an Entra directory.

    So the trust boundary holds the account list and nothing else CloudGuard
    reads -- every IAM listing belongs to the account plan.
    """
    tasks = prepared().build_directory_plan()

    assert [t.key for t in tasks] == [AwsEvidence.ORGANIZATION_ACCOUNTS]


# ------------------------------------------------- the plan against the policy
async def test_every_task_declares_actions_the_policy_grants() -> None:
    """The forward guard: a call with no permission behind it.

    Without this, a listing added without its action reaches a customer as an
    AccessDenied several minutes into a scan rather than as a failing test.
    """
    tasks = await prepared().build_account_plan()
    tasks += prepared().build_directory_plan()

    granted = set(iam.INLINE_READ_ACTIONS) | iam.MANAGED_ACTIONS
    for task in tasks:
        # The blocked placeholders declare nothing, and correctly: they never
        # call anything.
        if not task.actions:
            assert task.depends_on == (AwsEvidence.ENABLED_REGIONS,)
            continue
        for action in task.actions:
            assert action in granted, f"{task.key} needs {action}, which nothing grants"


async def test_every_declared_action_serves_a_key_somebody_reads() -> None:
    """The reverse guard: a permission nothing exercises.

    An action no call makes has never been checked against AWS by anything, and
    asking a customer to grant it is asking for access CloudGuard cannot
    demonstrate a use for.
    """
    tasks = await prepared().build_account_plan()
    tasks += prepared().build_directory_plan()
    used = {action for task in tasks for action in task.actions}

    for action in iam.INLINE_READ_ACTIONS:
        if action == "organizations:DescribeOrganization":
            # Granted for the onboarding probe rather than for a collection
            # task, which is why it is the one exception and is named here.
            continue
        assert action in used, f"{action} is granted and nothing calls it"


def test_every_action_maps_to_the_keys_it_serves() -> None:
    """So "your stack is missing three actions" becomes "these checks stop"."""
    for action in iam.INLINE_READ_ACTIONS:
        if action == "organizations:DescribeOrganization":
            continue
        assert ACTION_KEYS.get(action), f"{action} serves no evidence key"


# ---------------------------------------------------------------- truncation
async def test_a_truncated_listing_is_partial_rather_than_short(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A list missing an unknown number of entries cannot support "none of them".

    The same position the Azure client takes, and it has to be taken here too:
    botocore's paginator will happily walk a million pages, and the cap that
    stops it is only honest if stopping is recorded.
    """
    tasks = await prepared().build_account_plan()
    groups = next(t for t in tasks if t.key is AwsEvidence.SECURITY_GROUPS)

    class Truncating(FakeClient):
        async def paginate(self, operation: str, key: str, **kwargs: Any) -> list[dict]:
            self.truncated.add(operation)
            return [{"GroupId": "sg-1"}]

    monkeypatch.setattr(
        AwsPlanBuilder,
        "client",
        lambda self, service, region=None: Truncating(service, region),
    )
    result = await groups.run({})

    assert result.partial_reason == "describe_security_groups stopped at the page cap"
