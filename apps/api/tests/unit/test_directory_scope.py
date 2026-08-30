"""The directory is read once per scan, not once per subscription.

The bug this pins was not a cost problem, though it was that too. Directory
tasks lived in the per-subscription plan, so a twenty-subscription tenant read
the whole directory twenty times and normalized twenty copies of every user.
``cloud_resources`` was unique on (cloud_account_id, provider_resource_id), so
those copies were twenty separate asset rows -- and findings are identified by
(organization, rule, resource), so one administrator without MFA produced
twenty CRITICAL findings for one missing second factor.

Everything here runs without a database, Azure or a network: the plans are
declarations, and what they declare is exactly the thing that went wrong.
"""

import httpx
import pytest

from app.connectors.azure.plan import AzurePlanBuilder
from app.connectors.base import RawSnapshot
from app.core.enums import CollectionScope, Provider, ResourceType
from app.rules.azure.identity.mfa import AzureMfaRule
from app.rules.base import RuleContext


class FakeTokens:
    def arm_token(self) -> str:
        return "arm"

    def graph_token(self) -> str:
        return "graph"


def builder(subscription_id: str | None) -> AzurePlanBuilder:
    """A plan builder that never calls Azure. ``build_*`` only assembles
    closures; nothing runs until the executor runs them."""
    return AzurePlanBuilder(
        tokens=FakeTokens(),
        subscription_id=subscription_id,
        http_client=httpx.AsyncClient(),
    )


# --------------------------------------------------------------- the split
def test_the_account_plan_reads_no_directory() -> None:
    """The whole fix, stated as one assertion.

    An identity task in this plan runs once per subscription and returns the
    same tenant every time.
    """
    categories = {task.category for task in builder("sub-1").build_account_plan()}
    assert "identity" not in categories


def test_the_directory_plan_reads_only_the_directory() -> None:
    tasks = builder(None).build_directory_plan()
    assert tasks, "the directory plan must actually collect something"
    assert {task.category for task in tasks} == {"identity"}


def test_the_directory_plan_needs_no_subscription() -> None:
    """Graph is scoped by the token, not by a subscription in the URL.

    Worth pinning because the builder still takes an optional subscription:
    a directory plan that quietly required one would reintroduce the per-account
    coupling by the back door.
    """
    assert builder(None).build_directory_plan()


def test_an_account_plan_without_a_subscription_is_refused() -> None:
    """Rather than building URLs with ``None`` in them and failing per task."""
    with pytest.raises(ValueError, match="subscription"):
        builder(None).build_account_plan()


def test_the_two_plans_do_not_overlap() -> None:
    """No task key appears in both, so nothing is collected twice per scan."""
    account = {t.key for t in builder("sub-1").build_account_plan()}
    directory = {t.key for t in builder(None).build_directory_plan()}
    assert not account & directory


# ---------------------------------------------------- what the split prevents
def _user(object_id: str, roles: list[str]) -> dict:
    return {
        "id": object_id,
        "displayName": "Ada",
        "userPrincipalName": "ada@contoso.com",
        "accountEnabled": True,
    }


def directory_snapshot() -> RawSnapshot:
    """One tenant holding one privileged user with no MFA method."""
    return RawSnapshot(
        provider=Provider.AZURE,
        tenant_id="tenant-1",
        subscription_id=None,
        scope=CollectionScope.DIRECTORY,
        data={
            "users": [_user("user-1", ["Global Administrator"])],
            "directory_roles": [{"id": "role-1", "displayName": "Global Administrator"}],
            "user_role_map": {"user-1": ["Global Administrator"]},
            # Read, and empty: the administrator genuinely has no method
            # registered. Absent would be UNKNOWN instead, which is a different
            # test.
            "authentication_methods": {"user-1": []},
        },
    )


def test_one_administrator_produces_one_finding_however_many_subscriptions() -> None:
    """The duplication, reproduced at the layer it actually surfaced.

    A tenant-wide scan merges each collection's normalized state into one
    ``RuleContext``. Under the old shape every subscription contributed its own
    copy of the directory, so the rule saw the same user N times and failed N
    times -- N findings for one person. Collected once, it fails once, whatever
    the subscription count.
    """
    from app.connectors.azure.normalizer import AzureNormalizer

    state = AzureNormalizer().normalize(directory_snapshot())
    users = [r for r in state.resources if r.resource_type == ResourceType.USER]
    assert len(users) == 1

    # What the pipeline builds: one directory state, merged once, alongside any
    # number of subscriptions that contribute no users at all.
    context = RuleContext(resources=list(state.resources))
    results = [
        result
        for resource in context.resources
        if AzureMfaRule().matches(resource)
        for result in [AzureMfaRule().evaluate(resource, context)]
    ]
    failures = [r for r in results if r.state.value == "FAIL"]
    assert len(failures) == 1


def test_a_directory_snapshot_round_trips_as_a_directory_snapshot() -> None:
    """Replay has to know which scope it is holding.

    A stored capture that came back as ACCOUNT would be looked up against a
    subscription it never had, and the directory half of an old scan would
    silently drop out of the replay.
    """
    restored = RawSnapshot.from_json(directory_snapshot().to_json())
    assert restored.scope == CollectionScope.DIRECTORY
    assert restored.subscription_id is None


def test_a_snapshot_stored_before_the_split_reads_as_an_account_capture() -> None:
    """Every capture taken before this existed was a subscription capture.

    ACCOUNT is not a lenient default here; it is the fact about those rows.
    """
    legacy = {
        "provider": "azure",
        "tenant_id": "tenant-1",
        "subscription_id": "sub-1",
        "version": "1.0",
        "data": {},
        "errors": {},
        "coverage": {},
    }
    assert RawSnapshot.from_json(legacy).scope == CollectionScope.ACCOUNT
