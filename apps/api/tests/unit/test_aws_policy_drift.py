"""A customer's deployed policy is whatever it was on the day they ran the stack.

The AWS sibling of `test_role_drift.py`, and it exists for the same reason: a
check that needs a permission an older stack does not grant must say so in terms
the customer can act on. Until they redeploy, the rules behind it report UNKNOWN
rather than PASS.

The AWS half is worse than Azure's in one specific way, which is why the version
mechanism matters more here. ARM refuses a role definition atomically, so a
customer whose stack is short of a permission finds out at deploy time. **IAM
accepts a policy naming an action that does not exist** and grants nothing — the
stack creates, the console is green, and the read fails several minutes into a
scan.
"""

from itertools import pairwise

import pytest

from app.connectors.aws import iam
from app.connectors.aws.iam import (
    INLINE_READ_ACTIONS,
    POLICY_HISTORY,
    POLICY_VERSION,
    V1_ACTIONS,
    actions_missing_from,
    categories_behind,
    policy_is_current,
    version_of_granted,
)
from app.connectors.aws.onboarding import AwsOnboarding
from app.connectors.evidence import EvidenceCategory
from app.core.enums import CloudAccountStatus, ConnectionScope, ConsentStatus, Provider
from app.models.cloud_connection import CloudConnection


def connection(version: str) -> CloudConnection:
    return CloudConnection(
        provider=Provider.AWS,
        name="production",
        scope_type=ConnectionScope.ORGANIZATION,
        scope_id="111122223333",
        role_version=version,
        consent_status=ConsentStatus.GRANTED,
        status=CloudAccountStatus.ACTIVE,
    )


# ---------------------------------------------------------------- the history
def test_the_current_version_is_recorded_in_the_history() -> None:
    """Bumping the version without recording its actions is the failure mode.

    A connection deployed at an unrecorded version can be told it is behind and
    not which checks it is losing, which is a notification rather than a
    decision.
    """
    assert POLICY_VERSION in POLICY_HISTORY
    assert POLICY_HISTORY[POLICY_VERSION] == INLINE_READ_ACTIONS


def test_an_older_version_is_written_out_rather_than_derived() -> None:
    """What v1 granted is a fact about v1.

    Slicing it off today's list would make it change every time today's list
    does -- so a customer running v1 would be told they have whatever the code
    currently asks for.
    """
    assert POLICY_HISTORY["v1"] == V1_ACTIONS
    assert set(V1_ACTIONS) < set(INLINE_READ_ACTIONS)


def test_every_version_grants_something_the_one_before_did_not() -> None:
    """A version that grants exactly what its predecessor did is a bump nobody
    needed, and it costs every existing customer a redeploy prompt for nothing."""
    versions = list(POLICY_HISTORY)
    for older, newer in pairwise(versions):
        assert set(POLICY_HISTORY[older]) < set(POLICY_HISTORY[newer]), (
            f"{newer} grants no more than {older}"
        )


# --------------------------------------------------------------- what is lost
def test_an_older_policy_names_the_checks_it_cannot_serve() -> None:
    """"Two categories are degraded" is a number.

    "Your authorization and logging checks report UNKNOWN" is the sentence a
    customer can decide about.
    """
    missing = actions_missing_from("v1")
    assert "iam:GetPolicyVersion" in missing
    assert "ec2:DescribeFlowLogs" in missing

    behind = categories_behind("v1")
    assert EvidenceCategory.AUTHORIZATION in behind
    assert EvidenceCategory.LOGGING in behind


def test_the_current_policy_is_behind_on_nothing() -> None:
    assert actions_missing_from(POLICY_VERSION) == ()
    assert categories_behind(POLICY_VERSION) == frozenset()
    assert policy_is_current(POLICY_VERSION)


def test_a_version_nobody_recorded_loses_everything() -> None:
    """Absent from the history is not "current". A connection stamped with a
    version this code has never heard of has to be treated as granting nothing
    -- the alternative is reporting PASS on checks it cannot serve."""
    assert set(actions_missing_from("v0")) == set(INLINE_READ_ACTIONS)


# -------------------------------------------------------- what is deployed
def test_the_version_is_read_from_what_is_granted_not_from_a_label() -> None:
    """A tag is a label and a label is not evidence.

    It also gets the answer right for the customer who attached a broader policy
    of their own instead of deploying the stack.
    """
    granted = iam.actions_granted_by(
        [{"Effect": "Allow", "Action": list(V1_ACTIONS)}]
    )
    assert version_of_granted(granted) == "v1"

    granted_now = iam.actions_granted_by(
        [{"Effect": "Allow", "Action": list(INLINE_READ_ACTIONS)}]
    )
    assert version_of_granted(granted_now) == POLICY_VERSION


def test_a_wildcard_grant_covers_every_version() -> None:
    """A customer who attached ``AdministratorAccess`` has the access, whatever
    they did or did not deploy."""
    granted = iam.actions_granted_by([{"Effect": "Allow", "Action": "*"}])
    assert version_of_granted(granted) == POLICY_VERSION


# ---------------------------------------------------- what the customer sees
@pytest.mark.parametrize("version", ["v1", "v0"])
def test_a_connection_on_an_older_policy_is_offered_a_redeploy(version: str) -> None:
    onboarding = AwsOnboarding()
    link = connection(version)

    assert onboarding.grant_is_behind(link) is True
    assert onboarding.required_grant_version(link) == POLICY_VERSION


def test_a_current_connection_is_not_nagged() -> None:
    onboarding = AwsOnboarding()
    link = connection(POLICY_VERSION)

    assert onboarding.grant_is_behind(link) is False
    assert onboarding.degraded_categories(link) == {}


def test_the_degraded_message_names_both_versions() -> None:
    """A customer told they are behind and not what to redeploy toward has been
    given a problem rather than an action."""
    explanations = set(AwsOnboarding().degraded_categories(connection("v1")).values())

    assert len(explanations) == 1
    message = explanations.pop()
    assert POLICY_VERSION in message
    assert "v1" in message
