"""What CloudGuard asks AWS to allow, and the stack that grants it.

The sibling of ``test_azure_rbac.py``, with the same two-way discipline: every
call has a permission and every permission has a call. The AWS half needs it
more, not less. ARM refuses a role definition atomically, so a wrong action
string fails the deployment where the customer can see it; **IAM accepts a
policy naming an action that does not exist** and grants nothing, so the
deployment succeeds, the console is green, and the read fails mid-scan.

One assertion here is not negotiable. The trust policy must require an external
id. Without it, anybody who learns CloudGuard's account id can create a role
trusting CloudGuard and have it scan an environment on their behalf -- the
confused deputy, and the standard way third-party CSPM integrations get this
wrong.
"""

import json

import pytest

from app.connectors.aws import iam
from app.connectors.aws.iam import (
    INLINE_READ_ACTIONS,
    POLICY_HISTORY,
    POLICY_VERSION,
    TemplateContext,
    action_matches,
    actions_granted_by,
    cloudformation_template,
    launch_stack_url,
    version_of_granted,
)

PRINCIPAL = "arn:aws:iam::999988887777:user/cloudguard-scanner"
EXTERNAL_ID = "cg-abcdefghijklmnopqrstuvwx"


def context() -> TemplateContext:
    return TemplateContext(principal_arn=PRINCIPAL, external_id=EXTERNAL_ID)


def template() -> dict:
    return json.loads(cloudformation_template(context()))


def role_properties() -> dict:
    return template()["Resources"]["CloudGuardScannerRole"]["Properties"]


# --------------------------------------------------------- the external id
def test_the_trust_policy_requires_the_external_id() -> None:
    """The confused-deputy guard, and the reason this file exists.

    A role trusting CloudGuard's account with no condition can be created by
    anyone who knows that account id, and CloudGuard would then scan an
    environment on a stranger's behalf.
    """
    statement = role_properties()["AssumeRolePolicyDocument"]["Statement"][0]

    assert statement["Action"] == "sts:AssumeRole"
    assert statement["Principal"] == {"AWS": PRINCIPAL}
    assert statement["Condition"] == {
        "StringEquals": {"sts:ExternalId": EXTERNAL_ID}
    }


def test_the_external_id_reaches_the_customer_as_an_output() -> None:
    """So somebody reading the stack can see what it is without a support call."""
    assert template()["Outputs"]["ExternalId"]["Value"] == EXTERNAL_ID


# ------------------------------------------------------------ read-only
def test_the_inline_policy_grants_reads_and_nothing_else() -> None:
    """The claim "CloudGuard cannot write in your account" is checkable here.

    Verbs rather than a denylist: ``Get``, ``List`` and ``Describe`` are the
    read verbs, and the one exception is called out by name below.
    """
    allowed_prefixes = ("Get", "List", "Describe")
    for action in INLINE_READ_ACTIONS:
        verb = action.split(":", 1)[1]
        if action == "iam:GenerateCredentialReport":
            continue
        assert verb.startswith(allowed_prefixes), action


def test_the_one_action_that_reads_like_a_write_is_not_one() -> None:
    """``GenerateCredentialReport`` creates nothing and changes no configuration.

    It asks IAM to compile a report about state that already exists, and
    without it every credential-age check reports UNKNOWN. Pinned so nobody
    removes it as "the write in the read-only policy".
    """
    assert "iam:GenerateCredentialReport" in INLINE_READ_ACTIONS


def test_nothing_can_read_what_a_resource_contains() -> None:
    """Configuration, never contents.

    CloudGuard can say a bucket is public without being able to read a byte out
    of it, and a key exists without being able to decrypt anything with it.
    """
    forbidden = {
        "s3:GetObject",
        "kms:Decrypt",
        "secretsmanager:GetSecretValue",
        "ssm:GetParameter",
        "dynamodb:GetItem",
        "logs:GetLogEvents",
    }
    assert forbidden.isdisjoint(INLINE_READ_ACTIONS)


def test_the_policy_is_not_scoped_to_named_resources() -> None:
    """Deliberate, and worth stating rather than discovering.

    A CSPM that could only see the resources somebody remembered to list would
    report a clean posture over the ones they forgot. What bounds this is that
    every action is a read.
    """
    statement = role_properties()["Policies"][0]["PolicyDocument"]["Statement"][0]
    assert statement["Resource"] == "*"
    assert statement["Effect"] == "Allow"


def test_the_bulk_comes_from_policies_aws_maintains() -> None:
    """So a typo of ours cannot be the reason a customer's scan is short.

    IAM will not tell anyone that an action does not exist; it just grants
    nothing. The smaller the hand-written surface, the fewer ways that happens.
    """
    attached = role_properties()["ManagedPolicyArns"]
    assert "arn:aws:iam::aws:policy/SecurityAudit" in attached
    assert len(INLINE_READ_ACTIONS) < 30


# ------------------------------------------------------------ versioning
def test_the_current_version_is_recorded_in_the_history() -> None:
    """Bumping the version without recording its actions is the failure mode.

    A connection deployed at an unrecorded version can be told it is behind and
    not which checks it is losing, which is a notification rather than a
    decision.
    """
    assert POLICY_VERSION in POLICY_HISTORY
    assert POLICY_HISTORY[POLICY_VERSION] == INLINE_READ_ACTIONS


def test_the_version_is_read_from_what_a_policy_grants() -> None:
    """Not from a tag or a role name. A label is not evidence.

    It also gets the answer right for the customer who attached a broader
    policy of their own instead of deploying the stack.
    """
    granted = actions_granted_by(
        [{"Effect": "Allow", "Action": list(INLINE_READ_ACTIONS)}]
    )
    assert version_of_granted(granted) == POLICY_VERSION


def test_a_role_granting_something_unrelated_is_unknown_rather_than_old() -> None:
    """Absent is not the same as behind, and the caller treats them differently:
    it leaves the recorded version alone rather than replacing a fact with a
    probe that did not land."""
    granted = actions_granted_by([{"Effect": "Allow", "Action": ["lambda:Invoke*"]}])
    assert version_of_granted(granted) is None


def test_a_deny_statement_grants_nothing() -> None:
    granted = actions_granted_by(
        [{"Effect": "Deny", "Action": list(INLINE_READ_ACTIONS)}]
    )
    assert granted == set()


@pytest.mark.parametrize(
    ("granted", "wanted", "covered"),
    [
        ("s3:Get*", "s3:GetBucketPolicyStatus", True),
        ("*", "iam:GetAccountSummary", True),
        ("s3:*", "ec2:DescribeRegions", False),
        ("s3:GetObject", "s3:GetBucketLocation", False),
    ],
)
def test_a_wildcard_is_read_the_way_iam_reads_it(
    granted: str, wanted: str, covered: bool
) -> None:
    assert action_matches(granted, wanted) is covered


# --------------------------------------------------------------- the stack
def test_the_template_is_valid_json_with_one_role_in_it() -> None:
    body = template()
    assert body["AWSTemplateFormatVersion"] == "2010-09-09"
    assert list(body["Resources"]) == ["CloudGuardScannerRole"]
    assert body["Resources"]["CloudGuardScannerRole"]["Type"] == "AWS::IAM::Role"


def test_the_launch_link_carries_the_template_the_console_will_fetch() -> None:
    url = launch_stack_url("https://api.example.com/t.json?token=abc")

    assert "cloudformation" in url
    assert "templateURL=https%3A%2F%2Fapi.example.com%2Ft.json%3Ftoken%3Dabc" in url
    assert f"stackName={iam.STACK_NAME}" in url


def test_the_policy_version_travels_on_the_role() -> None:
    """So a customer looking at a deployed role can tell which one it is."""
    tags = {t["Key"]: t["Value"] for t in role_properties()["Tags"]}
    assert tags["PolicyVersion"] == POLICY_VERSION
