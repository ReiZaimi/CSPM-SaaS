"""What CloudGuard needs AWS IAM to allow, and the stack that grants it.

The direct analogue of ``azure/rbac.py``, and deliberately the same discipline:
every action is declared here, every action is reached by a real collector call,
and a test enforces both directions. An action nothing calls has never been
checked against AWS by anything.

Two differences from the Azure role are worth stating, because they change what
a mistake costs.

**AWS does not validate a policy atomically against a list of real operations.**
ARM refuses an entire role definition for one string that is not a genuine
provider operation, which is what made ``Microsoft.Security/autoProvisioningSettings/read``
fail a whole deployment. IAM accepts a policy naming an action that does not
exist; it simply grants nothing. That is *worse*, not better: the deployment
succeeds, the customer sees green, and the reading fails at scan time with
``AccessDenied`` several minutes in.

**So the bulk comes from AWS's own managed policies.** ``SecurityAudit`` and
``ViewOnlyAccess`` are maintained by AWS, cover almost everything here, and
cannot contain a typo of ours. The inline policy holds only what they do not,
which keeps the hand-written surface small enough to review by eye.

.. warning::

   Every action string below is written from the published service reference
   and **has not been verified against a live account**. Entries carry
   ``# UNVERIFIED`` until the checklist in ``docs/AWS_INTEGRATION.md`` §1 has
   been run. Bump :data:`POLICY_VERSION` when the set changes, so a customer
   running an older stack can be offered a redeploy rather than silently
   collecting UNKNOWN.
"""

import json
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Any

from app.connectors.evidence import EvidenceCategory

# Bump when the action set changes.
POLICY_VERSION = "v1"

STACK_NAME = "CloudGuardSecurityScanner"
ROLE_NAME = "CloudGuardScannerRole"

# AWS-managed policies attached to the scanner role. Maintained by AWS, so a
# service that gains a new read action is covered without a redeploy, and no
# string here can be a typo of ours.
#
# ``SecurityAudit`` is the one AWS documents for exactly this purpose: read
# access to configuration, and to nothing a resource contains. ``ViewOnlyAccess``
# adds the listings that make an inventory rather than an audit.
MANAGED_POLICY_ARNS: tuple[str, ...] = (
    "arn:aws:iam::aws:policy/SecurityAudit",
    "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess",
)

# Read actions the managed policies do not cover, or that CloudGuard depends on
# closely enough to state rather than inherit.
#
# Every entry is a read. There is no ``s3:GetObject``, no ``kms:Decrypt``, no
# ``secretsmanager:GetSecretValue`` and no ``ssm:GetParameter`` -- CloudGuard can
# tell a customer their bucket is public without being able to read one byte out
# of it, and that claim is checkable from this tuple.
INLINE_READ_ACTIONS: tuple[str, ...] = (
    # Where anything can be read at all. UNVERIFIED.
    "ec2:DescribeRegions",
    # The organization, read once per scan from the management account. Absent
    # from SecurityAudit, and the whole of account discovery. UNVERIFIED.
    "organizations:ListAccounts",
    "organizations:DescribeOrganization",
    # IAM's credential report: when each password and key was last used, whether
    # MFA is on, whether the root user still holds keys. ``GenerateCredentialReport``
    # is a write in IAM's own vocabulary and reads as one in a policy, which is
    # why it is called out here rather than left inside a managed policy: it
    # creates nothing and changes no configuration -- it asks IAM to compile a
    # report about state that already exists. Without it the report is never
    # produced and every credential-age check reports UNKNOWN. UNVERIFIED.
    "iam:GenerateCredentialReport",
    "iam:GetCredentialReport",
    "iam:GetAccountSummary",
    "iam:GetAccountPasswordPolicy",
    # Bucket-level settings. SecurityAudit carries most of these; stated because
    # a missing one costs a specific check rather than a category. UNVERIFIED.
    "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketPolicyStatus",
    "s3:GetEncryptionConfiguration",
    "s3:GetBucketLocation",
    # Whether new volumes are encrypted without anyone asking. UNVERIFIED.
    "ec2:GetEbsEncryptionByDefault",
    # What the customer's own security services have already concluded.
    # UNVERIFIED.
    "guardduty:ListDetectors",
    "guardduty:GetDetector",
)

# Which action each client call needs. The link between the code and the policy,
# and what the forward guard checks: add a call without adding it here and the
# test fails, rather than a customer discovering it as an AccessDenied buried in
# one collection category.
#
# Keys are ``service:operation`` as the collector calls them, so the mapping can
# be checked against the plan rather than agreeing with it by hand.
CLIENT_ACTIONS: dict[str, tuple[str, ...]] = {
    "ec2:describe_regions": ("ec2:DescribeRegions",),
    "organizations:list_accounts": ("organizations:ListAccounts",),
    "iam:list_users": ("iam:ListUsers",),
    "iam:list_roles": ("iam:ListRoles",),
    "iam:list_policies": ("iam:ListPolicies",),
    "iam:get_credential_report": (
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
    ),
    "iam:get_account_password_policy": ("iam:GetAccountPasswordPolicy",),
    "iam:get_account_summary": ("iam:GetAccountSummary",),
    "s3:list_buckets": ("s3:ListAllMyBuckets",),
    "s3:get_public_access_block": ("s3:GetBucketPublicAccessBlock",),
    "s3:get_bucket_encryption": ("s3:GetEncryptionConfiguration",),
    "s3:get_bucket_policy_status": ("s3:GetBucketPolicyStatus",),
    "ec2:get_ebs_encryption_by_default": ("ec2:GetEbsEncryptionByDefault",),
    "ec2:describe_security_groups": ("ec2:DescribeSecurityGroups",),
    "ec2:describe_vpcs": ("ec2:DescribeVpcs",),
    "ec2:describe_subnets": ("ec2:DescribeSubnets",),
    "ec2:describe_network_interfaces": ("ec2:DescribeNetworkInterfaces",),
    "ec2:describe_addresses": ("ec2:DescribeAddresses",),
    "ec2:describe_instances": ("ec2:DescribeInstances",),
    "rds:describe_db_instances": ("rds:DescribeDBInstances",),
    "kms:list_keys": ("kms:ListKeys",),
    "kms:describe_key": ("kms:DescribeKey",),
    "cloudtrail:describe_trails": ("cloudtrail:DescribeTrails",),
    "config:describe_configuration_recorders": (
        "config:DescribeConfigurationRecorders",
    ),
    "guardduty:list_detectors": ("guardduty:ListDetectors",),
    "guardduty:get_detector": ("guardduty:GetDetector",),
}

# Actions the managed policies supply, listed so the two-way test can tell
# "covered by AWS" from "nobody grants this". Not a claim that these strings are
# spelled correctly in the managed policy -- AWS owns that -- only that
# CloudGuard is not the one granting them.
MANAGED_ACTIONS: frozenset[str] = frozenset(
    {
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListPolicies",
        "s3:ListAllMyBuckets",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeAddresses",
        "ec2:DescribeInstances",
        "rds:DescribeDBInstances",
        "kms:ListKeys",
        "kms:DescribeKey",
        "cloudtrail:DescribeTrails",
        "config:DescribeConfigurationRecorders",
    }
)

# Which categories each version of the policy can serve. One entry per version,
# so a connection running an older stack can be told which checks it is losing
# rather than only that it is behind.
POLICY_HISTORY: dict[str, tuple[str, ...]] = {
    POLICY_VERSION: INLINE_READ_ACTIONS,
}


def policy_is_current(version: str) -> bool:
    return version == POLICY_VERSION


def actions_missing_from(version: str) -> tuple[str, ...]:
    """What the current policy grants that an older one did not."""
    granted = set(POLICY_HISTORY.get(version, ()))
    return tuple(a for a in INLINE_READ_ACTIONS if a not in granted)


def categories_behind(version: str) -> frozenset[EvidenceCategory]:
    """Collection categories an older policy cannot fully serve.

    Derived from the actions it is missing rather than listed, so a new action
    lands in the right category by the fact of being added.
    """
    from app.connectors.aws.plan import categories_for_actions

    return categories_for_actions(actions_missing_from(version))


def action_matches(granted: str, wanted: str) -> bool:
    """Whether one granted action string covers a wanted one.

    IAM wildcards are glob-shaped -- ``s3:Get*`` and the whole-account ``*`` --
    and a policy is read by three callers now, so the interpretation lives here
    rather than in whichever one asked first.
    """
    return fnmatch(wanted.lower(), granted.lower())


def actions_granted_by(statements: Iterable[Mapping[str, Any]]) -> set[str]:
    """Every action of ours that a set of policy statements allows.

    Read from what the policy grants rather than from its name, because the name
    is not evidence: a customer who attached ``ReadOnlyAccess`` instead of
    deploying the stack has the access, and a check that looked for the stack's
    role name would report them as unconfigured.
    """
    wanted = set(INLINE_READ_ACTIONS) | MANAGED_ACTIONS
    granted: set[str] = set()
    for statement in statements:
        if str(statement.get("Effect", "Allow")) != "Allow":
            continue
        actions = statement.get("Action") or []
        if isinstance(actions, str):
            actions = [actions]
        for pattern in actions:
            granted |= {a for a in wanted if action_matches(str(pattern), a)}
    return granted


def version_of_granted(granted: Collection[str]) -> str | None:
    """The newest policy version a set of granted actions fully covers.

    ``None`` when it covers none of them, which is the honest answer for a role
    holding something unrelated: absent is not the same as old.
    """
    covered = [
        version
        for version, actions in POLICY_HISTORY.items()
        if all(action in granted for action in actions)
    ]
    if not covered:
        return None
    return max(covered, key=lambda v: list(POLICY_HISTORY).index(v))


@dataclass(frozen=True)
class TemplateContext:
    """What a stack has to be filled in with before a customer deploys it."""

    principal_arn: str
    external_id: str


def inline_policy(context: TemplateContext) -> dict[str, Any]:
    """The one hand-written policy document, as a dict.

    Separate from the template so a test can assert what it grants without
    parsing YAML, and so the same document can be shown to a customer who wants
    to read it before deploying anything.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CloudGuardReadOnly",
                "Effect": "Allow",
                "Action": sorted(INLINE_READ_ACTIONS),
                # Read actions are not resource-scoped here, and deliberately:
                # a CSPM that could only see the resources somebody remembered
                # to list would report a clean posture over the ones they
                # forgot. What bounds this is that every action is a read.
                "Resource": "*",
            }
        ],
    }


def trust_policy(context: TemplateContext) -> dict[str, Any]:
    """Who may assume the scanner role, and under what condition.

    The ``sts:ExternalId`` condition is the whole security property and is not
    optional. Without it, anybody who learns CloudGuard's account id can create
    a role trusting CloudGuard and have it scan an environment on their behalf.
    ``test_aws_iam`` asserts this condition is present, and that assertion is
    not negotiable.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": context.principal_arn},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": context.external_id}},
            }
        ],
    }


def cloudformation_template(context: TemplateContext) -> str:
    """The stack a customer deploys, as JSON.

    JSON rather than YAML for the same reason the ARM template is JSON: it is
    what the console consumes, and it is what a test can parse without a
    dependency.
    """
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": (
            f"CloudGuard read-only security scanner role ({POLICY_VERSION}). "
            "Grants read access to configuration only -- no writes, and nothing "
            "that can read the contents of a bucket, a database or a secret."
        ),
        "Resources": {
            "CloudGuardScannerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": ROLE_NAME,
                    "Description": (
                        "Assumed by CloudGuard to read this account's security "
                        "configuration."
                    ),
                    "AssumeRolePolicyDocument": trust_policy(context),
                    "ManagedPolicyArns": list(MANAGED_POLICY_ARNS),
                    "Policies": [
                        {
                            "PolicyName": f"CloudGuardScannerInline-{POLICY_VERSION}",
                            "PolicyDocument": inline_policy(context),
                        }
                    ],
                    "Tags": [
                        {"Key": "Application", "Value": "CloudGuard"},
                        {"Key": "PolicyVersion", "Value": POLICY_VERSION},
                    ],
                },
            }
        },
        "Outputs": {
            "RoleArn": {
                "Description": (
                    "Paste this into CloudGuard if it does not appear on its own."
                ),
                "Value": {"Fn::GetAtt": ["CloudGuardScannerRole", "Arn"]},
            },
            "ExternalId": {
                "Description": "The external id this role requires.",
                "Value": context.external_id,
            },
        },
    }
    return json.dumps(template, indent=2)


def launch_stack_url(template_url: str, region: str = "us-east-1") -> str:
    """The console link that opens CloudFormation with the template loaded.

    The AWS analogue of Deploy to Azure. The region only decides which console
    the customer lands in -- an IAM role is global, so the stack creates the
    same role wherever it is run.
    """
    from urllib.parse import quote

    return (
        f"https://{region}.console.aws.amazon.com/cloudformation/home"
        f"?region={region}#/stacks/create/review"
        f"?templateURL={quote(template_url, safe='')}"
        f"&stackName={STACK_NAME}"
    )
