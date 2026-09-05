"""The AWS rule set, and the pipeline it sits at the end of.

Every test here is a fixture snapshot in and a verdict out: no network, no
database, no clock. That is what makes a rule replayable against a capture
nobody can re-take, and it is why the connector stores the provider's own JSON.

Two things get more attention than the individual verdicts. **Nothing may PASS
over evidence that did not arrive** -- an AWS rule losing its listing has to
return UNKNOWN, and the regional fan-out gives it a new way to lose one. And
**no rule may judge another cloud's resources**: an S3 bucket and an Azure
storage account are both ``STORAGE_ACCOUNT``, so type alone would let an Azure
rule raise a finding carrying ``az storage account update`` as the fix for a
bucket.
"""

from datetime import UTC, datetime
from typing import Any

import pytest

from app.connectors.aws.normalizer import AwsNormalizer
from app.connectors.base import RawSnapshot
from app.core.enums import Provider, RuleState
from app.rules.aws.compute.exposure import AwsInstanceMetadataRule
from app.rules.aws.database.exposure import (
    AwsDatabaseEncryptionRule,
    AwsPublicDatabaseRule,
)
from app.rules.aws.identity.credentials import (
    AwsAccessAnalyzerRule,
    AwsAdministratorPolicyRule,
    AwsExpiredCertificateRule,
    AwsPasswordPolicyRule,
    AwsRootAccessKeyRule,
    AwsRootMfaRule,
    AwsStaleAccessKeyRule,
    AwsSupportRoleRule,
    AwsUserWithoutMfaRule,
)
from app.rules.aws.logging.trails import (
    AwsCloudTrailCoverageRule,
    AwsConfigRecorderRule,
    AwsEbsDefaultEncryptionRule,
    AwsFlowLogRule,
    AwsRootUsageMonitoringRule,
    AwsTrailBucketLoggingRule,
    AwsTrailEncryptionRule,
    AwsTrailValidationRule,
    AwsUnauthorizedApiMonitoringRule,
    _MonitoredEventRule,
)
from app.rules.aws.network.exposure import (
    AwsDefaultSecurityGroupRule,
    AwsOpenNetworkAclRule,
    AwsPublicRdpRule,
    AwsPublicSshRule,
)
from app.rules.aws.posture.coverage import AwsGuardDutyRule, AwsSecurityHubRule
from app.rules.aws.secrets.keys import AwsKeyRotationRule
from app.rules.aws.storage.public_access import (
    AwsBucketEncryptionRule,
    AwsBucketTransportRule,
    AwsPublicBucketRule,
)
from app.rules.base import RuleContext
from app.rules.engine import RuleEngine
from app.rules.registry import RULE_REGISTRY

COLLECTED_AT = datetime(2026, 6, 1, tzinfo=UTC)


def capture(gaps: dict[str, str] | None = None, **data: Any) -> RawSnapshot:
    return RawSnapshot(
        provider=Provider.AWS,
        tenant_id="o-example",
        subscription_id="111122223333",
        collected_at=COLLECTED_AT,
        data=dict(data),
        gaps=dict(gaps or {}),
    )


def context_from(gaps: dict[str, str] | None = None, **data: Any) -> RuleContext:
    """A rule context built the way a scan builds one: through the normalizer.

    Deliberately not hand-assembled. A test that constructed ``CloudResource``
    objects itself would pass while the normalizer produced something else
    entirely, which is the drift these fixtures exist to catch.
    """
    state = AwsNormalizer().normalize(capture(gaps, **data))
    relationships: dict[tuple[str, str], list[str]] = {}
    for source, kind, target in state.relationships:
        relationships.setdefault((source, kind.value), []).append(target)
    return RuleContext(
        resources=state.resources,
        relationships=relationships,
        controls=state.controls,
        collection_errors=state.collection_errors,
    )


def verdict(rule, context: RuleContext, name: str | None = None) -> RuleState:
    """Run one rule the way the engine does, and return the verdict."""
    if not rule.applies_to:
        result = rule.evaluate(None, context)
        return (result if not isinstance(result, list) else result[0]).state
    target = next(
        r for r in context.resources if rule.matches(r) and (name is None or r.name == name)
    )
    result = rule.evaluate(target, context)
    return (result if not isinstance(result, list) else result[0]).state


def bucket(name: str = "logs", **settings: Any) -> dict[str, Any]:
    return {
        "s3_buckets": [{"Name": name, "Region": "eu-west-1"}],
        **settings,
    }


# --------------------------------------------------------------- the buckets
def test_a_bucket_with_a_public_policy_fails() -> None:
    context = context_from(
        **bucket(
            s3_public_access_block=[{"Bucket": "logs", "Configuration": None}],
            s3_bucket_policy_status=[
                {"Bucket": "logs", "Configuration": {"PolicyStatus": {"IsPublic": True}}}
            ],
        )
    )
    assert verdict(AwsPublicBucketRule(), context) is RuleState.FAIL


def test_a_fully_blocked_bucket_passes() -> None:
    context = context_from(
        **bucket(
            s3_public_access_block=[
                {
                    "Bucket": "logs",
                    "Configuration": {
                        "PublicAccessBlockConfiguration": {
                            "BlockPublicAcls": True,
                            "IgnorePublicAcls": True,
                            "BlockPublicPolicy": True,
                            "RestrictPublicBuckets": True,
                        }
                    },
                }
            ],
            s3_bucket_policy_status=[
                {"Bucket": "logs", "Configuration": {"PolicyStatus": {"IsPublic": False}}}
            ],
        )
    )
    assert verdict(AwsPublicBucketRule(), context) is RuleState.PASS


def test_three_of_four_flags_is_not_blocked() -> None:
    """Each flag closes a different route in.

    A bucket with three of them is still reachable by the fourth, and a rule
    that accepted "mostly blocked" would report a clean bucket that is not.
    """
    context = context_from(
        **bucket(
            s3_public_access_block=[
                {
                    "Bucket": "logs",
                    "Configuration": {
                        "PublicAccessBlockConfiguration": {
                            "BlockPublicAcls": True,
                            "IgnorePublicAcls": True,
                            "BlockPublicPolicy": True,
                            "RestrictPublicBuckets": False,
                        }
                    },
                }
            ]
        )
    )
    assert verdict(AwsPublicBucketRule(), context) is RuleState.FAIL


def test_a_bucket_nobody_could_ask_about_is_unknown() -> None:
    """The four-state algebra, at the point where it matters most.

    PASS here would be CloudGuard reporting a bucket as closed on the strength
    of never having looked.
    """
    assert verdict(AwsPublicBucketRule(), context_from(**bucket())) is RuleState.UNKNOWN


def test_a_failed_listing_degrades_the_rule_that_read_it() -> None:
    context = context_from(
        gaps={"s3_public_access_block": "AccessDenied"},
        **bucket(s3_public_access_block=[]),
    )
    assert verdict(AwsPublicBucketRule(), context) is RuleState.UNKNOWN


def test_a_sibling_listing_failing_costs_nothing() -> None:
    """A bucket whose *encryption* read failed has had its access block read
    perfectly well, and degrading the public-access rule over it would be a gap
    CloudGuard invented rather than one it found."""
    context = context_from(
        gaps={"s3_encryption": "AccessDenied"},
        **bucket(
            s3_public_access_block=[{"Bucket": "logs", "Configuration": None}],
        ),
    )
    assert verdict(AwsPublicBucketRule(), context) is RuleState.FAIL


def test_a_bucket_with_no_default_encryption_fails() -> None:
    context = context_from(
        **bucket(s3_encryption=[{"Bucket": "logs", "Configuration": None}])
    )
    assert verdict(AwsBucketEncryptionRule(), context) is RuleState.FAIL


def test_a_bucket_with_default_encryption_passes() -> None:
    context = context_from(
        **bucket(
            s3_encryption=[
                {
                    "Bucket": "logs",
                    "Configuration": {
                        "ServerSideEncryptionConfiguration": {
                            "Rules": [
                                {
                                    "ApplyServerSideEncryptionByDefault": {
                                        "SSEAlgorithm": "aws:kms"
                                    }
                                }
                            ]
                        }
                    },
                }
            ]
        )
    )
    assert verdict(AwsBucketEncryptionRule(), context) is RuleState.PASS


# --------------------------------------------------------- the security groups
def group(region: str = "eu-west-1", **permission: Any) -> dict[str, Any]:
    return {
        "security_groups": [
            {
                "region": region,
                "items": [
                    {"GroupId": "sg-1", "GroupName": "web", "IpPermissions": [permission]}
                ],
            }
        ]
    }


def test_ssh_open_to_the_world_fails() -> None:
    context = context_from(
        **group(FromPort=22, ToPort=22, IpRanges=[{"CidrIp": "0.0.0.0/0"}])
    )
    assert verdict(AwsPublicSshRule(), context) is RuleState.FAIL


def test_ssh_open_to_the_world_over_ipv6_fails_too() -> None:
    """A group open to every IPv6 host on earth is open."""
    context = context_from(
        **group(FromPort=22, ToPort=22, Ipv6Ranges=[{"CidrIpv6": "::/0"}])
    )
    assert verdict(AwsPublicSshRule(), context) is RuleState.FAIL


def test_a_wide_port_range_covering_ssh_fails() -> None:
    context = context_from(
        **group(FromPort=1, ToPort=1024, IpRanges=[{"CidrIp": "0.0.0.0/0"}])
    )
    assert verdict(AwsPublicSshRule(), context) is RuleState.FAIL


def test_all_protocols_open_covers_every_rule() -> None:
    """``-1`` returns no port range, which is broader than any range, not
    narrower."""
    context = context_from(
        **group(IpProtocol="-1", IpRanges=[{"CidrIp": "0.0.0.0/0"}])
    )
    assert verdict(AwsPublicSshRule(), context) is RuleState.FAIL
    assert verdict(AwsPublicRdpRule(), context) is RuleState.FAIL


def test_ssh_open_to_one_range_passes() -> None:
    context = context_from(
        **group(FromPort=22, ToPort=22, IpRanges=[{"CidrIp": "203.0.113.0/24"}])
    )
    assert verdict(AwsPublicSshRule(), context) is RuleState.PASS


def test_an_open_group_in_front_of_nothing_scores_lower() -> None:
    """Still a misconfiguration and still worth fixing, but it exposes no host
    today -- and the score should say so rather than treating a forgotten
    template as an open door."""
    rule = AwsPublicSshRule()
    context = context_from(
        **group(FromPort=22, ToPort=22, IpRanges=[{"CidrIp": "0.0.0.0/0"}])
    )
    target = next(r for r in context.resources if rule.matches(r))
    result = rule.evaluate(target, context)

    assert result.state is RuleState.FAIL
    assert rule.effective_exploitability(result) < rule.exploitability


# ------------------------------------------------------------------ databases
def rds(**fields: Any) -> dict[str, Any]:
    return {
        "rds_instances": [
            {
                "region": "eu-west-1",
                "items": [
                    {
                        "DBInstanceIdentifier": "orders",
                        "DBInstanceArn": "arn:aws:rds:eu-west-1:1:db:orders",
                        "Engine": "postgres",
                        **fields,
                    }
                ],
            }
        ]
    }


def test_a_public_database_fails() -> None:
    context = context_from(**rds(PubliclyAccessible=True))
    assert verdict(AwsPublicDatabaseRule(), context) is RuleState.FAIL


def test_a_private_database_passes() -> None:
    context = context_from(**rds(PubliclyAccessible=False))
    assert verdict(AwsPublicDatabaseRule(), context) is RuleState.PASS


def test_an_unencrypted_database_fails() -> None:
    context = context_from(**rds(StorageEncrypted=False))
    assert verdict(AwsDatabaseEncryptionRule(), context) is RuleState.FAIL


def test_a_database_setting_missing_from_the_capture_is_unknown() -> None:
    context = context_from(**rds())
    assert verdict(AwsDatabaseEncryptionRule(), context) is RuleState.UNKNOWN


# ------------------------------------------------------------------- identity
def user(**report: Any) -> dict[str, Any]:
    return {
        "iam_users": [{"UserName": "ana", "Arn": "arn:aws:iam::1:user/ana"}],
        "iam_credential_report": [{"arn": "arn:aws:iam::1:user/ana", **report}],
    }


def test_a_console_user_without_mfa_fails() -> None:
    context = context_from(**user(password_enabled="true", mfa_active="false"))
    assert verdict(AwsUserWithoutMfaRule(), context) is RuleState.FAIL


def test_a_console_user_with_mfa_passes() -> None:
    context = context_from(**user(password_enabled="true", mfa_active="true"))
    assert verdict(AwsUserWithoutMfaRule(), context) is RuleState.PASS


def test_an_api_only_user_is_not_judged_on_mfa() -> None:
    """MFA protects a sign-in. A user with no console password has none, and a
    finding against them is one nobody can act on."""
    context = context_from(**user(password_enabled="false", mfa_active="false"))
    assert verdict(AwsUserWithoutMfaRule(), context) is RuleState.NOT_APPLICABLE


def test_a_long_unused_key_fails_and_the_age_comes_from_the_capture() -> None:
    """Measured against ``collected_at``, never the clock.

    A rule that read the clock would answer differently on replay, which would
    make "verified fixed" a statement about when somebody asked.
    """
    context = context_from(
        **user(
            password_enabled="false",
            access_key_1_active="true",
            access_key_1_last_used_date="2025-01-01T00:00:00+00:00",
        )
    )
    assert verdict(AwsStaleAccessKeyRule(), context) is RuleState.FAIL


def test_a_recently_used_key_passes() -> None:
    context = context_from(
        **user(
            password_enabled="false",
            access_key_1_active="true",
            access_key_1_last_used_date="2026-05-20T00:00:00+00:00",
        )
    )
    assert verdict(AwsStaleAccessKeyRule(), context) is RuleState.PASS


def test_a_key_never_used_falls_back_to_when_it_was_made() -> None:
    """IAM writes ``N/A`` for a key nobody has used, which is the strongest case
    for removing it rather than a missing value."""
    context = context_from(
        **user(
            password_enabled="false",
            access_key_1_active="true",
            access_key_1_last_used_date="N/A",
            access_key_1_last_rotated="2024-01-01T00:00:00+00:00",
        )
    )
    assert verdict(AwsStaleAccessKeyRule(), context) is RuleState.FAIL


def test_a_user_with_no_active_key_has_no_stale_one() -> None:
    context = context_from(**user(password_enabled="true", access_key_1_active="false"))
    assert verdict(AwsStaleAccessKeyRule(), context) is RuleState.NOT_APPLICABLE


def test_a_root_access_key_fails() -> None:
    context = context_from(account_summary=[{"AccountAccessKeysPresent": 1}])
    assert verdict(AwsRootAccessKeyRule(), context) is RuleState.FAIL


def test_no_root_access_key_passes() -> None:
    context = context_from(account_summary=[{"AccountAccessKeysPresent": 0}])
    assert verdict(AwsRootAccessKeyRule(), context) is RuleState.PASS


def test_a_missing_summary_is_unknown_rather_than_clean() -> None:
    assert verdict(AwsRootAccessKeyRule(), context_from()) is RuleState.UNKNOWN


def test_a_short_password_policy_fails() -> None:
    context = context_from(account_password_policy=[{"MinimumPasswordLength": 8}])
    assert verdict(AwsPasswordPolicyRule(), context) is RuleState.FAIL


def test_no_password_policy_at_all_fails() -> None:
    """Absent is the finding, not a missing reading: the collector records "no
    policy" as an empty list rather than as a failed call."""
    context = context_from(account_password_policy=[])
    assert verdict(AwsPasswordPolicyRule(), context) is RuleState.FAIL


def test_a_long_password_policy_passes() -> None:
    context = context_from(account_password_policy=[{"MinimumPasswordLength": 16}])
    assert verdict(AwsPasswordPolicyRule(), context) is RuleState.PASS


# -------------------------------------------------------------------- regions
def test_a_region_with_no_trail_fails() -> None:
    context = context_from(
        enabled_regions=["eu-west-1", "us-east-1"],
        cloudtrail_trails=[
            {"region": "eu-west-1", "items": [{"Name": "org-trail"}]},
            {"region": "us-east-1", "items": []},
        ],
    )
    assert verdict(AwsCloudTrailCoverageRule(), context) is RuleState.FAIL


def test_every_region_covered_passes() -> None:
    context = context_from(
        enabled_regions=["eu-west-1", "us-east-1"],
        cloudtrail_trails=[
            {"region": "eu-west-1", "items": [{"Name": "org-trail"}]},
            {"region": "us-east-1", "items": [{"Name": "org-trail"}]},
        ],
    )
    assert verdict(AwsCloudTrailCoverageRule(), context) is RuleState.PASS


def test_not_knowing_the_regions_is_unknown_rather_than_covered() -> None:
    """The failure this whole arrangement guards against.

    Without the region list there is no denominator, and "no uncovered regions"
    would be true of an account nobody enumerated.
    """
    context = context_from(cloudtrail_trails=[])
    assert verdict(AwsCloudTrailCoverageRule(), context) is RuleState.UNKNOWN


def test_a_region_without_default_ebs_encryption_fails() -> None:
    context = context_from(
        enabled_regions=["eu-west-1", "us-east-1"],
        ebs_encryption_default=[
            {"region": "eu-west-1", "items": [{"EbsEncryptionByDefault": True}]},
            {"region": "us-east-1", "items": [{"EbsEncryptionByDefault": False}]},
        ],
    )
    assert verdict(AwsEbsDefaultEncryptionRule(), context) is RuleState.FAIL


# ------------------------------------------------------ the pipeline, end to end
def test_a_public_bucket_produces_an_aws_fix_and_never_an_azure_one() -> None:
    """The whole point of provider-scoped rules, checked at the end of the pipe.

    ``STORAGE_ACCOUNT`` is neutral, so without the provider check on
    ``matches`` an Azure rule would judge this bucket and the finding would
    carry ``az storage account update`` as the fix for something in AWS.
    """
    context = context_from(
        **bucket(
            s3_bucket_policy_status=[
                {"Bucket": "logs", "Configuration": {"PolicyStatus": {"IsPublic": True}}}
            ]
        )
    )
    report = RuleEngine().evaluate(context)

    assert report.failures, "a public bucket should raise something"
    raised = [f.rule.rule_id for f in report.failures]
    assert all(rule_id.startswith("AWS-") for rule_id in raised), raised
    assert "AWS-STO-001" in raised

    fix = next(
        r.remediation for r in RULE_REGISTRY if r.rule_id == "AWS-STO-001"
    )
    assert "aws s3api" in fix
    assert "az storage" not in fix


def test_no_azure_rule_reaches_an_aws_resource() -> None:
    """Checked over the whole registry rather than one rule.

    An aggregate rule never goes through ``matches`` at all -- it reads
    ``context.resources`` directly -- which is why the engine narrows the
    context per provider as well.
    """
    context = context_from(
        **bucket(),
        rds_instances=[
            {
                "region": "eu-west-1",
                "items": [{"DBInstanceIdentifier": "orders", "Engine": "postgres"}],
            }
        ],
    )
    azure_rules = [r for r in RULE_REGISTRY if r.provider is Provider.AZURE]

    for rule in azure_rules:
        assert not any(rule.matches(r) for r in context.resources), rule.rule_id


# =========================================================== the second wave
#
# Everything below judges evidence the first thirteen rules collected and never
# read. The pattern is the same -- fixture in, verdict out -- and the cases that
# earn their place are the ones where a naive check gets the wrong answer.


# ------------------------------------------------------------------- compute
def test_an_instance_accepting_imdsv1_fails() -> None:
    """The metadata service is the most productive single step in a cloud
    intrusion: an SSRF that reaches it reads the role's credentials."""
    context = context_from(
        ec2_instances=[
            {
                "region": "eu-west-1",
                "items": [
                    {"InstanceId": "i-1", "MetadataOptions": {"HttpTokens": "optional"}}
                ],
            }
        ]
    )
    assert verdict(AwsInstanceMetadataRule(), context) is RuleState.FAIL


def test_an_instance_requiring_a_token_passes() -> None:
    context = context_from(
        ec2_instances=[
            {
                "region": "eu-west-1",
                "items": [
                    {"InstanceId": "i-1", "MetadataOptions": {"HttpTokens": "required"}}
                ],
            }
        ]
    )
    assert verdict(AwsInstanceMetadataRule(), context) is RuleState.PASS


# -------------------------------------------------------------------- secrets
def test_a_customer_key_that_does_not_rotate_fails() -> None:
    context = context_from(
        kms_keys=[
            {
                "region": "eu-west-1",
                "items": [
                    {
                        "Arn": "arn:aws:kms:eu-west-1:1:key/abc",
                        "KeyManager": "CUSTOMER",
                        "KeyRotationEnabled": False,
                    }
                ],
            }
        ]
    )
    assert verdict(AwsKeyRotationRule(), context) is RuleState.FAIL


def test_an_aws_managed_key_is_not_the_customer_s_to_rotate() -> None:
    """AWS rotates it on its own schedule and the setting cannot be changed.

    A finding here would be one nobody can act on, which is worse than no
    finding: it costs attention and cannot be closed.
    """
    context = context_from(
        kms_keys=[
            {
                "region": "eu-west-1",
                "items": [
                    {"Arn": "arn:aws:kms:eu-west-1:1:key/aws", "KeyManager": "AWS"}
                ],
            }
        ]
    )
    assert verdict(AwsKeyRotationRule(), context) is RuleState.NOT_APPLICABLE


# ------------------------------------------------------------- authorization
def test_a_policy_granting_everything_fails_in_either_spelling() -> None:
    """IAM accepts ``*`` and ``*:*`` and treats them the same.

    A check that knew one spelling would pass the other, which is the shape of
    bug that only shows up in the account that used it.
    """
    for action in ("*", "*:*", ["*"]):
        context = context_from(
            iam_policies=[{"Arn": "arn:aws:iam::1:policy/admin"}],
            iam_policy_documents=[
                {
                    "Arn": "arn:aws:iam::1:policy/admin",
                    "PolicyName": "admin",
                    "Document": {
                        "Statement": [
                            {"Effect": "Allow", "Action": action, "Resource": "*"}
                        ]
                    },
                }
            ],
        )
        assert verdict(AwsAdministratorPolicyRule(), context) is RuleState.FAIL, action


def test_a_scoped_policy_passes() -> None:
    context = context_from(
        iam_policies=[{"Arn": "arn:aws:iam::1:policy/reader"}],
        iam_policy_documents=[
            {
                "Arn": "arn:aws:iam::1:policy/reader",
                "PolicyName": "reader",
                "Document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObject"],
                            "Resource": "arn:aws:s3:::reports/*",
                        }
                    ]
                },
            }
        ],
    )
    assert verdict(AwsAdministratorPolicyRule(), context) is RuleState.PASS


def test_a_wildcard_grant_behind_a_condition_is_not_unbounded() -> None:
    """A condition is a real limit, and a statement carrying one is not the
    blanket grant this rule is about."""
    context = context_from(
        iam_policies=[{"Arn": "arn:aws:iam::1:policy/conditional"}],
        iam_policy_documents=[
            {
                "Arn": "arn:aws:iam::1:policy/conditional",
                "PolicyName": "conditional",
                "Document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*",
                            "Condition": {
                                "StringEquals": {"aws:PrincipalOrgID": "o-example"}
                            },
                        }
                    ]
                },
            }
        ],
    )
    assert verdict(AwsAdministratorPolicyRule(), context) is RuleState.PASS


def test_a_deny_of_everything_is_not_a_grant_of_everything() -> None:
    context = context_from(
        iam_policies=[{"Arn": "arn:aws:iam::1:policy/deny"}],
        iam_policy_documents=[
            {
                "Arn": "arn:aws:iam::1:policy/deny",
                "PolicyName": "deny",
                "Document": {
                    "Statement": [
                        {"Effect": "Deny", "Action": "*", "Resource": "*"}
                    ]
                },
            }
        ],
    )
    assert verdict(AwsAdministratorPolicyRule(), context) is RuleState.PASS


# -------------------------------------------------------------------- storage
def test_a_bucket_with_no_policy_accepts_plaintext_http() -> None:
    """AWS answers ``NoSuchBucketPolicy``, which the collector records as a null
    configuration -- and that *is* the finding, not a missing reading."""
    context = context_from(
        **bucket(s3_bucket_policy=[{"Bucket": "logs", "Document": None}])
    )
    assert verdict(AwsBucketTransportRule(), context) is RuleState.FAIL


def test_a_policy_denying_insecure_transport_passes() -> None:
    context = context_from(
        **bucket(
            s3_bucket_policy=[
                {
                    "Bucket": "logs",
                    "Document": {
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Principal": "*",
                                "Action": "s3:*",
                                "Resource": "arn:aws:s3:::logs/*",
                                "Condition": {
                                    "Bool": {"aws:SecureTransport": "false"}
                                },
                            }
                        ]
                    },
                }
            ]
        )
    )
    assert verdict(AwsBucketTransportRule(), context) is RuleState.PASS


# -------------------------------------------------------------------- network
def acl(**entry: Any) -> dict[str, Any]:
    return {
        "network_acls": [
            {
                "region": "eu-west-1",
                "items": [{"NetworkAclId": "acl-1", "Entries": [entry]}],
            }
        ]
    }


def test_an_acl_admitting_ssh_from_anywhere_fails() -> None:
    context = context_from(
        **acl(
            Egress=False,
            RuleAction="allow",
            CidrBlock="0.0.0.0/0",
            PortRange={"From": 22, "To": 22},
        )
    )
    assert verdict(AwsOpenNetworkAclRule(), context) is RuleState.FAIL


def test_a_deny_entry_is_not_a_finding_whatever_it_covers() -> None:
    """The default ACL ends with a deny-all on 0.0.0.0/0. Read without this,
    every well-written ACL in AWS reports as open."""
    context = context_from(
        **acl(Egress=False, RuleAction="deny", CidrBlock="0.0.0.0/0")
    )
    assert verdict(AwsOpenNetworkAclRule(), context) is RuleState.PASS


def test_an_egress_entry_is_not_ingress() -> None:
    context = context_from(
        **acl(
            Egress=True,
            RuleAction="allow",
            CidrBlock="0.0.0.0/0",
            PortRange={"From": 22, "To": 22},
        )
    )
    assert verdict(AwsOpenNetworkAclRule(), context) is RuleState.PASS


def test_a_default_security_group_carrying_rules_fails() -> None:
    context = context_from(
        security_groups=[
            {
                "region": "eu-west-1",
                "items": [
                    {
                        "GroupId": "sg-default",
                        "GroupName": "default",
                        "IpPermissions": [
                            {"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": "sg-default"}]}
                        ],
                    }
                ],
            }
        ]
    )
    assert verdict(AwsDefaultSecurityGroupRule(), context, "default") is RuleState.FAIL


def test_a_named_group_is_judged_on_what_it_admits_instead() -> None:
    context = context_from(
        security_groups=[
            {
                "region": "eu-west-1",
                "items": [{"GroupId": "sg-1", "GroupName": "web", "IpPermissions": []}],
            }
        ]
    )
    assert (
        verdict(AwsDefaultSecurityGroupRule(), context, "web")
        is RuleState.NOT_APPLICABLE
    )


# -------------------------------------------------------------------- logging
def trail(**fields: Any) -> dict[str, Any]:
    """One multi-region trail, as every region it covers reports it."""
    entry = {
        "Name": "org-trail",
        "TrailARN": "arn:aws:cloudtrail:eu-west-1:1:trail/org-trail",
        "IsMultiRegionTrail": True,
        "S3BucketName": "audit-logs",
        **fields,
    }
    return {
        "enabled_regions": ["eu-west-1", "us-east-1"],
        "cloudtrail_trails": [
            {"region": "eu-west-1", "items": [entry]},
            {"region": "us-east-1", "items": [entry]},
        ],
    }


def test_one_multi_region_trail_is_counted_once() -> None:
    """Every region it covers reports it, which is what makes coverage
    answerable -- and what would make every other trail rule count it twice."""
    context = context_from(**trail(LogFileValidationEnabled=False))
    result = AwsTrailValidationRule().evaluate(None, context)

    assert result.state is RuleState.FAIL
    assert result.evidence["without_validation"] == [
        "arn:aws:cloudtrail:eu-west-1:1:trail/org-trail"
    ]


def test_a_validated_trail_passes() -> None:
    context = context_from(**trail(LogFileValidationEnabled=True))
    assert verdict(AwsTrailValidationRule(), context) is RuleState.PASS


def test_no_trail_at_all_is_the_coverage_rule_s_finding_not_this_one() -> None:
    """Raising both would charge the security score twice for one problem."""
    context = context_from(enabled_regions=["eu-west-1"], cloudtrail_trails=[])
    assert verdict(AwsTrailValidationRule(), context) is RuleState.NOT_APPLICABLE


def test_a_trail_without_a_kms_key_fails() -> None:
    context = context_from(**trail(LogFileValidationEnabled=True))
    assert verdict(AwsTrailEncryptionRule(), context) is RuleState.FAIL


def test_a_trail_bucket_in_another_account_is_unknown_rather_than_failed() -> None:
    """A dedicated log archive account is the shape AWS recommends, and
    CloudGuard cannot read a bucket it was not granted. "We could not look" is
    not "logging is off"."""
    context = context_from(**trail(), s3_buckets=[])
    assert verdict(AwsTrailBucketLoggingRule(), context) is RuleState.UNKNOWN


def test_a_trail_bucket_without_access_logging_fails() -> None:
    context = context_from(
        **trail(),
        s3_buckets=[{"Name": "audit-logs", "Region": "eu-west-1"}],
        s3_bucket_logging=[{"Bucket": "audit-logs", "Configuration": {}}],
    )
    assert verdict(AwsTrailBucketLoggingRule(), context) is RuleState.FAIL


def test_a_stopped_config_recorder_records_nothing() -> None:
    """Creating a recorder is two commands and starting it is the third. A check
    that only looked for existence would pass the account that stopped there."""
    context = context_from(
        enabled_regions=["eu-west-1"],
        config_recorders=[
            {
                "region": "eu-west-1",
                "items": [{"name": "default", "Status": {"recording": False}}],
            }
        ],
    )
    assert verdict(AwsConfigRecorderRule(), context) is RuleState.FAIL


def test_a_recording_config_recorder_passes() -> None:
    context = context_from(
        enabled_regions=["eu-west-1"],
        config_recorders=[
            {
                "region": "eu-west-1",
                "items": [{"name": "default", "Status": {"recording": True}}],
            }
        ],
    )
    assert verdict(AwsConfigRecorderRule(), context) is RuleState.PASS


def test_a_vpc_with_no_flow_log_fails() -> None:
    context = context_from(
        vpcs=[{"region": "eu-west-1", "items": [{"VpcId": "vpc-1"}]}],
        vpc_flow_logs=[{"region": "eu-west-1", "items": []}],
    )
    assert verdict(AwsFlowLogRule(), context) is RuleState.FAIL


def test_an_inactive_flow_log_covers_nothing() -> None:
    """A flow log in a non-ACTIVE state records nothing, so reading its
    existence rather than its status would pass an account logging nothing."""
    context = context_from(
        vpcs=[{"region": "eu-west-1", "items": [{"VpcId": "vpc-1"}]}],
        vpc_flow_logs=[
            {
                "region": "eu-west-1",
                "items": [{"ResourceId": "vpc-1", "FlowLogStatus": "INACTIVE"}],
            }
        ],
    )
    assert verdict(AwsFlowLogRule(), context) is RuleState.FAIL


def test_an_active_flow_log_covers_its_vpc() -> None:
    context = context_from(
        vpcs=[{"region": "eu-west-1", "items": [{"VpcId": "vpc-1"}]}],
        vpc_flow_logs=[
            {
                "region": "eu-west-1",
                "items": [{"ResourceId": "vpc-1", "FlowLogStatus": "ACTIVE"}],
            }
        ],
    )
    assert verdict(AwsFlowLogRule(), context) is RuleState.PASS


# ------------------------------------------------------------------- identity
def test_a_root_user_without_mfa_fails() -> None:
    context = context_from(account_summary=[{"AccountMFAEnabled": 0}])
    assert verdict(AwsRootMfaRule(), context) is RuleState.FAIL


def test_a_root_user_with_mfa_passes() -> None:
    context = context_from(account_summary=[{"AccountMFAEnabled": 1}])
    assert verdict(AwsRootMfaRule(), context) is RuleState.PASS


def test_an_expired_certificate_is_judged_against_the_capture() -> None:
    """Not against the clock. A replayed scan has to reach the verdict the
    original one did, or "verified fixed" becomes a statement about when
    somebody asked."""
    context = context_from(
        iam_server_certificates=[
            {"ServerCertificateName": "old", "Expiration": "2025-01-01T00:00:00+00:00"}
        ]
    )
    assert verdict(AwsExpiredCertificateRule(), context) is RuleState.FAIL


def test_a_current_certificate_passes() -> None:
    context = context_from(
        iam_server_certificates=[
            {"ServerCertificateName": "new", "Expiration": "2027-01-01T00:00:00+00:00"}
        ]
    )
    assert verdict(AwsExpiredCertificateRule(), context) is RuleState.PASS


def test_a_region_without_an_access_analyzer_fails() -> None:
    context = context_from(
        enabled_regions=["eu-west-1", "us-east-1"],
        access_analyzers=[
            {"region": "eu-west-1", "items": [{"name": "account", "status": "ACTIVE"}]},
            {"region": "us-east-1", "items": []},
        ],
    )
    assert verdict(AwsAccessAnalyzerRule(), context) is RuleState.FAIL


# -------------------------------------------------------------------- posture
def test_a_region_without_guardduty_fails() -> None:
    context = context_from(
        enabled_regions=["eu-west-1", "us-east-1"],
        guardduty_detectors=[
            {"region": "eu-west-1", "items": [{"Status": "ENABLED"}]},
            {"region": "us-east-1", "items": []},
        ],
    )
    assert verdict(AwsGuardDutyRule(), context) is RuleState.FAIL


def test_not_knowing_the_regions_never_passes_a_coverage_rule() -> None:
    """"No uncovered regions" is trivially true of an account nobody
    enumerated, and would be the most misleading PASS this product could
    produce."""
    for rule in (AwsGuardDutyRule(), AwsSecurityHubRule(), AwsAccessAnalyzerRule()):
        assert verdict(rule, context_from()) is RuleState.UNKNOWN, rule.rule_id


# ------------------------------------------------------ somebody is told
#
# CIS section 4 asks a question no single setting answers: is anybody alerted
# when this happens? The chain is trail -> CloudWatch log group -> metric filter
# -> metric -> alarm -> action, and every hop can be missing on its own. The
# tests below are one per hop, because a check that only looked for the filter
# would pass the most common half-done case there is.

GROUP = "/aws/cloudtrail/bk-trail"
GROUP_ARN = f"arn:aws:logs:eu-west-1:1:log-group:{GROUP}:*"

UNAUTHORIZED_PATTERN = (
    '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }'
)
ROOT_PATTERN = (
    '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS '
    '&& $.eventType != "AwsServiceEvent" }'
)


def monitoring(
    *,
    log_group: str | None = GROUP_ARN,
    pattern: str | None = UNAUTHORIZED_PATTERN,
    alarm: bool = True,
    alarm_actions: bool = True,
    metric: str = "UnauthorizedAPICalls",
    alarm_region: str = "eu-west-1",
) -> dict[str, Any]:
    """One account's monitoring chain, with any hop removable."""
    trail: dict[str, Any] = {
        "Name": "bk-trail",
        "TrailARN": "arn:aws:cloudtrail:eu-west-1:1:trail/bk-trail",
        "IsMultiRegionTrail": True,
        "S3BucketName": "audit-logs",
        "LogFileValidationEnabled": True,
    }
    if log_group:
        trail["CloudWatchLogsLogGroupArn"] = log_group

    filters = (
        [
            {
                "filterName": "f1",
                "logGroupName": GROUP,
                "filterPattern": pattern,
                "metricTransformations": [
                    {"metricName": metric, "metricNamespace": "CISBenchmark"}
                ],
            }
        ]
        if pattern
        else []
    )
    alarms = (
        [
            {
                "AlarmName": "a1",
                "MetricName": metric,
                "Namespace": "CISBenchmark",
                "AlarmActions": (
                    ["arn:aws:sns:eu-west-1:1:alerts"] if alarm_actions else []
                ),
            }
        ]
        if alarm
        else []
    )
    return {
        "enabled_regions": ["eu-west-1"],
        "cloudtrail_trails": [{"region": "eu-west-1", "items": [trail]}],
        "log_metric_filters": [{"region": "eu-west-1", "items": filters}],
        "cloudwatch_alarms": [{"region": alarm_region, "items": alarms}],
    }


def test_a_complete_chain_passes() -> None:
    context = context_from(**monitoring())
    assert verdict(AwsUnauthorizedApiMonitoringRule(), context) is RuleState.PASS


def test_a_trail_that_never_reaches_cloudwatch_cannot_be_alarmed_on() -> None:
    """The first hop, and the one most likely to be missing: a trail delivering
    only to S3 has no log group, so no metric filter can exist for it."""
    context = context_from(**monitoring(log_group=None))
    result = AwsUnauthorizedApiMonitoringRule().evaluate(None, context)

    assert result.state is RuleState.FAIL
    assert "CloudWatch log group" in result.message


def test_a_filter_that_does_not_name_the_event_is_not_this_filter() -> None:
    context = context_from(
        **monitoring(pattern='{ $.eventName = "ConsoleLogin" }')
    )
    assert verdict(AwsUnauthorizedApiMonitoringRule(), context) is RuleState.FAIL


def test_a_filter_with_no_alarm_on_its_metric_tells_nobody() -> None:
    """The most common half-done state. A check looking only for the filter
    would pass an account where the metric is published and watched by
    nothing."""
    context = context_from(**monitoring(alarm=False))
    result = AwsUnauthorizedApiMonitoringRule().evaluate(None, context)

    assert result.state is RuleState.FAIL
    assert "no alarm" in result.message


def test_an_alarm_with_no_action_changes_a_colour_and_nothing_else() -> None:
    context = context_from(**monitoring(alarm_actions=False))
    result = AwsUnauthorizedApiMonitoringRule().evaluate(None, context)

    assert result.state is RuleState.FAIL
    assert "notifies nobody" in result.message


def test_an_alarm_in_another_region_never_meets_the_metric() -> None:
    """An alarm can only watch a metric in its own region. A filter in eu-west-1
    and an alarm in us-east-1 are two things that never meet, and reading them
    as a pair would report a chain that does not exist."""
    context = context_from(**monitoring(alarm_region="us-east-1"))
    assert verdict(AwsUnauthorizedApiMonitoringRule(), context) is RuleState.FAIL


def test_a_filter_on_a_different_log_group_is_not_on_the_trail() -> None:
    payload = monitoring()
    payload["log_metric_filters"][0]["items"][0]["logGroupName"] = "/aws/lambda/other"
    assert (
        verdict(AwsUnauthorizedApiMonitoringRule(), context_from(**payload))
        is RuleState.FAIL
    )


def test_the_root_rule_wants_its_own_fields() -> None:
    """The two rules walk the same chain and are not the same check. A pattern
    matching refused calls says nothing about root."""
    unauthorized_only = monitoring()
    assert (
        verdict(AwsRootUsageMonitoringRule(), context_from(**unauthorized_only))
        is RuleState.FAIL
    )

    root = monitoring(pattern=ROOT_PATTERN, metric="RootAccountUsage")
    assert verdict(AwsRootUsageMonitoringRule(), context_from(**root)) is RuleState.PASS


def test_the_matched_pattern_is_shown_rather_than_trusted() -> None:
    """CloudGuard does not evaluate CloudWatch's filter-pattern language.

    The check is that the required fields are named, which is necessary and not
    sufficient — so the finding carries the pattern it matched, and a reader can
    judge it rather than take this rule's word for it.
    """
    context = context_from(**monitoring(alarm=False))
    result = AwsUnauthorizedApiMonitoringRule().evaluate(None, context)

    assert result.evidence["matching_filter_patterns"] == [UNAUTHORIZED_PATTERN]
    assert result.evidence["trail_log_groups"] == [GROUP]


def test_no_trail_is_the_coverage_rule_s_finding_not_these_two() -> None:
    """Raising all three would charge the security score three times for one
    problem written three ways."""
    context = context_from(enabled_regions=["eu-west-1"], cloudtrail_trails=[])
    for rule in (AwsUnauthorizedApiMonitoringRule(), AwsRootUsageMonitoringRule()):
        assert verdict(rule, context) is RuleState.NOT_APPLICABLE, rule.rule_id


def test_a_failed_filter_listing_degrades_rather_than_passes() -> None:
    context = context_from(
        gaps={"log_metric_filters": "AccessDenied"}, **monitoring()
    )
    assert verdict(AwsUnauthorizedApiMonitoringRule(), context) is RuleState.UNKNOWN


# ---------------------------------------------- the rest of CIS AWS section 4
# Fifteen controls of one shape, so the interesting question is not whether the
# walk works -- three hops of it are tested above -- but whether the fifteen are
# fifteen different questions. Both tests below are over the registry rather
# than a list written here, so a sixteenth rule is covered the day it is added.

SECTION_FOUR = [rule for rule in RULE_REGISTRY if isinstance(rule, _MonitoredEventRule)]


def declared_pattern(rule) -> str:
    """The filter pattern out of the command the rule tells a customer to run."""
    return rule.remediation_spec.cli[0].split("--filter-pattern '", 1)[1].split(
        "' --metric-transformations", 1
    )[0]


def declared_metric(rule) -> str:
    return rule.remediation_spec.cli[1].split("--alarm-name ", 1)[1].split(" ", 1)[0]


@pytest.mark.parametrize("rule", SECTION_FOUR, ids=lambda r: r.rule_id)
def test_the_filter_the_remediation_prints_satisfies_the_check(rule) -> None:
    """A customer who runs exactly what the finding told them to run passes.

    The same discipline ``test_remediation_spec.py`` applies to the rules that
    can state an expected value, applied to the ones that cannot: the pattern in
    the remediation and the ingredients in the check are one claim written
    twice, and this is what keeps them the same claim.
    """
    context = context_from(
        **monitoring(pattern=declared_pattern(rule), metric=declared_metric(rule))
    )
    assert verdict(rule, context) is RuleState.PASS


@pytest.mark.parametrize("rule", SECTION_FOUR, ids=lambda r: r.rule_id)
def test_no_rule_here_is_satisfied_by_another_one_s_filter(rule) -> None:
    """Thirteen rules sharing one evaluation is a saving right up until two of
    them accept the same filter -- at which point an account is told it watches
    an event nothing watches."""
    for other in SECTION_FOUR:
        if other.rule_id == rule.rule_id:
            continue
        context = context_from(
            **monitoring(pattern=declared_pattern(other), metric=declared_metric(other))
        )
        assert verdict(rule, context) is RuleState.FAIL, other.rule_id


# ---------------------------------------------------- who can call AWS
def test_an_account_where_nobody_holds_support_access_fails() -> None:
    """The moment this matters is the worst moment to discover it.

    An account under active abuse needs a case opened with AWS, and without the
    policy attached to somebody the only way in is root.
    """
    context = context_from(iam_support_access=[])
    assert verdict(AwsSupportRoleRule(), context) is RuleState.FAIL


def test_a_role_holding_support_access_passes() -> None:
    context = context_from(
        iam_support_access=[
            {"kind": "role", "RoleName": "incident-response", "RoleId": "AROA1"}
        ]
    )
    assert verdict(AwsSupportRoleRule(), context) is RuleState.PASS


def test_any_kind_of_principal_counts() -> None:
    """CIS asks whether anybody can manage a case, not what shape they are.
    ``ListEntitiesForPolicy`` answers with three differently-shaped lists and
    a check reading only one of them would fail an account that is fine."""
    for kind, field in (
        ("role", "RoleName"),
        ("user", "UserName"),
        ("group", "GroupName"),
    ):
        context = context_from(iam_support_access=[{"kind": kind, field: "support"}])
        assert verdict(AwsSupportRoleRule(), context) is RuleState.PASS, kind


def test_the_holders_are_named_in_the_evidence() -> None:
    """"Which role" is the first thing somebody asks, and the answer is one
    field away."""
    context = context_from(
        iam_support_access=[{"kind": "role", "RoleName": "incident-response"}]
    )
    result = AwsSupportRoleRule().evaluate(None, context)

    assert result.evidence["holders"] == [
        {"kind": "role", "name": "incident-response"}
    ]


def test_a_readiness_gap_scores_as_nothing_and_is_reported_anyway() -> None:
    """There is no attack here at all. The cost is paid during an incident
    rather than caused by one, so it contributes nothing to the risk score --
    and a product that only reported what scores would never mention it."""
    rule = AwsSupportRoleRule()
    result = rule.evaluate(None, context_from(iam_support_access=[]))

    assert result.state is RuleState.FAIL
    assert rule.effective_exploitability(result) == 0


def test_a_failed_support_listing_degrades_rather_than_fails() -> None:
    """"We could not ask" is not "nobody holds it" -- and this is a finding
    somebody would go and create a role over."""
    context = context_from(
        gaps={"iam_support_access": "AccessDenied"}, iam_support_access=[]
    )
    assert verdict(AwsSupportRoleRule(), context) is RuleState.UNKNOWN
