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

from app.connectors.aws.normalizer import AwsNormalizer
from app.connectors.base import RawSnapshot
from app.core.enums import Provider, RuleState
from app.rules.aws.database.exposure import (
    AwsDatabaseEncryptionRule,
    AwsPublicDatabaseRule,
)
from app.rules.aws.identity.credentials import (
    AwsPasswordPolicyRule,
    AwsRootAccessKeyRule,
    AwsStaleAccessKeyRule,
    AwsUserWithoutMfaRule,
)
from app.rules.aws.logging.trails import (
    AwsCloudTrailCoverageRule,
    AwsEbsDefaultEncryptionRule,
)
from app.rules.aws.network.exposure import AwsPublicRdpRule, AwsPublicSshRule
from app.rules.aws.storage.public_access import (
    AwsBucketEncryptionRule,
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
