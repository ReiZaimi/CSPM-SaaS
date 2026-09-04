"""AWS payloads -> cloud-neutral resources.

A pure function of a stored capture, so every test here is a fixture in and a
list of ``CloudResource`` out: no network, no database, no clock. That is the
whole testing strategy, and it is what makes a capture from a real account
replayable years later.

The two things worth pinning are the ones with no Azure equivalent: regional
blocks are unwrapped with the region travelling onto each resource, and the
per-bucket settings are joined back onto the bucket they belong to -- with
"could not be read" staying distinguishable from "not configured".
"""

from typing import Any

from app.connectors.aws.normalizer import AwsNormalizer
from app.connectors.base import RawSnapshot
from app.core.enums import Level, Provider, RelationshipType, ResourceType


def snapshot(**data: Any) -> RawSnapshot:
    return RawSnapshot(
        provider=Provider.AWS,
        tenant_id="o-example",
        subscription_id="111122223333",
        data=dict(data),
    )


def normalize(**data: Any):
    return AwsNormalizer().normalize(snapshot(**data))


def by_type(state, resource_type: ResourceType):
    return [r for r in state.resources if r.resource_type is resource_type]


# ------------------------------------------------------------ regional blocks
def test_a_resource_carries_the_region_it_was_read_in() -> None:
    """Not recovered from an identifier afterwards.

    Several AWS identifiers carry no region at all, so a normalizer forced to
    parse one back out would produce nothing for exactly the resources whose
    region matters.
    """
    state = normalize(
        security_groups=[
            {"region": "eu-west-1", "items": [{"GroupId": "sg-1", "GroupName": "web"}]},
            {"region": "us-east-1", "items": [{"GroupId": "sg-2", "GroupName": "db"}]},
        ]
    )

    groups = {r.name: r.region for r in by_type(state, ResourceType.NETWORK_SECURITY_GROUP)}
    assert groups == {"web": "eu-west-1", "db": "us-east-1"}


def test_the_same_key_read_in_two_regions_produces_two_resources() -> None:
    """A block per region rather than one list overwritten sixteen times."""
    state = normalize(
        ec2_instances=[
            {"region": "eu-west-1", "items": [{"InstanceId": "i-1"}]},
            {"region": "us-east-1", "items": [{"InstanceId": "i-2"}]},
        ]
    )

    assert {r.name for r in by_type(state, ResourceType.VIRTUAL_MACHINE)} == {
        "i-1",
        "i-2",
    }


def test_a_global_listing_needs_no_block_and_gets_no_region() -> None:
    state = normalize(
        iam_users=[{"UserName": "ana", "Arn": "arn:aws:iam::1:user/ana"}]
    )

    user = by_type(state, ResourceType.USER)[0]
    assert user.name == "ana"
    assert user.region is None


# ---------------------------------------------------------------- the buckets
def test_a_bucket_carries_the_three_settings_read_separately() -> None:
    """Joined here rather than in each rule.

    All three are keyed by bucket name, and a rule joining them itself would
    join them slightly differently each time.
    """
    state = normalize(
        s3_buckets=[{"Name": "logs", "Region": "eu-west-1"}],
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
        s3_encryption=[
            {
                "Bucket": "logs",
                "Configuration": {"ServerSideEncryptionConfiguration": {}},
            }
        ],
        s3_bucket_policy_status=[
            {"Bucket": "logs", "Configuration": {"PolicyStatus": {"IsPublic": False}}}
        ],
    )

    bucket = by_type(state, ResourceType.STORAGE_ACCOUNT)[0]
    assert bucket.provider_resource_id == "arn:aws:s3:::logs"
    assert bucket.region == "eu-west-1"
    assert bucket.get("PublicAccessBlock.PublicAccessBlockConfiguration.BlockPublicAcls")
    assert bucket.public_exposure is Level.LOW


def test_a_bucket_nobody_could_ask_about_is_unknown_not_private() -> None:
    """"We did not look" and "it is private" are different sentences.

    The risk engine scores UNKNOWN cautiously rather than optimistically, which
    only works if the normalizer refuses to invent the optimistic answer.
    """
    state = normalize(s3_buckets=[{"Name": "logs", "Region": "eu-west-1"}])

    assert by_type(state, ResourceType.STORAGE_ACCOUNT)[0].public_exposure is Level.UNKNOWN


def test_a_bucket_with_a_public_policy_is_exposed_whatever_the_block_says() -> None:
    """Two independent ways in, and a block on one does not cover the other."""
    state = normalize(
        s3_buckets=[{"Name": "open", "Region": "us-east-1"}],
        s3_bucket_policy_status=[
            {"Bucket": "open", "Configuration": {"PolicyStatus": {"IsPublic": True}}}
        ],
    )

    assert by_type(state, ResourceType.STORAGE_ACCOUNT)[0].public_exposure is Level.HIGH


def test_a_setting_that_is_simply_not_set_is_not_a_missing_reading() -> None:
    """AWS answers "no configuration" with an error code, and that *is* the
    finding -- so the row is present with a null configuration rather than
    absent."""
    state = normalize(
        s3_buckets=[{"Name": "plain", "Region": "us-east-1"}],
        s3_encryption=[{"Bucket": "plain", "Configuration": None}],
    )

    bucket = by_type(state, ResourceType.STORAGE_ACCOUNT)[0]
    assert "Encryption" in bucket.metadata
    assert bucket.metadata["Encryption"] is None


# ------------------------------------------------------------------ exposure
def test_a_group_open_to_the_world_on_ssh_is_high_exposure() -> None:
    state = normalize(
        security_groups=[
            {
                "region": "eu-west-1",
                "items": [
                    {
                        "GroupId": "sg-1",
                        "IpPermissions": [
                            {
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            }
                        ],
                    }
                ],
            }
        ]
    )

    assert by_type(state, ResourceType.NETWORK_SECURITY_GROUP)[0].public_exposure is Level.HIGH


def test_a_group_open_to_one_office_is_not_exposed() -> None:
    state = normalize(
        security_groups=[
            {
                "region": "eu-west-1",
                "items": [
                    {
                        "GroupId": "sg-1",
                        "IpPermissions": [
                            {
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpRanges": [{"CidrIp": "203.0.113.0/24"}],
                            }
                        ],
                    }
                ],
            }
        ]
    )

    assert by_type(state, ResourceType.NETWORK_SECURITY_GROUP)[0].public_exposure is Level.LOW


def test_all_protocols_open_to_the_world_covers_every_port_there_is() -> None:
    """``-1`` protocol comes back with no port range at all, which is not a
    narrower rule than one naming 22."""
    state = normalize(
        security_groups=[
            {
                "region": "eu-west-1",
                "items": [
                    {
                        "GroupId": "sg-1",
                        "IpPermissions": [
                            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                        ],
                    }
                ],
            }
        ]
    )

    assert by_type(state, ResourceType.NETWORK_SECURITY_GROUP)[0].public_exposure is Level.HIGH


# ------------------------------------------------------------------ databases
def test_an_rds_engine_decides_which_neutral_type_it_becomes() -> None:
    state = normalize(
        rds_instances=[
            {
                "region": "eu-west-1",
                "items": [
                    {
                        "DBInstanceIdentifier": "orders",
                        "DBInstanceArn": "arn:aws:rds:eu-west-1:1:db:orders",
                        "Engine": "postgres",
                        "PubliclyAccessible": True,
                    },
                    {
                        "DBInstanceIdentifier": "billing",
                        "DBInstanceArn": "arn:aws:rds:eu-west-1:1:db:billing",
                        "Engine": "mysql",
                    },
                ],
            }
        ]
    )

    assert [r.name for r in by_type(state, ResourceType.POSTGRESQL_SERVER)] == ["orders"]
    assert [r.name for r in by_type(state, ResourceType.SQL_SERVER)] == ["billing"]
    assert by_type(state, ResourceType.POSTGRESQL_SERVER)[0].public_exposure is Level.HIGH


# --------------------------------------------------------------- identity
def test_a_user_carries_the_credential_report_row_it_matches() -> None:
    """The facts a rule needs are in the report, not in ``ListUsers``."""
    state = normalize(
        iam_users=[{"UserName": "ana", "Arn": "arn:aws:iam::1:user/ana"}],
        iam_credential_report=[
            {"arn": "arn:aws:iam::1:user/ana", "mfa_active": "false"}
        ],
    )

    assert by_type(state, ResourceType.USER)[0].get("CredentialReport.mfa_active") == "false"


def test_a_user_the_report_did_not_cover_keeps_the_absence_visible() -> None:
    state = normalize(iam_users=[{"UserName": "ana", "Arn": "arn:aws:iam::1:user/ana"}])

    assert "CredentialReport" not in by_type(state, ResourceType.USER)[0].metadata


def test_a_role_is_a_workload_identity_rather_than_a_person() -> None:
    """The remediation differs entirely: a person gets MFA, a role gets a
    narrower policy."""
    state = normalize(iam_roles=[{"RoleName": "deploy", "Arn": "arn:aws:iam::1:role/deploy"}])

    assert by_type(state, ResourceType.SERVICE_PRINCIPAL)[0].name == "deploy"
    assert by_type(state, ResourceType.USER) == []


# ---------------------------------------------------------- the graph's edges
def test_an_instance_runs_as_its_profile_and_is_protected_by_its_groups() -> None:
    """``HAS_IDENTITY`` is the capability edge -- the first hop from a
    compromised workload to everything that workload may do."""
    state = normalize(
        ec2_instances=[
            {
                "region": "eu-west-1",
                "items": [
                    {
                        "InstanceId": "i-1",
                        "SecurityGroups": [{"GroupId": "sg-1"}],
                        "IamInstanceProfile": {
                            "Arn": "arn:aws:iam::1:instance-profile/app"
                        },
                    }
                ],
            }
        ]
    )

    assert ("sg-1", RelationshipType.PROTECTS, "i-1") in state.relationships
    assert (
        "i-1",
        RelationshipType.HAS_IDENTITY,
        "arn:aws:iam::1:instance-profile/app",
    ) in state.relationships


def test_a_subnet_is_contained_by_its_vpc() -> None:
    state = normalize(
        subnets=[
            {
                "region": "eu-west-1",
                "items": [{"SubnetId": "subnet-1", "VpcId": "vpc-1"}],
            }
        ]
    )

    assert ("vpc-1", RelationshipType.CONTAINS, "subnet-1") in state.relationships


# ------------------------------------------------------------------ controls
def test_account_defences_are_controls_rather_than_assets() -> None:
    """Nobody secures a password policy. It lowers what a weak credential is
    worth, which is a different thing from being a thing that can be weak."""
    state = normalize(
        account_password_policy=[{"MinimumPasswordLength": 14}],
        guardduty_detectors=[
            {"region": "eu-west-1", "items": [{"Status": "ENABLED"}]},
            {"region": "us-east-1", "items": [{"Status": "DISABLED"}]},
        ],
    )

    assert state.controls["password_policy"] == {"MinimumPasswordLength": 14}
    assert state.controls["guardduty_regions"] == ["eu-west-1"]
    assert by_type(state, ResourceType.UNKNOWN) == []


def test_the_account_itself_is_a_resource_findings_can_attach_to() -> None:
    """"The root user still has access keys" is about the account, not about
    anything in it."""
    state = normalize()

    account = by_type(state, ResourceType.SUBSCRIPTION)[0]
    assert account.name == "111122223333"
    assert account.provider is Provider.AWS


# ----------------------------------------------------------------- the gaps
def test_the_capture_s_gaps_reach_the_rule_context_unchanged() -> None:
    """One entry per evidence key, which is what a rule declares.

    The region is inside the reason rather than in the key, or a rule would be
    asked about evidence it has never heard of.
    """
    capture = snapshot(security_groups=[])
    capture.gaps["security_groups"] = "us-east-1: AccessDenied"

    state = AwsNormalizer().normalize(capture)

    assert state.collection_errors == {"security_groups": "us-east-1: AccessDenied"}
