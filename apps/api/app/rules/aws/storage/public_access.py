"""S3 rules. The classic cloud data-leak shape, in AWS's vocabulary.

Provider-specific rules over a neutral resource type, which is the decision
``MULTI_CLOUD.md`` §6 records and the reason it was not aesthetic: ``remediation``
is snapshot-copied onto every finding, and ``aws s3api put-public-access-block``
is not a variant of ``az storage account update``. A shared rule would branch on
provider to produce the fix, which is the same mistake as branching on framework
name.
"""

from typing import ClassVar

from app.connectors.aws.evidence import AwsEvidence
from app.core.enums import Provider, ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import ExpectedState, RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule


class AwsPublicBucketRule(SecurityRule):
    rule_id = "AWS-STO-001"
    name = "S3 bucket allows public access"
    description = (
        "A bucket does not block public access, or carries a policy that grants a "
        "wildcard principal. Anyone who learns or guesses the bucket name can read its "
        "contents without credentials."
    )
    category = "storage"
    provider = Provider.AWS
    severity = Severity.HIGH
    exploitability = 5
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.STORAGE_ACCOUNT]
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.S3_BUCKETS,
        AwsEvidence.S3_PUBLIC_ACCESS_BLOCK,
        AwsEvidence.S3_BUCKET_POLICY_STATUS,
    )
    estimated_effort_minutes = 15
    rationale = (
        "Publicly readable object storage is the single most common source of large "
        "cloud data breaches. It requires no exploit — the data is served to whoever asks."
    )
    remediation = (
        "Turn on the bucket's public access block, and remove any policy statement "
        "granting a wildcard principal.\n\n"
        "AWS CLI:\n"
        "  aws s3api put-public-access-block --bucket <bucket> \\\n"
        "    --public-access-block-configuration BlockPublicAcls=true,"
        "IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\n\n"
        "Then check the policy:\n"
        "  aws s3api get-bucket-policy --bucket <bucket>\n\n"
        "Set the same four flags at the account level to stop it recurring:\n"
        "  aws s3control put-public-access-block --account-id <account> \\\n"
        "    --public-access-block-configuration BlockPublicAcls=true,"
        "IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\n\n"
        "Where content genuinely must be public, serve it through CloudFront with an "
        "origin access control rather than leaving the bucket itself open."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="public_access_blocked",
                equals=True,
                describes="All four bucket public access block settings are on",
                terraform_attribute="aws_s3_bucket_public_access_block",
            ),
            ExpectedState(
                field="policy_is_public",
                equals=False,
                describes="The bucket policy grants no wildcard principal",
                terraform_attribute="aws_s3_bucket_policy.policy",
            ),
        ),
        cli=(
            "aws s3api put-public-access-block --bucket <bucket> "
            "--public-access-block-configuration BlockPublicAcls=true,"
            "IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        ),
        # No ``policy_resource_type``: Azure Policy cannot enforce an S3 setting,
        # and ``enforceable`` correctly answers False. The AWS equivalent is an
        # AWS Config rule or an SCP, and neither has been written or verified
        # from here -- an unverified one would deploy and check nothing, which
        # is the failure ``rbac.py`` records for an unverified string.
        notes=(
            "Preventive enforcement on AWS would be an AWS Config rule or an "
            "SCP. Neither is generated yet."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["2.1.4"],
        "ISO_27001": ["A.5.10", "A.8.3"],
        "NIST_CSF": ["PR.AC-3", "PR.DS-5"],
        "GDPR": ["5(1)(f)", "25", "32(1)(b)"],
        "NIST_800_53": ["AC-3", "SC-7"],
        "SOC2": ["CC6.1", "CC6.6"],
        "PCI_DSS_4": ["1.3.1", "7.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Bucket configuration unavailable: {failure}")

        blocked = resource.get("public_access_blocked")
        policy_is_public = resource.get("policy_is_public")

        # Both absent means the settings were never in this capture, which is
        # not the same as the bucket being closed.
        if blocked is None and policy_is_public is None:
            return RuleResult.unknown("Bucket access settings missing from snapshot")

        problems: list[str] = []
        if policy_is_public:
            problems.append("The bucket policy grants access to a wildcard principal")
        if blocked is False:
            problems.append(
                "The bucket does not block public access on all four settings"
            )

        evidence = {
            "public_access_blocked": blocked,
            "policy_is_public": bool(policy_is_public),
            "raw_public_access_block": resource.get("PublicAccessBlock"),
            "region": resource.region,
        }

        if not problems:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence={**evidence, "problems": problems},
            # Two failures wear one rule id and only one of them hands data to a
            # stranger today. A policy granting ``*`` serves the objects now; an
            # incomplete block means a future ACL or policy *could*, which is an
            # attacker who first has to get something else granted.
            exploitability=None if policy_is_public else 3,
            message=f"{resource.name} is publicly accessible: {'; '.join(problems)}",
        )


class AwsBucketEncryptionRule(SecurityRule):
    rule_id = "AWS-STO-002"
    name = "S3 bucket has no default encryption"
    description = (
        "A bucket has no default server-side encryption, so an object written without "
        "encryption headers is stored in the clear."
    )
    category = "storage"
    provider = Provider.AWS
    severity = Severity.MEDIUM
    # Not reachable on its own. It matters when something else goes wrong --
    # a stolen snapshot, a mis-scoped role, physical media -- which is what a
    # defence-in-depth control is for.
    exploitability = 1
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.STORAGE_ACCOUNT]
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.S3_BUCKETS,
        AwsEvidence.S3_ENCRYPTION,
    )
    estimated_effort_minutes = 10
    rationale = (
        "Default encryption costs nothing and applies to every future object. Without "
        "it, whether an object is encrypted depends on whichever client happened to "
        "write it."
    )
    remediation = (
        "Set default encryption on the bucket.\n\n"
        "AWS CLI:\n"
        "  aws s3api put-bucket-encryption --bucket <bucket> \\\n"
        "    --server-side-encryption-configuration '{\"Rules\":[{"
        '"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"},'
        "\"BucketKeyEnabled\":true}]}'\n\n"
        "SSE-S3 (`AES256`) is the zero-effort option; a customer-managed KMS key adds "
        "an access-control boundary of its own and is worth it for anything sensitive."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="default_encryption_enabled",
                equals=True,
                describes="The bucket applies server-side encryption by default",
                terraform_attribute=(
                    "aws_s3_bucket_server_side_encryption_configuration"
                ),
            ),
        ),
        cli=(
            "aws s3api put-bucket-encryption --bucket <bucket> "
            "--server-side-encryption-configuration "
            '\'{"Rules":[{"ApplyServerSideEncryptionByDefault":'
            '{"SSEAlgorithm":"aws:kms"},"BucketKeyEnabled":true}]}\'',
        ),
        notes=(
            "Preventive enforcement on AWS would be an AWS Config rule or an "
            "SCP. Neither is generated yet."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["2.1.1"],
        "ISO_27001": ["A.8.24"],
        "NIST_CSF": ["PR.DS-1"],
        "GDPR": ["32(1)(a)"],
        "NIST_800_53": ["SC-28"],
        "SOC2": ["CC6.1"],
        "PCI_DSS_4": ["3.5.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Bucket encryption unavailable: {failure}")

        enabled = resource.get("default_encryption_enabled")
        if enabled is None:
            return RuleResult.unknown("Bucket encryption setting missing from snapshot")

        evidence = {
            "default_encryption_enabled": enabled,
            "algorithm": resource.get("default_encryption"),
            "region": resource.region,
        }

        if enabled:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} has no default encryption",
        )
