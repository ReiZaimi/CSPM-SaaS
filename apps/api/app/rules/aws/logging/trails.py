"""Logging and account-wide defaults, judged per region.

Both rules here are aggregate and both read the same shape: a set of regions
where something is true, against the set of regions the account has enabled.
That comparison is the whole reason ``enabled_regions`` is carried as a control
-- "there is no trail in eu-west-1" means nothing without a list of the regions
that exist for this customer.
"""

from typing import ClassVar

from app.connectors.aws.evidence import AwsEvidence
from app.core.enums import Provider, RuleScope, Severity
from app.domain.resource import CloudResource
from app.remediation import RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule


class AwsCloudTrailCoverageRule(SecurityRule):
    rule_id = "AWS-LOG-001"
    name = "A region has no CloudTrail coverage"
    description = (
        "One or more enabled regions have no CloudTrail trail. API activity there is "
        "not recorded, so an action taken in that region leaves nothing behind."
    )
    category = "logging"
    provider = Provider.AWS
    severity = Severity.HIGH
    # Not exploitable on its own. It removes the record, which is what turns a
    # contained incident into an unanswerable one.
    exploitability = 1
    scope = RuleScope.AGGREGATE
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.CLOUDTRAIL_TRAILS,
        AwsEvidence.ENABLED_REGIONS,
    )
    estimated_effort_minutes = 30
    rationale = (
        "An attacker who finds an unlogged region will use it. Without a trail there "
        "is no record of what was created, read or deleted -- which is the difference "
        "between an incident with a scope and one without."
    )
    remediation = (
        "Create one multi-region trail. It covers every region including ones enabled "
        "later, which a per-region trail does not.\n\n"
        "AWS CLI:\n"
        "  aws cloudtrail create-trail --name org-trail --s3-bucket-name <bucket> \\\n"
        "    --is-multi-region-trail --enable-log-file-validation\n"
        "  aws cloudtrail start-logging --name org-trail\n\n"
        "In an organization, create it in the management account with "
        "--is-organization-trail so member accounts are covered without each one "
        "having to remember."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        # Aggregate, and genuinely unstatable as a value: the expectation is a
        # comparison between two sets of regions, which no expected state on an
        # asset can express.
        expected=(),
        cli=(
            "aws cloudtrail create-trail --name org-trail "
            "--s3-bucket-name <bucket> --is-multi-region-trail "
            "--enable-log-file-validation",
            "aws cloudtrail start-logging --name org-trail",
        ),
        notes=(
            "One multi-region trail rather than one per region: it covers "
            "regions enabled later, which a per-region trail does not."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["3.1"],
        "ISO_27001": ["A.8.15", "A.8.16"],
        "NIST_CSF": ["DE.CM-1", "PR.PT-1"],
        "NIST_800_53": ["AU-2", "AU-6"],
        "SOC2": ["CC7.2"],
        "PCI_DSS_4": ["10.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Trail coverage unavailable: {failure}")

        enabled = set(context.controls.get("enabled_regions") or [])
        if not enabled:
            return RuleResult.unknown("The account's enabled regions are not known")

        # A multi-region trail is returned by every region it covers, which is
        # exactly what makes this answerable: the question is not "does a trail
        # exist" but "is this region covered by one", and only the region's own
        # listing can say.
        covered = set(context.controls.get("cloudtrail_regions") or [])
        uncovered = sorted(enabled - covered)
        evidence = {
            "enabled_regions": sorted(enabled),
            "regions_with_a_trail": sorted(covered),
            "regions_without": uncovered,
        }

        if not uncovered:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"{len(uncovered)} of {len(enabled)} enabled regions have no "
                f"CloudTrail trail: {', '.join(uncovered)}"
            ),
        )


class AwsEbsDefaultEncryptionRule(SecurityRule):
    rule_id = "AWS-CMP-001"
    name = "EBS volumes are not encrypted by default"
    description = (
        "One or more regions do not encrypt new EBS volumes by default, so whether a "
        "volume is encrypted depends on whoever created it."
    )
    category = "compute"
    provider = Provider.AWS
    severity = Severity.MEDIUM
    exploitability = 1
    scope = RuleScope.AGGREGATE
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.EBS_ENCRYPTION_DEFAULT,
        AwsEvidence.ENABLED_REGIONS,
    )
    estimated_effort_minutes = 10
    rationale = (
        "The setting is one call per region and applies to every volume created "
        "afterwards. Without it, encryption is a thing each engineer has to remember, "
        "and snapshots inherit whatever the volume was."
    )
    remediation = (
        "Turn the default on in every enabled region.\n\n"
        "AWS CLI:\n"
        "  aws ec2 enable-ebs-encryption-by-default --region <region>\n\n"
        "It applies to new volumes only. Existing unencrypted volumes have to be "
        "snapshotted, copied with a key, and restored."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        # Aggregate: one setting per region, so the expectation is a statement
        # about a set of regions rather than about an asset.
        expected=(),
        cli=("aws ec2 enable-ebs-encryption-by-default --region <region>",),
        notes=(
            "Applies to new volumes only. Existing unencrypted volumes have to "
            "be snapshotted, copied with a key, and restored."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["2.2.1"],
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
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Encryption defaults unavailable: {failure}")

        by_region = context.controls.get("ebs_encryption_by_default") or {}
        if not by_region:
            return RuleResult.unknown("EBS encryption defaults missing from snapshot")

        off = sorted(region for region, on in by_region.items() if not on)
        evidence = {
            "regions_checked": sorted(by_region),
            "regions_without_default": off,
        }
        if not off:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"{len(off)} region(s) do not encrypt new EBS volumes by default: "
                f"{', '.join(off)}"
            ),
        )
