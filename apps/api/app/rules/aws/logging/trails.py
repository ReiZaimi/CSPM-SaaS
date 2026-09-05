"""Logging and account-wide defaults, judged per region.

Both rules here are aggregate and both read the same shape: a set of regions
where something is true, against the set of regions the account has enabled.
That comparison is the whole reason ``enabled_regions`` is carried as a control
-- "there is no trail in eu-west-1" means nothing without a list of the regions
that exist for this customer.
"""

from typing import ClassVar

from app.connectors.aws.evidence import AwsEvidence
from app.core.enums import Provider, ResourceType, RuleScope, Severity
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


class AwsTrailValidationRule(SecurityRule):
    rule_id = "AWS-LOG-002"
    name = "A CloudTrail trail has no log file validation"
    description = (
        "A trail does not write digest files, so there is no way to prove "
        "afterwards that its logs were not altered or deleted."
    )
    category = "logging"
    provider = Provider.AWS
    severity = Severity.MEDIUM
    exploitability = 1
    scope = RuleScope.AGGREGATE
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.CLOUDTRAIL_TRAILS,
    )
    estimated_effort_minutes = 10
    rationale = (
        "The logs are the record of what happened. Without validation, an "
        "attacker with access to the log bucket can remove the evidence of their "
        "own activity and nothing detects the gap."
    )
    remediation = (
        "Turn validation on. It costs nothing and applies from the next log "
        "file:\n\n"
        "  aws cloudtrail update-trail --name <trail> --enable-log-file-validation"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        # Aggregate: a statement about the trails an account has rather than
        # about any asset in it.
        expected=(),
        cli=(
            "aws cloudtrail update-trail --name <trail> "
            "--enable-log-file-validation",
        ),
        notes=(
            "Validation applies from the next log file. It does not make "
            "existing files provable."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["3.2"],
        "ISO_27001": ["A.8.15"],
        "NIST_CSF": ["PR.PT-1"],
        "NIST_800_53": ["AU-9"],
        "SOC2": ["CC7.2"],
        "PCI_DSS_4": ["10.3.2"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Trail configuration unavailable: {failure}")

        trails = _unique_trails(context)
        if not trails:
            # No trail at all is AWS-LOG-001's finding, not this one. Raising it
            # twice would charge the security score for one problem written two
            # ways.
            return RuleResult.not_applicable("This account has no trail")

        unvalidated = sorted(
            name
            for name, trail in trails.items()
            if not trail.get("LogFileValidationEnabled")
        )
        evidence = {"trails": sorted(trails), "without_validation": unvalidated}
        if not unvalidated:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"{len(unvalidated)} trail(s) do not validate their log files: "
                f"{', '.join(unvalidated)}"
            ),
        )


class AwsTrailEncryptionRule(SecurityRule):
    rule_id = "AWS-LOG-005"
    name = "A CloudTrail trail is not encrypted with a KMS key"
    description = (
        "A trail writes its logs with S3's default encryption rather than a KMS "
        "key, so reading them needs only access to the bucket."
    )
    category = "logging"
    provider = Provider.AWS
    severity = Severity.MEDIUM
    exploitability = 1
    scope = RuleScope.AGGREGATE
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.CLOUDTRAIL_TRAILS,
    )
    estimated_effort_minutes = 20
    rationale = (
        "A KMS key puts a second, separately audited authorization in front of "
        "the logs: reading them then needs bucket access *and* a grant on the "
        "key, and every use of the key is itself recorded."
    )
    remediation = (
        "Point the trail at a KMS key:\n\n"
        "  aws cloudtrail update-trail --name <trail> --kms-key-id <key-arn>\n\n"
        "The key's policy has to allow CloudTrail to encrypt with it, and anyone "
        "who reads the logs needs decrypt on it — which is the point."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=("aws cloudtrail update-trail --name <trail> --kms-key-id <key-arn>",),
        notes=(
            "The key policy must allow CloudTrail to encrypt, or the trail stops "
            "delivering. Check it before switching, not after."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["3.5"],
        "ISO_27001": ["A.8.24"],
        "NIST_CSF": ["PR.DS-1"],
        "NIST_800_53": ["AU-9", "SC-28"],
        "SOC2": ["CC6.1"],
        "PCI_DSS_4": ["10.3.2"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Trail configuration unavailable: {failure}")

        trails = _unique_trails(context)
        if not trails:
            return RuleResult.not_applicable("This account has no trail")

        unencrypted = sorted(
            name for name, trail in trails.items() if not trail.get("KmsKeyId")
        )
        evidence = {"trails": sorted(trails), "without_kms": unencrypted}
        if not unencrypted:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"{len(unencrypted)} trail(s) are not encrypted with a KMS key: "
                f"{', '.join(unencrypted)}"
            ),
        )


class AwsTrailBucketLoggingRule(SecurityRule):
    rule_id = "AWS-LOG-004"
    name = "The CloudTrail bucket does not record who reads it"
    description = (
        "The bucket a trail writes to has no server access logging, so there is "
        "no record of who read or removed the audit log itself."
    )
    category = "logging"
    provider = Provider.AWS
    severity = Severity.MEDIUM
    exploitability = 1
    scope = RuleScope.AGGREGATE
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.CLOUDTRAIL_TRAILS,
        AwsEvidence.S3_BUCKET_LOGGING,
    )
    estimated_effort_minutes = 15
    rationale = (
        "CloudTrail records what happened in the account; nothing records what "
        "happened to CloudTrail. Access logging on that one bucket is what makes "
        "the audit trail auditable."
    )
    remediation = (
        "Turn on server access logging for the trail's bucket, writing to a "
        "different bucket:\n\n"
        "  aws s3api put-bucket-logging --bucket <trail-bucket> \\\n"
        "    --bucket-logging-status '{\"LoggingEnabled\":{"
        "\"TargetBucket\":\"<log-bucket>\",\"TargetPrefix\":\"trail-access/\"}}'\n\n"
        "A different bucket, deliberately: logging a bucket into itself makes "
        "each read produce a write that produces another read."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "aws s3api put-bucket-logging --bucket <trail-bucket> "
            '--bucket-logging-status \'{"LoggingEnabled":'
            '{"TargetBucket":"<log-bucket>","TargetPrefix":"trail-access/"}}\'',
        ),
        notes=(
            "Log to a different bucket. A bucket logging into itself makes each "
            "read produce a write that produces another read."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["3.4"],
        "ISO_27001": ["A.8.15"],
        "NIST_CSF": ["PR.PT-1"],
        "NIST_800_53": ["AU-9"],
        "SOC2": ["CC7.2"],
        "PCI_DSS_4": ["10.3.2"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Trail bucket state unavailable: {failure}")

        trails = _unique_trails(context)
        wanted = {
            str(trail.get("S3BucketName"))
            for trail in trails.values()
            if trail.get("S3BucketName")
        }
        if not wanted:
            return RuleResult.not_applicable("No trail names a bucket")

        # The trail's bucket is very often in a *different* account -- a
        # dedicated log archive is the shape AWS recommends -- and CloudGuard
        # cannot read a bucket it was not granted. Unknown rather than failed:
        # "we could not look" is not "logging is off".
        buckets = {
            r.name: r
            for r in context.get_resources_by_type(ResourceType.STORAGE_ACCOUNT)
        }
        missing = sorted(name for name in wanted if name not in buckets)
        if missing:
            return RuleResult.unknown(
                "The trail's bucket is not in this account's inventory: "
                + ", ".join(missing)
            )

        unlogged = sorted(
            name
            for name in wanted
            if buckets[name].get("access_logging_enabled") is False
        )
        unknown = sorted(
            name
            for name in wanted
            if buckets[name].get("access_logging_enabled") is None
        )
        if unknown:
            return RuleResult.unknown(
                "Access logging could not be read for: " + ", ".join(unknown)
            )

        evidence = {"trail_buckets": sorted(wanted), "without_logging": unlogged}
        if not unlogged:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=(
                "The trail's bucket does not record who reads it: "
                f"{', '.join(unlogged)}"
            ),
        )


class AwsConfigRecorderRule(SecurityRule):
    rule_id = "AWS-LOG-003"
    name = "AWS Config is not recording in every region"
    description = (
        "One or more enabled regions have no AWS Config recorder, or have one "
        "that is stopped. Configuration changes in those regions leave no "
        "history to look back at."
    )
    category = "logging"
    provider = Provider.AWS
    severity = Severity.MEDIUM
    exploitability = 1
    scope = RuleScope.AGGREGATE
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.CONFIG_RECORDERS,
        AwsEvidence.ENABLED_REGIONS,
    )
    estimated_effort_minutes = 30
    rationale = (
        "CloudTrail says what call was made; Config says what the resource "
        "looked like before and after. Without it, \"when did this become "
        "public?\" has no answer."
    )
    remediation = (
        "Create and start a recorder in each region:\n\n"
        "  aws configservice put-configuration-recorder \\\n"
        "    --configuration-recorder name=default,roleARN=<role> \\\n"
        "    --recording-group allSupported=true,includeGlobalResourceTypes=true\n"
        "  aws configservice put-delivery-channel "
        "--delivery-channel name=default,s3BucketName=<bucket>\n"
        "  aws configservice start-configuration-recorder "
        "--configuration-recorder-name default\n\n"
        "A recorder that exists and is stopped records nothing, which is why "
        "the last command is not optional."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "aws configservice start-configuration-recorder "
            "--configuration-recorder-name default",
        ),
        notes=(
            "A recorder that exists and is stopped records nothing. Creating "
            "one is two commands; starting it is the third and the one people "
            "miss."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["3.3"],
        "ISO_27001": ["A.8.15"],
        "NIST_CSF": ["DE.CM-1"],
        "NIST_800_53": ["CM-6", "AU-2"],
        "SOC2": ["CC7.1"],
        "PCI_DSS_4": ["10.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Config recorders unavailable: {failure}")

        enabled = set(context.controls.get("enabled_regions") or [])
        if not enabled:
            return RuleResult.unknown("The account's enabled regions are not known")

        recording = {
            str(entry.get("region"))
            for entry in context.controls.get("config_recorders") or []
            if (entry.get("Status") or {}).get("recording")
        }
        uncovered = sorted(enabled - recording)
        evidence = {
            "enabled_regions": sorted(enabled),
            "regions_recording": sorted(recording),
            "regions_without": uncovered,
        }
        if not uncovered:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"AWS Config is not recording in {len(uncovered)} of "
                f"{len(enabled)} enabled regions: {', '.join(uncovered)}"
            ),
        )


class AwsFlowLogRule(SecurityRule):
    rule_id = "AWS-LOG-006"
    name = "A VPC has no flow logs"
    description = (
        "One or more VPCs record no network flows, so there is no way to answer "
        "what talked to what after an incident."
    )
    category = "logging"
    provider = Provider.AWS
    severity = Severity.MEDIUM
    exploitability = 1
    scope = RuleScope.AGGREGATE
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.VPC_FLOW_LOGS,
        AwsEvidence.VPCS,
    )
    estimated_effort_minutes = 20
    rationale = (
        "Flow logs are the only record of network activity AWS keeps, and they "
        "are off by default. Without them, the question after an intrusion — "
        "what did it reach — has no evidence behind it at all."
    )
    remediation = (
        "Turn them on per VPC:\n\n"
        "  aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> \\\n"
        "    --traffic-type ALL --log-destination-type cloud-watch-logs \\\n"
        "    --log-group-name <group> --deliver-logs-permission-arn <role>\n\n"
        "S3 as the destination is cheaper for volume; CloudWatch Logs is easier "
        "to query. Either satisfies this."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> "
            "--traffic-type ALL --log-destination-type s3 "
            "--log-destination arn:aws:s3:::<bucket>",
        ),
        notes=(
            "A flow log in a non-ACTIVE state records nothing, so this reads the "
            "status rather than the existence of the log."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["3.7"],
        "ISO_27001": ["A.8.15", "A.8.16"],
        "NIST_CSF": ["DE.CM-1", "DE.AE-3"],
        "NIST_800_53": ["AU-2", "SI-4"],
        "SOC2": ["CC7.2"],
        "PCI_DSS_4": ["10.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Flow log coverage unavailable: {failure}")

        vpcs = context.get_resources_by_type(ResourceType.VIRTUAL_NETWORK)
        if not vpcs:
            return RuleResult.not_applicable("This account has no VPC")

        covered = set(context.controls.get("flow_log_resources") or [])
        uncovered = sorted(
            vpc.provider_resource_id
            for vpc in vpcs
            if vpc.provider_resource_id not in covered
        )
        evidence = {
            "vpcs": sorted(v.provider_resource_id for v in vpcs),
            "vpcs_without_flow_logs": uncovered,
        }
        if not uncovered:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"{len(uncovered)} of {len(vpcs)} VPC(s) have no flow logs: "
                f"{', '.join(uncovered)}"
            ),
        )


def _unique_trails(context: RuleContext) -> dict[str, dict]:
    """Every trail this account has, once.

    A multi-region trail is returned by every region it covers, which is what
    makes coverage answerable (AWS-LOG-001) and what would make every other
    trail rule count it seventeen times. Keyed by ARN so the same trail seen
    from three regions is one trail.
    """
    found: dict[str, dict] = {}
    for entry in context.controls.get("cloudtrail_trails") or []:
        arn = str(entry.get("TrailARN") or entry.get("Name") or "")
        if arn:
            found.setdefault(arn, entry)
    return found
