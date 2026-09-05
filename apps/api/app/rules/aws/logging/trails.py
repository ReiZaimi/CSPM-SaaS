"""Logging and account-wide defaults, judged per region.

Both rules here are aggregate and both read the same shape: a set of regions
where something is true, against the set of regions the account has enabled.
That comparison is the whole reason ``enabled_regions`` is carried as a control
-- "there is no trail in eu-west-1" means nothing without a list of the regions
that exist for this customer.
"""

from dataclasses import dataclass
from typing import Any, ClassVar

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


# ---------------------------------------------------------------- monitoring
#
# CIS section 4 asks whether somebody is *told* when something happens, and the
# answer is a chain rather than a setting:
#
#     trail -> CloudWatch log group -> metric filter -> metric -> alarm -> action
#
# Every hop can be missing on its own, and a missing hop anywhere means nobody
# is told. A check that looked only for the filter would pass the very common
# half-done case: the filter exists, the metric is published, and no alarm was
# ever created on it.


@dataclass(frozen=True)
class MonitoringCheck:
    """How far along the chain this account actually gets.

    Carried rather than reduced to a boolean because *where* it stops is the
    remediation. "No filter" and "a filter with no alarm" are the same verdict
    and different afternoons.
    """

    log_groups: tuple[str, ...] = ()
    matching_filters: tuple[dict[str, Any], ...] = ()
    alarms: tuple[str, ...] = ()
    alarms_without_action: tuple[str, ...] = ()

    @property
    def monitored(self) -> bool:
        return bool(self.alarms)

    def why_not(self) -> str:
        if not self.log_groups:
            return "no trail sends its events to a CloudWatch log group"
        if not self.matching_filters:
            return "no metric filter on the trail's log group matches this event"
        if self.alarms_without_action:
            return (
                "a metric filter exists and its alarm notifies nobody: "
                + ", ".join(self.alarms_without_action)
            )
        return "a metric filter exists and no alarm is raised on its metric"


def _trail_log_groups(context: RuleContext) -> dict[str, set[str]]:
    """Region -> the CloudWatch log groups this account's trails write to.

    A trail that delivers only to S3 has no log group, and no metric filter can
    exist for it. That is the first way this control is not met, and naming it
    is more useful than reporting "no filter found".

    The ARN's name is taken from the ARN rather than trusted from elsewhere:
    ``arn:aws:logs:<region>:<account>:log-group:<name>:*``.
    """
    groups: dict[str, set[str]] = {}
    for entry in context.controls.get("cloudtrail_trails") or []:
        arn = str(entry.get("CloudWatchLogsLogGroupArn") or "")
        region = str(entry.get("region") or "")
        if not arn or not region:
            continue
        parts = arn.split(":")
        if len(parts) >= 7 and parts[5] == "log-group":
            groups.setdefault(region, set()).add(parts[6])
    return groups


def _matches(pattern: str, required: tuple[tuple[str, ...], ...]) -> bool:
    """Whether a filter pattern names everything this check is about.

    **This is a necessary condition, not a sufficient one, and the limit is
    real.** CloudGuard does not evaluate CloudWatch's filter-pattern language --
    doing that properly means implementing somebody else's expression grammar,
    and implementing it *nearly* right is worse than not implementing it, because
    a filter that parses differently to how AWS parses it produces a confident
    wrong answer.

    So the test is that every required ingredient appears. A pattern naming
    ``$.errorCode`` and both refusal codes is doing this job or is a very
    strange thing to have written; one that names none of them is not. The
    pattern itself goes into the finding's evidence, so a reader can see exactly
    what was matched rather than trusting this function's opinion of it.

    Each entry in ``required`` is a set of alternatives: the pattern has to
    carry at least one from each. That is what lets ``AccessDenied`` and
    ``AccessDenied*`` both count without accepting a pattern that mentions
    neither.
    """
    haystack = pattern.replace(" ", "").lower()
    return all(
        any(alternative.replace(" ", "").lower() in haystack for alternative in group)
        for group in required
    )


def _monitoring(
    context: RuleContext, required: tuple[tuple[str, ...], ...]
) -> MonitoringCheck:
    """Walk filter -> metric -> alarm -> action for one kind of event."""
    groups = _trail_log_groups(context)
    if not groups:
        return MonitoringCheck()

    matching: list[dict[str, Any]] = []
    for entry in context.controls.get("log_metric_filters") or []:
        region = str(entry.get("region") or "")
        if str(entry.get("logGroupName") or "") not in groups.get(region, set()):
            continue
        if _matches(str(entry.get("filterPattern") or ""), required):
            matching.append(entry)

    flat_groups = tuple(sorted({name for names in groups.values() for name in names}))
    if not matching:
        return MonitoringCheck(log_groups=flat_groups)

    # The metrics those filters publish, as (region, namespace, name). The
    # region is part of the key because an alarm can only watch a metric in its
    # own region, and a filter in eu-west-1 with an alarm in us-east-1 is two
    # things that never meet.
    wanted = {
        (
            str(entry.get("region")),
            str(transformation.get("metricNamespace")),
            str(transformation.get("metricName")),
        )
        for entry in matching
        for transformation in entry.get("metricTransformations") or []
    }

    alarmed: list[str] = []
    silent: list[str] = []
    for alarm in context.controls.get("cloudwatch_alarms") or []:
        key = (
            str(alarm.get("region")),
            str(alarm.get("Namespace")),
            str(alarm.get("MetricName")),
        )
        if key not in wanted:
            continue
        name = str(alarm.get("AlarmName") or "")
        # An alarm with no action changes a colour on a dashboard nobody is
        # looking at. CIS asks for a notification, and so does this.
        if alarm.get("AlarmActions"):
            alarmed.append(name)
        else:
            silent.append(name)

    return MonitoringCheck(
        log_groups=flat_groups,
        matching_filters=tuple(matching),
        alarms=tuple(sorted(alarmed)),
        alarms_without_action=tuple(sorted(silent)),
    )


class _MonitoredEventRule(SecurityRule):
    """Shared evaluation for "somebody is told when this happens".

    Not a rule itself -- absent from the registry, declares no id. It exists so
    two rules do not each grow their own copy of a four-hop walk, and so the
    "we could not read the trails" case degrades identically in both.
    """

    provider = Provider.AWS
    category = "logging"
    scope = RuleScope.AGGREGATE
    # Not exploitable. It is the difference between an incident somebody
    # notices and one they read about later.
    exploitability = 1
    required: ClassVar[tuple[tuple[str, ...], ...]] = ()
    event: str = ""
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.CLOUDTRAIL_TRAILS,
        AwsEvidence.LOG_METRIC_FILTERS,
        AwsEvidence.CLOUDWATCH_ALARMS,
    )

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Monitoring configuration unavailable: {failure}")

        if not _unique_trails(context):
            # No trail at all is AWS-LOG-001's finding. Raising it again here,
            # twice over, would charge the security score three times for one
            # problem written three ways.
            return RuleResult.not_applicable("This account has no trail")

        check = _monitoring(context, self.required)
        evidence = {
            "event": self.event,
            "trail_log_groups": list(check.log_groups),
            # The patterns that matched, verbatim. This function tests that the
            # right ingredients are present and does not evaluate CloudWatch's
            # filter language -- so a reader is shown what was matched rather
            # than asked to trust the match.
            "matching_filter_patterns": [
                str(entry.get("filterPattern") or "")
                for entry in check.matching_filters
            ],
            "alarms": list(check.alarms),
            "alarms_without_action": list(check.alarms_without_action),
        }

        if check.monitored:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=f"Nobody is alerted when {self.event}: {check.why_not()}",
        )


class AwsUnauthorizedApiMonitoringRule(_MonitoredEventRule):
    rule_id = "AWS-LOG-007"
    name = "Unauthorized API calls raise no alarm"
    description = (
        "No CloudWatch alarm fires on refused API calls. A credential being "
        "tried against everything it does not have produces a burst of "
        "AccessDenied and UnauthorizedOperation, which is the clearest early "
        "signal of a compromised key there is — and nobody sees it."
    )
    severity = Severity.MEDIUM
    event = "an API call is refused"
    # ``$.errorCode`` plus both refusal codes AWS uses. Spelled as alternatives
    # because CIS's own pattern writes them with wildcards and a hand-written
    # one usually does not.
    required: ClassVar[tuple[tuple[str, ...], ...]] = (
        ("$.errorCode",),
        ("UnauthorizedOperation",),
        ("AccessDenied",),
    )
    estimated_effort_minutes = 30
    rationale = (
        "An attacker with a stolen key finds out what it can do by trying. The "
        "refusals are logged either way; the difference between noticing on the "
        "day and reading about it in an invoice is whether anything watches "
        "them."
    )
    remediation = (
        "The trail has to reach CloudWatch Logs first — a trail delivering only "
        "to S3 cannot be alarmed on:\n\n"
        "  aws cloudtrail update-trail --name <trail> \\\n"
        "    --cloud-watch-logs-log-group-arn <group-arn> \\\n"
        "    --cloud-watch-logs-role-arn <role-arn>\n\n"
        "Then the filter, and the alarm on the metric it publishes:\n\n"
        "  aws logs put-metric-filter --log-group-name <group> \\\n"
        "    --filter-name UnauthorizedAPICalls \\\n"
        "    --filter-pattern '{ ($.errorCode = \"*UnauthorizedOperation\") || "
        '($.errorCode = "AccessDenied*") }\' \\\n'
        "    --metric-transformations "
        "metricName=UnauthorizedAPICalls,metricNamespace=CISBenchmark,metricValue=1\n\n"
        "  aws cloudwatch put-metric-alarm --alarm-name UnauthorizedAPICalls \\\n"
        "    --metric-name UnauthorizedAPICalls --namespace CISBenchmark \\\n"
        "    --statistic Sum --period 300 --threshold 1 \\\n"
        "    --comparison-operator GreaterThanOrEqualToThreshold \\\n"
        "    --evaluation-periods 1 --alarm-actions <sns-topic-arn>\n\n"
        "The `--alarm-actions` is not optional. An alarm with no action changes "
        "a colour on a dashboard nobody is looking at."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        # Aggregate, and genuinely unstatable as a value: the expectation is a
        # chain across three services, not a field on an asset.
        expected=(),
        cli=(
            "aws logs put-metric-filter --log-group-name <group> "
            "--filter-name UnauthorizedAPICalls "
            "--filter-pattern '{ ($.errorCode = \"*UnauthorizedOperation\") || "
            "($.errorCode = \"AccessDenied*\") }' "
            "--metric-transformations metricName=UnauthorizedAPICalls,"
            "metricNamespace=CISBenchmark,metricValue=1",
            "aws cloudwatch put-metric-alarm --alarm-name UnauthorizedAPICalls "
            "--metric-name UnauthorizedAPICalls --namespace CISBenchmark "
            "--statistic Sum --period 300 --threshold 1 "
            "--comparison-operator GreaterThanOrEqualToThreshold "
            "--evaluation-periods 1 --alarm-actions <sns-topic-arn>",
        ),
        notes=(
            "CloudGuard checks that the filter names the fields this event is "
            "about and that an alarm with an action watches the metric it "
            "publishes. It does not evaluate CloudWatch's filter-pattern "
            "language: the matched pattern is shown in the finding so it can be "
            "read rather than trusted."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["4.1"],
        "ISO_27001": ["A.8.16"],
        "NIST_CSF": ["DE.CM-1", "DE.AE-3"],
        "NIST_800_53": ["AU-6", "SI-4"],
        "SOC2": ["CC7.2"],
        "PCI_DSS_4": ["10.5.1"],
    }


class AwsRootUsageMonitoringRule(_MonitoredEventRule):
    rule_id = "AWS-LOG-008"
    name = "Root account usage raises no alarm"
    description = (
        "No CloudWatch alarm fires when the root user does anything. Root should "
        "be used approximately never, so any use of it is either a planned "
        "exception somebody can confirm or an incident."
    )
    severity = Severity.HIGH
    event = "the root user is used"
    # ``$.userIdentity.type`` and the value that identifies root. CIS's pattern
    # also excludes service events, which is a refinement rather than a
    # requirement -- an alarm that fires on those too is noisier and not wrong.
    required: ClassVar[tuple[tuple[str, ...], ...]] = (
        ("$.userIdentity.type",),
        ("Root",),
    )
    estimated_effort_minutes = 30
    rationale = (
        "Root cannot be restricted by any policy and no SCP can deny it, so "
        "there is no preventive control to fall back on. Noticing is the whole "
        "of the defence, and root is used rarely enough that an alarm on it is "
        "almost never noise."
    )
    remediation = (
        "With the trail already reaching CloudWatch Logs:\n\n"
        "  aws logs put-metric-filter --log-group-name <group> \\\n"
        "    --filter-name RootAccountUsage \\\n"
        '    --filter-pattern \'{ $.userIdentity.type = "Root" && '
        '$.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }\' \\\n'
        "    --metric-transformations "
        "metricName=RootAccountUsage,metricNamespace=CISBenchmark,metricValue=1\n\n"
        "  aws cloudwatch put-metric-alarm --alarm-name RootAccountUsage \\\n"
        "    --metric-name RootAccountUsage --namespace CISBenchmark \\\n"
        "    --statistic Sum --period 300 --threshold 1 \\\n"
        "    --comparison-operator GreaterThanOrEqualToThreshold \\\n"
        "    --evaluation-periods 1 --alarm-actions <sns-topic-arn>\n\n"
        "The two exclusions in the pattern keep AWS's own service events out of "
        "it. Without them the alarm fires on billing and support activity and "
        "gets muted, which is the same outcome as not having it."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "aws logs put-metric-filter --log-group-name <group> "
            "--filter-name RootAccountUsage "
            '--filter-pattern \'{ $.userIdentity.type = "Root" && '
            '$.userIdentity.invokedBy NOT EXISTS && '
            '$.eventType != "AwsServiceEvent" }\' '
            "--metric-transformations metricName=RootAccountUsage,"
            "metricNamespace=CISBenchmark,metricValue=1",
            "aws cloudwatch put-metric-alarm --alarm-name RootAccountUsage "
            "--metric-name RootAccountUsage --namespace CISBenchmark "
            "--statistic Sum --period 300 --threshold 1 "
            "--comparison-operator GreaterThanOrEqualToThreshold "
            "--evaluation-periods 1 --alarm-actions <sns-topic-arn>",
        ),
        notes=(
            "Exclude AWS's own service events, or the alarm fires on billing "
            "and support activity and gets muted -- which is the same outcome "
            "as not having it."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["4.3"],
        "ISO_27001": ["A.8.15", "A.8.16"],
        "NIST_CSF": ["DE.CM-1", "PR.AC-4"],
        "NIST_800_53": ["AU-6", "AC-6"],
        "SOC2": ["CC7.2"],
        "PCI_DSS_4": ["10.2.1"],
    }
