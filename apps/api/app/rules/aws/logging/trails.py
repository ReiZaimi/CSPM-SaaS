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


# --------------------------------------------- the rest of CIS AWS section 4
#
# Section 4 is fifteen controls of one shape: a metric filter over the trail's
# log group, the metric it publishes, and an alarm that notifies somebody.
# AWS-LOG-007 and AWS-LOG-008 walk that chain for two of them, and the thirteen
# below are the rest. They are declarations rather than code, because the walk
# is already written and a second copy of it would be a second thing to get
# wrong.
#
# Each names the ingredients CIS's own filter pattern for that control carries.
# The test stays a necessary condition (see ``_matches``): CloudGuard does not
# evaluate CloudWatch's filter language, and the pattern that matched travels in
# the finding so a reader can judge it rather than trust it.

_PUT_FILTER = (
    "aws logs put-metric-filter --log-group-name <group> "
    "--filter-name {name} --filter-pattern '{pattern}' "
    "--metric-transformations metricName={name},"
    "metricNamespace=CISBenchmark,metricValue=1"
)
_PUT_ALARM = (
    "aws cloudwatch put-metric-alarm --alarm-name {name} "
    "--metric-name {name} --namespace CISBenchmark --statistic Sum "
    "--period 300 --threshold 1 "
    "--comparison-operator GreaterThanOrEqualToThreshold "
    "--evaluation-periods 1 --alarm-actions <sns-topic-arn>"
)
_SPEC_NOTES = (
    "CloudGuard checks that a filter on the trail's log group names the fields "
    "this event is about, and that an alarm with an action watches the metric "
    "that filter publishes. It does not evaluate CloudWatch's filter-pattern "
    "language: the matched pattern is shown in the finding so it can be read "
    "rather than trusted."
)


def _monitoring_commands(name: str, pattern: str) -> tuple[str, str]:
    return (
        _PUT_FILTER.format(name=name, pattern=pattern),
        _PUT_ALARM.format(name=name),
    )


def _monitoring_remediation(name: str, pattern: str) -> str:
    """The prose half, generated from the same two commands as the declaration.

    Written once rather than thirteen times. Thirteen copies of one paragraph
    drift: the day the alarm command gains an argument, twelve of them keep the
    old one and a customer follows whichever they were handed.
    """
    put_filter, put_alarm = _monitoring_commands(name, pattern)
    return (
        "The trail has to reach CloudWatch Logs first — a trail delivering only "
        "to S3 cannot be alarmed on:\n\n"
        "  aws cloudtrail update-trail --name <trail> \\\n"
        "    --cloud-watch-logs-log-group-arn <group-arn> \\\n"
        "    --cloud-watch-logs-role-arn <role-arn>\n\n"
        "Then the filter, and the alarm on the metric it publishes:\n\n"
        f"  {put_filter}\n\n"
        f"  {put_alarm}\n\n"
        "The `--alarm-actions` is not optional. An alarm with no action changes "
        "a colour on a dashboard nobody is looking at."
    )


def _monitoring_spec(name: str, pattern: str, note: str) -> RemediationSpec:
    return RemediationSpec(
        # Aggregate, and genuinely unstatable as a value: the expectation is a
        # chain across three services, not a field on an asset.
        expected=(),
        cli=_monitoring_commands(name, pattern),
        notes=f"{_SPEC_NOTES} {note}",
    )


_MONITORING_MAPPINGS: dict[str, list[str]] = {
    "ISO_27001": ["A.8.16"],
    "NIST_CSF": ["DE.CM-1", "DE.AE-3"],
    "NIST_800_53": ["AU-6", "SI-4"],
    "SOC2": ["CC7.2"],
    "PCI_DSS_4": ["10.5.1"],
}

_CONSOLE_MFA_PATTERN = (
    '{ ($.eventName = "ConsoleLogin") && '
    '($.additionalEventData.MFAUsed != "Yes") }'
)


class AwsConsoleSignInWithoutMfaMonitoringRule(_MonitoredEventRule):
    rule_id = "AWS-LOG-009"
    name = "Console sign-in without MFA raises no alarm"
    description = (
        "No CloudWatch alarm fires when somebody signs in to the console with a "
        "password alone. AWS-IAM-001 reports the users who can do it; this "
        "reports that nobody finds out when one of them does."
    )
    severity = Severity.MEDIUM
    event = "somebody signs in to the console without MFA"
    # ``$.eventName``, the sign-in event, and the field that says whether a
    # second factor was used.
    required: ClassVar[tuple[tuple[str, ...], ...]] = (
        ("$.eventName",),
        ("ConsoleLogin",),
        ("MFAUsed",),
    )
    estimated_effort_minutes = 30
    rationale = (
        "A password-only sign-in is what a phished credential looks like from "
        "the outside. Enforcing MFA is the fix and this is not it — it is the "
        "answer to what happens between the credential being stolen and the "
        "enforcement being finished."
    )
    remediation = _monitoring_remediation(
        "ConsoleSignInWithoutMFA", _CONSOLE_MFA_PATTERN
    )
    remediation_spec: ClassVar[RemediationSpec | None] = _monitoring_spec(
        "ConsoleSignInWithoutMFA",
        _CONSOLE_MFA_PATTERN,
        "A sign-in through an assumed role carries no MFAUsed field of its own; "
        "the factor was presented when the role was assumed.",
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["4.2"],
        **_MONITORING_MAPPINGS,
    }


_IAM_POLICY_PATTERN = (
    "{ ($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||"
    "($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||"
    "($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||"
    "($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||"
    "($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||"
    "($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||"
    "($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||"
    "($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy) }"
)


class AwsIamPolicyChangeMonitoringRule(_MonitoredEventRule):
    rule_id = "AWS-LOG-010"
    name = "IAM policy changes raise no alarm"
    description = (
        "No CloudWatch alarm fires when a policy is written, attached or "
        "detached. Every escalation an attacker performs inside an account ends "
        "in one of these calls, because permission is the thing being taken."
    )
    severity = Severity.MEDIUM
    event = "an IAM policy is written, attached or detached"
    # ``$.eventName`` and one call from each half of what CIS's pattern lists:
    # a policy written inline, and a managed policy attached to a principal.
    required: ClassVar[tuple[tuple[str, ...], ...]] = (
        ("$.eventName",),
        ("PutRolePolicy", "PutUserPolicy", "PutGroupPolicy"),
        ("AttachRolePolicy", "AttachUserPolicy", "AttachGroupPolicy"),
    )
    estimated_effort_minutes = 30
    rationale = (
        "A foothold is worth what its permissions are worth, so the first thing "
        "an attacker does with one is widen them. These calls are also routine "
        "administration, which is the point: an alarm here is read against a "
        "change nobody planned, not against zero."
    )
    remediation = _monitoring_remediation("IAMPolicyChanges", _IAM_POLICY_PATTERN)
    remediation_spec: ClassVar[RemediationSpec | None] = _monitoring_spec(
        "IAMPolicyChanges",
        _IAM_POLICY_PATTERN,
        "This one fires on legitimate work too. Route it somewhere a change can "
        "be matched against a ticket rather than to a pager.",
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["4.4"],
        **_MONITORING_MAPPINGS,
    }


_TRAIL_CHANGE_PATTERN = (
    "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || "
    "($.eventName = DeleteTrail) || ($.eventName = StartLogging) || "
    "($.eventName = StopLogging) }"
)


class AwsTrailChangeMonitoringRule(_MonitoredEventRule):
    rule_id = "AWS-LOG-011"
    name = "CloudTrail configuration changes raise no alarm"
    description = (
        "No CloudWatch alarm fires when a trail is changed, deleted, or has its "
        "logging stopped. Every other alarm in this section is downstream of the "
        "trail, so this is the one whose failure hides the others."
    )
    severity = Severity.HIGH
    event = "a trail is changed or its logging is stopped"
    # ``$.eventName``, the call that blinds the account, and one of the two that
    # rewrite or remove the trail itself.
    required: ClassVar[tuple[tuple[str, ...], ...]] = (
        ("$.eventName",),
        ("StopLogging",),
        ("DeleteTrail", "UpdateTrail"),
    )
    estimated_effort_minutes = 30
    rationale = (
        "`StopLogging` is one call, takes effect immediately, and is the "
        "standard first move once an attacker has permission to make it. "
        "Everything after it happened to an account nobody was recording, and "
        "the gap in the trail is the only evidence left."
    )
    remediation = _monitoring_remediation("CloudTrailChanges", _TRAIL_CHANGE_PATTERN)
    remediation_spec: ClassVar[RemediationSpec | None] = _monitoring_spec(
        "CloudTrailChanges",
        _TRAIL_CHANGE_PATTERN,
        "AWS-LOG-001 asks whether the trail exists and AWS-LOG-002 whether its "
        "files can be shown to be intact. This asks whether anybody hears it "
        "stop.",
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["4.5"],
        **_MONITORING_MAPPINGS,
    }


_AUTH_FAILURE_PATTERN = (
    '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }'
)


class AwsConsoleAuthFailureMonitoringRule(_MonitoredEventRule):
    rule_id = "AWS-LOG-012"
    name = "Console authentication failures raise no alarm"
    description = (
        "No CloudWatch alarm fires on failed console sign-ins. One is somebody "
        "mistyping a password; several hundred against one account is a "
        "password spray, and the two look identical until somebody counts."
    )
    severity = Severity.LOW
    event = "a console sign-in fails"
    # ``$.eventName``, the sign-in event, and the message AWS puts on a refusal.
    required: ClassVar[tuple[tuple[str, ...], ...]] = (
        ("$.eventName",),
        ("ConsoleLogin",),
        ("Failed authentication", "$.errorMessage"),
    )
    estimated_effort_minutes = 30
    rationale = (
        "Lowest of the thirteen, and deliberately: a password policy and "
        "enforced MFA are preventive, this is only detective, and CloudGuard "
        "checks both of those separately. It still earns its place — a spray "
        "that eventually succeeds produces a *successful* sign-in nothing else "
        "distinguishes from a Monday morning."
    )
    remediation = _monitoring_remediation("ConsoleSignInFailures", _AUTH_FAILURE_PATTERN)
    remediation_spec: ClassVar[RemediationSpec | None] = _monitoring_spec(
        "ConsoleSignInFailures",
        _AUTH_FAILURE_PATTERN,
        "A threshold of one on this alarm is noise. Raise the threshold or "
        "lengthen the period rather than muting it, or it ends up ignored, "
        "which is the same as not having it.",
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["4.6"],
        **_MONITORING_MAPPINGS,
    }


_KEY_DISABLE_PATTERN = (
    "{ ($.eventSource = kms.amazonaws.com) && "
    "(($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion)) }"
)


class AwsKeyDisableMonitoringRule(_MonitoredEventRule):
    rule_id = "AWS-LOG-013"
    name = "Disabling or deleting a customer key raises no alarm"
    description = (
        "No CloudWatch alarm fires when a KMS key is disabled or scheduled for "
        "deletion. Everything encrypted under that key becomes unreadable when "
        "the deletion lands, and the waiting period is the entire window in "
        "which anybody can stop it."
    )
    severity = Severity.HIGH
    event = "a customer key is disabled or scheduled for deletion"
    # The service, and both calls CIS names. A pattern carrying only one of them
    # is watching half of a two-step nobody performs by accident.
    required: ClassVar[tuple[tuple[str, ...], ...]] = (
        ("kms.amazonaws.com",),
        ("DisableKey",),
        ("ScheduleKeyDeletion",),
    )
    estimated_effort_minutes = 30
    rationale = (
        "This is the destructive path that needs no data access at all: a "
        "principal that can schedule a key for deletion can make a backup, a "
        "bucket and a database unreadable without reading one byte of any of "
        "them. The minimum waiting period is seven days, and it is only a "
        "safeguard if somebody is told the clock started."
    )
    remediation = _monitoring_remediation("DisableOrDeleteCMK", _KEY_DISABLE_PATTERN)
    remediation_spec: ClassVar[RemediationSpec | None] = _monitoring_spec(
        "DisableOrDeleteCMK",
        _KEY_DISABLE_PATTERN,
        "Cancel a deletion with `aws kms cancel-key-deletion --key-id <id>` "
        "while the waiting period is still running. After it, the key material "
        "is gone and AWS cannot recover it.",
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["4.7"],
        **_MONITORING_MAPPINGS,
    }


_BUCKET_POLICY_PATTERN = (
    "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || "
    "($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || "
    "($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) "
    "|| ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) "
    "|| ($.eventName = DeleteBucketLifecycle) || "
    "($.eventName = DeleteBucketReplication)) }"
)


class AwsBucketPolicyChangeMonitoringRule(_MonitoredEventRule):
    rule_id = "AWS-LOG-014"
    name = "S3 bucket policy changes raise no alarm"
    description = (
        "No CloudWatch alarm fires when a bucket's policy or ACL is rewritten. "
        "AWS-STO-001 finds a bucket that is public at the moment of a scan; this "
        "is what tells somebody on the afternoon it becomes public."
    )
    severity = Severity.MEDIUM
    event = "a bucket policy or ACL is changed"
    # The service, and both directions: a policy written, and one removed.
    required: ClassVar[tuple[tuple[str, ...], ...]] = (
        ("s3.amazonaws.com",),
        ("PutBucketPolicy",),
        ("DeleteBucketPolicy",),
    )
    estimated_effort_minutes = 30
    rationale = (
        "A scan is periodic and an exposure is not. A bucket opened and closed "
        "between two scans never appears in a finding, and the copy somebody "
        "took while it was open is not undone by closing it."
    )
    remediation = _monitoring_remediation("S3BucketPolicyChanges", _BUCKET_POLICY_PATTERN)
    remediation_spec: ClassVar[RemediationSpec | None] = _monitoring_spec(
        "S3BucketPolicyChanges",
        _BUCKET_POLICY_PATTERN,
        "An account-level public access block is the preventive control and "
        "should be on regardless; this reports the attempts it refuses as well "
        "as the changes it does not cover.",
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["4.8"],
        **_MONITORING_MAPPINGS,
    }


_CONFIG_CHANGE_PATTERN = (
    "{ ($.eventSource = config.amazonaws.com) && "
    "(($.eventName=StopConfigurationRecorder)||"
    "($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||"
    "($.eventName=PutConfigurationRecorder)) }"
)


class AwsConfigChangeMonitoringRule(_MonitoredEventRule):
    rule_id = "AWS-LOG-015"
    name = "AWS Config changes raise no alarm"
    description = (
        "No CloudWatch alarm fires when configuration recording is stopped or "
        "its delivery channel is changed. The recorder is the account's history "
        "of what its resources looked like, and stopping it is quiet."
    )
    severity = Severity.MEDIUM
    event = "configuration recording is stopped or redirected"
    # The service, the call that stops recording, and the one that removes where
    # the recordings go.
    required: ClassVar[tuple[tuple[str, ...], ...]] = (
        ("config.amazonaws.com",),
        ("StopConfigurationRecorder",),
        ("DeleteDeliveryChannel",),
    )
    estimated_effort_minutes = 30
    rationale = (
        "AWS-LOG-005 reports a recorder that is off at scan time. The gap it "
        "cannot report is a recorder switched off and back on between scans, "
        "which is exactly the shape of somebody covering a change."
    )
    remediation = _monitoring_remediation("AWSConfigChanges", _CONFIG_CHANGE_PATTERN)
    remediation_spec: ClassVar[RemediationSpec | None] = _monitoring_spec(
        "AWSConfigChanges",
        _CONFIG_CHANGE_PATTERN,
        "`PutConfigurationRecorder` and `PutDeliveryChannel` are in the pattern "
        "too: a recorder narrowed to one resource type records almost nothing "
        "while still reporting itself as recording.",
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["4.9"],
        **_MONITORING_MAPPINGS,
    }


_SECURITY_GROUP_PATTERN = (
    "{ ($.eventName = AuthorizeSecurityGroupIngress) || "
    "($.eventName = AuthorizeSecurityGroupEgress) || "
    "($.eventName = RevokeSecurityGroupIngress) || "
    "($.eventName = RevokeSecurityGroupEgress) || "
    "($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
)


class AwsSecurityGroupChangeMonitoringRule(_MonitoredEventRule):
    rule_id = "AWS-LOG-016"
    name = "Security group changes raise no alarm"
    description = (
        "No CloudWatch alarm fires when a security group rule is added or "
        "removed. A security group is the account's firewall, and one added rule "
        "is the difference between a private database and a public one."
    )
    severity = Severity.MEDIUM
    event = "a security group rule is added or removed"
    # ``$.eventName``, the call that opens a port, and one that creates or
    # removes a group outright.
    required: ClassVar[tuple[tuple[str, ...], ...]] = (
        ("$.eventName",),
        ("AuthorizeSecurityGroupIngress",),
        ("CreateSecurityGroup", "DeleteSecurityGroup"),
    )
    estimated_effort_minutes = 30
    rationale = (
        "AWS-NET-001 through AWS-NET-003 report a port open to the internet at "
        "scan time. `AuthorizeSecurityGroupIngress` is the call that opened it, "
        "and knowing who made it and when is most of an incident's timeline."
    )
    remediation = _monitoring_remediation("SecurityGroupChanges", _SECURITY_GROUP_PATTERN)
    remediation_spec: ClassVar[RemediationSpec | None] = _monitoring_spec(
        "SecurityGroupChanges",
        _SECURITY_GROUP_PATTERN,
        "In an account where groups are managed by Terraform or CloudFormation, "
        "every alarm from this is either a deployment or an unplanned change, "
        "and the two are easy to tell apart by the principal that made it.",
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["4.10"],
        **_MONITORING_MAPPINGS,
    }


_NETWORK_ACL_PATTERN = (
    "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) "
    "|| ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) "
    "|| ($.eventName = ReplaceNetworkAclEntry) || "
    "($.eventName = ReplaceNetworkAclAssociation) }"
)


class AwsNetworkAclChangeMonitoringRule(_MonitoredEventRule):
    rule_id = "AWS-LOG-017"
    name = "Network ACL changes raise no alarm"
    description = (
        "No CloudWatch alarm fires when a network ACL entry is written or "
        "replaced. An ACL sits in front of every security group in its subnet, "
        "so a change here quietly widens what all of them allow."
    )
    severity = Severity.MEDIUM
    event = "a network ACL entry is changed"
    # ``$.eventName``, an entry written, and an ACL or entry removed.
    required: ClassVar[tuple[tuple[str, ...], ...]] = (
        ("$.eventName",),
        ("CreateNetworkAclEntry",),
        ("DeleteNetworkAcl",),
    )
    estimated_effort_minutes = 30
    rationale = (
        "ACLs are edited rarely and by few people, which makes an alarm on them "
        "close to silent in a healthy account — and unusually informative when "
        "it does fire."
    )
    remediation = _monitoring_remediation("NetworkAclChanges", _NETWORK_ACL_PATTERN)
    remediation_spec: ClassVar[RemediationSpec | None] = _monitoring_spec(
        "NetworkAclChanges",
        _NETWORK_ACL_PATTERN,
        "`ReplaceNetworkAclAssociation` is in the pattern because moving a "
        "subnet to a permissive ACL changes what it allows without editing any "
        "rule.",
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["4.11"],
        **_MONITORING_MAPPINGS,
    }


_GATEWAY_PATTERN = (
    "{ ($.eventName = CreateCustomerGateway) || "
    "($.eventName = DeleteCustomerGateway) || "
    "($.eventName = AttachInternetGateway) || "
    "($.eventName = CreateInternetGateway) || "
    "($.eventName = DeleteInternetGateway) || "
    "($.eventName = DetachInternetGateway) }"
)


class AwsGatewayChangeMonitoringRule(_MonitoredEventRule):
    rule_id = "AWS-LOG-018"
    name = "Network gateway changes raise no alarm"
    description = (
        "No CloudWatch alarm fires when an internet or customer gateway is "
        "created, attached or detached. Attaching an internet gateway is the "
        "single call that gives a private VPC a route to the internet."
    )
    severity = Severity.MEDIUM
    event = "a network gateway is attached or removed"
    # ``$.eventName``, and both directions of the attachment that matters.
    required: ClassVar[tuple[tuple[str, ...], ...]] = (
        ("$.eventName",),
        ("CreateInternetGateway", "AttachInternetGateway"),
        ("DeleteInternetGateway", "DetachInternetGateway"),
    )
    estimated_effort_minutes = 30
    rationale = (
        "A workload nobody meant to expose is usually exposed in two calls: a "
        "gateway attached and a route added. This is the first of them, and "
        "AWS-LOG-019 is the second."
    )
    remediation = _monitoring_remediation("NetworkGatewayChanges", _GATEWAY_PATTERN)
    remediation_spec: ClassVar[RemediationSpec | None] = _monitoring_spec(
        "NetworkGatewayChanges",
        _GATEWAY_PATTERN,
        "Detaching a gateway is in the pattern as well as attaching one: it "
        "takes a production network offline, which is an outage somebody should "
        "hear about immediately.",
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["4.12"],
        **_MONITORING_MAPPINGS,
    }


_ROUTE_TABLE_PATTERN = (
    "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || "
    "($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) "
    "|| ($.eventName = DeleteRoute) || ($.eventName = DeleteRouteTable) || "
    "($.eventName = DisassociateRouteTable) }"
)


class AwsRouteTableChangeMonitoringRule(_MonitoredEventRule):
    rule_id = "AWS-LOG-019"
    name = "Route table changes raise no alarm"
    description = (
        "No CloudWatch alarm fires when a route is added, replaced or removed. A "
        "route decides where a subnet's traffic goes, and neither a security "
        "group nor an ACL says anything about it."
    )
    severity = Severity.MEDIUM
    event = "a route table is changed"
    # ``$.eventName``, a route added, and a route redirected.
    required: ClassVar[tuple[tuple[str, ...], ...]] = (
        ("$.eventName",),
        ("CreateRoute",),
        ("ReplaceRoute",),
    )
    estimated_effort_minutes = 30
    rationale = (
        "Adding `0.0.0.0/0` to a private subnet's table exposes everything in it "
        "without touching a single firewall rule, so nothing else in this "
        "product's network checks would see it happen."
    )
    remediation = _monitoring_remediation("RouteTableChanges", _ROUTE_TABLE_PATTERN)
    remediation_spec: ClassVar[RemediationSpec | None] = _monitoring_spec(
        "RouteTableChanges",
        _ROUTE_TABLE_PATTERN,
        "`ReplaceRouteTableAssociation` moves a subnet to a different table "
        "wholesale, which changes every route it follows in one call.",
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["4.13"],
        **_MONITORING_MAPPINGS,
    }


_VPC_PATTERN = (
    "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || "
    "($.eventName = ModifyVpcAttribute) || "
    "($.eventName = AcceptVpcPeeringConnection) || "
    "($.eventName = CreateVpcPeeringConnection) || "
    "($.eventName = DeleteVpcPeeringConnection) || "
    "($.eventName = RejectVpcPeeringConnection) || "
    "($.eventName = AttachClassicLinkVpc) || "
    "($.eventName = DetachClassicLinkVpc) || "
    "($.eventName = DisableVpcClassicLink) || "
    "($.eventName = EnableVpcClassicLink) }"
)


class AwsVpcChangeMonitoringRule(_MonitoredEventRule):
    rule_id = "AWS-LOG-020"
    name = "VPC changes raise no alarm"
    description = (
        "No CloudWatch alarm fires when a VPC is created or deleted, or when a "
        "peering connection is made or accepted. A peering connection joins two "
        "networks that were separate, and one end of it can be an account "
        "nobody here controls."
    )
    severity = Severity.MEDIUM
    event = "a VPC or a peering connection is changed"
    # ``$.eventName`` and both ends of a VPC's life. ``CreateVpc`` also matches
    # the peering calls, which is the intent -- they are the same control.
    required: ClassVar[tuple[tuple[str, ...], ...]] = (
        ("$.eventName",),
        ("CreateVpc",),
        ("DeleteVpc",),
    )
    estimated_effort_minutes = 30
    rationale = (
        "Accepting a peering connection is a one-sided decision with a two-sided "
        "consequence: after it, another account's instances are inside this "
        "network's routable space, and no security group written before it knew "
        "that was possible."
    )
    remediation = _monitoring_remediation("VPCChanges", _VPC_PATTERN)
    remediation_spec: ClassVar[RemediationSpec | None] = _monitoring_spec(
        "VPCChanges",
        _VPC_PATTERN,
        "A new VPC is also worth hearing about on its own: it starts outside "
        "whatever flow logging, ACLs and tagging the existing ones were given.",
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["4.14"],
        **_MONITORING_MAPPINGS,
    }


_ORGANIZATIONS_PATTERN = (
    "{ ($.eventSource = organizations.amazonaws.com) && "
    '(($.eventName = "AcceptHandshake") || ($.eventName = "AttachPolicy") || '
    '($.eventName = "CreateAccount") || '
    '($.eventName = "CreateOrganizationalUnit") || '
    '($.eventName = "CreatePolicy") || ($.eventName = "DeclineHandshake") || '
    '($.eventName = "DeleteOrganization") || '
    '($.eventName = "DeleteOrganizationalUnit") || '
    '($.eventName = "DeletePolicy") || ($.eventName = "DetachPolicy") || '
    '($.eventName = "DisablePolicyType") || ($.eventName = "EnablePolicyType") '
    '|| ($.eventName = "InviteAccountToOrganization") || '
    '($.eventName = "LeaveOrganization") || ($.eventName = "MoveAccount") || '
    '($.eventName = "RemoveAccountFromOrganization") || '
    '($.eventName = "UpdatePolicy") || '
    '($.eventName = "UpdateOrganizationalUnit")) }'
)


class AwsOrganizationsChangeMonitoringRule(_MonitoredEventRule):
    rule_id = "AWS-LOG-021"
    name = "AWS Organizations changes raise no alarm"
    description = (
        "No CloudWatch alarm fires when an organization's structure or its "
        "policies change. A service control policy is the one boundary an "
        "account's own administrator cannot argue with, and detaching one is a "
        "single call."
    )
    severity = Severity.HIGH
    event = "an organization's structure or policies change"
    # The service, an account leaving, and a policy detached. Both are things
    # that remove a boundary rather than move something inside one.
    required: ClassVar[tuple[tuple[str, ...], ...]] = (
        ("organizations.amazonaws.com",),
        ("LeaveOrganization",),
        ("DetachPolicy",),
    )
    estimated_effort_minutes = 30
    rationale = (
        "Everything CloudGuard checks in a member account is checked under the "
        "assumption that the organization above it still constrains that "
        "account. `LeaveOrganization` and `DetachPolicy` end that assumption "
        "without changing anything inside the account, so no other check in this "
        "product would notice."
    )
    remediation = _monitoring_remediation("OrganizationsChanges", _ORGANIZATIONS_PATTERN)
    remediation_spec: ClassVar[RemediationSpec | None] = _monitoring_spec(
        "OrganizationsChanges",
        _ORGANIZATIONS_PATTERN,
        "Organizations is a global service that logs to us-east-1. The filter "
        "belongs on the log group of a trail that covers that region, or it "
        "matches nothing at all.",
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["4.15"],
        **_MONITORING_MAPPINGS,
    }
