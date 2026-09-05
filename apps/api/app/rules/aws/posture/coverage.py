"""Whether the account's own watchers are switched on.

Both rules here are aggregate and both ask the same shape of question: is this
service running in every region the account has enabled? That comparison is why
``enabled_regions`` is carried as a control — "GuardDuty is off in eu-west-1"
means nothing without a list of the regions that exist for this customer.

Neither rule re-reports what these services found. CloudGuard reads Defender's
assessments as evidence and reaches its own verdict (DECISIONS.md §62), and the
same discipline applies here: what is judged is whether anybody is watching,
which is a fact about the account rather than a conclusion of theirs.
"""

from typing import ClassVar

from app.connectors.aws.evidence import AwsEvidence
from app.core.enums import Provider, RuleScope, Severity
from app.domain.resource import CloudResource
from app.remediation import RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule


class _RegionalServiceRule(SecurityRule):
    """Shared evaluation for "this service is not on in every enabled region".

    Not a rule itself — absent from the registry, declares no id. It exists so
    two rules do not each grow their own copy of the set arithmetic, and so the
    "we do not know the regions" case is handled identically in both: UNKNOWN,
    never a pass, because "no uncovered regions" is trivially true of an account
    nobody enumerated.
    """

    provider = Provider.AWS
    scope = RuleScope.AGGREGATE
    control_key: str = ""
    service: str = ""

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"{self.service} coverage unavailable: {failure}")

        enabled = set(context.controls.get("enabled_regions") or [])
        if not enabled:
            return RuleResult.unknown("The account's enabled regions are not known")

        covered = set(context.controls.get(self.control_key) or [])
        uncovered = sorted(enabled - covered)
        evidence = {
            "enabled_regions": sorted(enabled),
            "regions_covered": sorted(covered),
            "regions_without": uncovered,
        }
        if not uncovered:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"{self.service} is not enabled in {len(uncovered)} of "
                f"{len(enabled)} enabled regions: {', '.join(uncovered)}"
            ),
        )


class AwsGuardDutyRule(_RegionalServiceRule):
    rule_id = "AWS-POS-001"
    name = "GuardDuty is not enabled in every region"
    description = (
        "One or more enabled regions have no GuardDuty detector, so credential "
        "misuse, cryptomining and reconnaissance in those regions are not "
        "detected at all."
    )
    category = "posture"
    severity = Severity.HIGH
    # Not exploitable. It removes detection, which is what turns a contained
    # incident into one nobody notices until the bill arrives.
    exploitability = 1
    control_key = "guardduty_regions"
    service = "GuardDuty"
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.GUARDDUTY_DETECTORS,
        AwsEvidence.ENABLED_REGIONS,
    )
    estimated_effort_minutes = 20
    rationale = (
        "An attacker who finds an unwatched region will use it. GuardDuty needs "
        "no agents and no configuration, so an unenabled region is almost always "
        "an oversight rather than a decision."
    )
    remediation = (
        "Enable a detector in each region:\n\n"
        "  aws guardduty create-detector --enable --region <region>\n\n"
        "In an organization, delegate administration once and turn on "
        "auto-enable so new accounts and new regions are covered without anyone "
        "remembering:\n"
        "  aws guardduty update-organization-configuration \\\n"
        "    --detector-id <id> --auto-enable-organization-members ALL"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        # Aggregate: a comparison between two sets of regions, which no expected
        # state on an asset can express.
        expected=(),
        cli=("aws guardduty create-detector --enable --region <region>",),
        notes=(
            "Auto-enable at the organization level is the version that stays "
            "true: a per-region command covers the regions enabled today."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.8.16"],
        "NIST_CSF": ["DE.CM-1", "DE.AE-3"],
        "NIST_800_53": ["SI-4"],
        "SOC2": ["CC7.2"],
        "PCI_DSS_4": ["10.2.1"],
    }


class AwsSecurityHubRule(_RegionalServiceRule):
    rule_id = "AWS-POS-002"
    name = "Security Hub is not enabled in every region"
    description = (
        "One or more enabled regions have no Security Hub, so findings from "
        "GuardDuty, Inspector and Config in those regions are aggregated "
        "nowhere."
    )
    category = "posture"
    severity = Severity.MEDIUM
    exploitability = 1
    control_key = "securityhub_regions"
    service = "Security Hub"
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.SECURITYHUB_STATUS,
        AwsEvidence.ENABLED_REGIONS,
    )
    estimated_effort_minutes = 20
    rationale = (
        "Findings that reach nowhere are findings nobody acts on. Security Hub "
        "is where the account's other detectors are meant to arrive, and a "
        "region without it has each of them reporting into its own console."
    )
    remediation = (
        "Enable it per region:\n\n"
        "  aws securityhub enable-security-hub --region <region>\n\n"
        "In an organization, delegate administration and turn on auto-enable so "
        "the answer stays true for accounts and regions added later."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=("aws securityhub enable-security-hub --region <region>",),
        notes=(
            "CloudGuard reads whether the hub exists, not what it holds: it "
            "reaches its own verdicts rather than re-reporting somebody else's."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["4.16"],
        "ISO_27001": ["A.8.16"],
        "NIST_CSF": ["DE.AE-3"],
        "NIST_800_53": ["SI-4"],
        "SOC2": ["CC7.2"],
        "PCI_DSS_4": ["10.5.1"],
    }
