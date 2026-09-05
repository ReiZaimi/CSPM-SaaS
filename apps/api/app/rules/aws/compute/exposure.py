"""Compute rules: what an instance hands over to whatever runs on it."""

from typing import ClassVar

from app.connectors.aws.evidence import AwsEvidence
from app.core.enums import Provider, ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import ExpectedState, RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule


class AwsInstanceMetadataRule(SecurityRule):
    rule_id = "AWS-CMP-002"
    name = "Instance metadata is reachable without a session token"
    description = (
        "An EC2 instance still accepts IMDSv1 requests. Any request that can be "
        "made through the instance — a server-side request forgery in an "
        "application on it, a misconfigured proxy — reads the instance role's "
        "credentials from the metadata service."
    )
    category = "compute"
    provider = Provider.AWS
    severity = Severity.HIGH
    # Not reachable from the internet on its own: it needs a flaw in something
    # running on the instance. That flaw is common enough, and the payoff is
    # complete -- the role's credentials, usable from anywhere.
    exploitability = 3
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.VIRTUAL_MACHINE]
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.EC2_INSTANCES,
    )
    estimated_effort_minutes = 15
    rationale = (
        "IMDSv1 answers any request that reaches it. IMDSv2 requires a PUT to "
        "obtain a token first, which an SSRF generally cannot make — turning the "
        "single most productive step in a cloud intrusion into a dead end."
    )
    remediation = (
        "Require a session token on the instance:\n\n"
        "  aws ec2 modify-instance-metadata-options --instance-id <id> \\\n"
        "    --http-tokens required --http-endpoint enabled\n\n"
        "It takes effect immediately and needs no restart. Anything using the "
        "metadata service through a current AWS SDK already speaks IMDSv2; the "
        "usual thing that breaks is a hand-written curl in a startup script.\n\n"
        "Set the account default so new instances arrive this way:\n"
        "  aws ec2 modify-instance-metadata-defaults --http-tokens required"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="imdsv2_required",
                equals=True,
                describes="The metadata service requires a session token (IMDSv2)",
                terraform_attribute="metadata_options.http_tokens",
            ),
        ),
        cli=(
            "aws ec2 modify-instance-metadata-options --instance-id <id> "
            "--http-tokens required --http-endpoint enabled",
        ),
        notes=(
            "Preventive enforcement on AWS would be an AWS Config rule or an "
            "SCP. Neither is generated yet."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["5.6"],
        "ISO_27001": ["A.8.2"],
        "NIST_CSF": ["PR.AC-1"],
        "NIST_800_53": ["AC-6"],
        "SOC2": ["CC6.1"],
        "PCI_DSS_4": ["7.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Instance configuration unavailable: {failure}")

        required = resource.get("imdsv2_required")
        if required is None:
            return RuleResult.unknown("Metadata options missing from snapshot")

        evidence = {
            "imdsv2_required": required,
            "state": (resource.get("State") or {}).get("Name"),
            "region": resource.region,
        }
        if required:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} still accepts IMDSv1 metadata requests",
        )
