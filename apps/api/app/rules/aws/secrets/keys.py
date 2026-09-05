"""KMS rules. The key's configuration, never its material."""

from typing import ClassVar

from app.connectors.aws.evidence import AwsEvidence
from app.core.enums import Provider, ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import ExpectedState, RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule


class AwsKeyRotationRule(SecurityRule):
    rule_id = "AWS-SEC-001"
    name = "A customer-managed key does not rotate"
    description = (
        "A KMS key the customer manages has automatic rotation switched off, so "
        "the same key material protects everything it has ever encrypted."
    )
    category = "secrets"
    provider = Provider.AWS
    severity = Severity.MEDIUM
    # Not a way in. It is what bounds the damage when key material is exposed:
    # without rotation, one exposure covers the whole history of the key.
    exploitability = 1
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.KEY_VAULT]
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (AwsEvidence.KMS_KEYS,)
    estimated_effort_minutes = 5
    rationale = (
        "Rotation is one call and costs nothing: AWS keeps the old material so "
        "existing ciphertext stays readable, and new writes use the new key. "
        "Without it, material exposed once covers everything the key has ever "
        "protected."
    )
    remediation = (
        "Turn annual rotation on:\n\n"
        "  aws kms enable-key-rotation --key-id <key-id>\n\n"
        "Nothing has to be re-encrypted. AWS retains previous material so old "
        "ciphertext still decrypts; only new encryption uses the new key."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="rotation_enabled",
                equals=True,
                describes="Automatic annual key rotation is enabled",
                terraform_attribute="enable_key_rotation",
            ),
        ),
        cli=("aws kms enable-key-rotation --key-id <key-id>",),
        # Only about keys the customer controls. An AWS-managed key rotates on
        # AWS's schedule and cannot be configured, so a rule that judged one
        # would raise a finding nobody can act on.
        applies_when={"customer_managed": True},
        notes=(
            "Preventive enforcement on AWS would be an AWS Config rule or an "
            "SCP. Neither is generated yet."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["3.6"],
        "ISO_27001": ["A.8.24"],
        "NIST_CSF": ["PR.DS-1"],
        "NIST_800_53": ["SC-12"],
        "SOC2": ["CC6.1"],
        "PCI_DSS_4": ["3.6.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Key configuration unavailable: {failure}")

        # An AWS-managed key rotates on AWS's schedule and cannot be
        # configured. Judging one would raise a finding nobody can act on.
        if not resource.get("customer_managed"):
            return RuleResult.not_applicable(
                f"{resource.name} is managed by AWS, not by this account"
            )

        rotating = resource.get("rotation_enabled")
        if rotating is None:
            return RuleResult.unknown("Key rotation state missing from snapshot")

        evidence = {
            "rotation_enabled": rotating,
            "key_state": resource.get("KeyState"),
            "region": resource.region,
        }
        if rotating:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} does not rotate automatically",
        )
