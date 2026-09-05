"""RDS rules: who can reach the database, and whether what it holds is encrypted."""

from typing import ClassVar

from app.connectors.aws.evidence import AwsEvidence
from app.core.enums import Provider, ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import ExpectedState, RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule

RDS_TYPES: list[ResourceType] = [
    ResourceType.SQL_SERVER,
    ResourceType.POSTGRESQL_SERVER,
]


class AwsPublicDatabaseRule(SecurityRule):
    rule_id = "AWS-DB-001"
    name = "RDS instance is publicly accessible"
    description = (
        "An RDS instance is marked publicly accessible, so it is given a public "
        "endpoint and can be reached from outside the VPC by anyone the security "
        "group allows."
    )
    category = "database"
    provider = Provider.AWS
    severity = Severity.CRITICAL
    exploitability = 4
    applies_to: ClassVar[list[ResourceType]] = RDS_TYPES
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.RDS_INSTANCES,
    )
    estimated_effort_minutes = 30
    rationale = (
        "A publicly addressable database turns a leaked or weak credential into direct "
        "access to the data. Nothing else stands in the way."
    )
    remediation = (
        "Turn off public accessibility. The instance keeps its private endpoint, so "
        "anything inside the VPC is unaffected.\n\n"
        "AWS CLI:\n"
        "  aws rds modify-db-instance --db-instance-identifier <id> \\\n"
        "    --no-publicly-accessible --apply-immediately\n\n"
        "Reach it from outside through a bastion, a VPN, or RDS Proxy in a private "
        "subnet. Check the security group afterwards: turning this off removes the "
        "public address, not the ingress rule that pointed at it."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="publicly_accessible",
                equals=False,
                describes="The instance has no public endpoint",
                terraform_attribute="publicly_accessible",
            ),
        ),
        cli=(
            "aws rds modify-db-instance --db-instance-identifier <id> "
            "--no-publicly-accessible --apply-immediately",
        ),
        notes=(
            "Preventive enforcement on AWS would be an AWS Config rule or an "
            "SCP. Neither is generated yet."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["2.3.3"],
        "ISO_27001": ["A.8.20", "A.8.23"],
        "NIST_CSF": ["PR.AC-3", "PR.DS-5"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["SC-7", "AC-3"],
        "SOC2": ["CC6.1", "CC6.6"],
        "PCI_DSS_4": ["1.3.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"RDS configuration unavailable: {failure}")

        public = resource.get("publicly_accessible")
        if public is None:
            return RuleResult.unknown("RDS accessibility missing from snapshot")

        evidence = {
            "publicly_accessible": public,
            "engine": resource.get("Engine"),
            "region": resource.region,
            "endpoint": (resource.get("Endpoint") or {}).get("Address"),
        }
        if not public:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} is publicly accessible",
        )


class AwsDatabaseEncryptionRule(SecurityRule):
    rule_id = "AWS-DB-002"
    name = "RDS storage is not encrypted"
    description = (
        "An RDS instance stores its data unencrypted. Its automated backups and "
        "snapshots are unencrypted too, and neither can be encrypted afterwards "
        "without recreating the instance."
    )
    category = "database"
    provider = Provider.AWS
    severity = Severity.HIGH
    exploitability = 1
    applies_to: ClassVar[list[ResourceType]] = RDS_TYPES
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.RDS_INSTANCES,
    )
    # Honest rather than optimistic: encryption cannot be switched on in place.
    # Fixing this means a snapshot, an encrypted copy, a restore and a cutover.
    estimated_effort_minutes = 180
    rationale = (
        "Encryption at rest is what stands between a copied snapshot or a decommissioned "
        "volume and the data on it. It costs nothing to run and cannot be added later "
        "without recreating the instance, which is why an unencrypted instance is worth "
        "raising even though nothing is reachable through it today."
    )
    remediation = (
        "Encryption cannot be enabled in place. Recreate the instance from an "
        "encrypted snapshot copy:\n\n"
        "  aws rds create-db-snapshot --db-instance-identifier <id> "
        "--db-snapshot-identifier <snap>\n"
        "  aws rds copy-db-snapshot --source-db-snapshot-identifier <snap> \\\n"
        "    --target-db-snapshot-identifier <snap-encrypted> --kms-key-id <key>\n"
        "  aws rds restore-db-instance-from-db-snapshot \\\n"
        "    --db-instance-identifier <new-id> --db-snapshot-identifier <snap-encrypted>\n\n"
        "Then cut over and delete the original. Set the account-level default so new "
        "instances are encrypted without anyone remembering to ask."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="storage_encrypted",
                equals=True,
                describes="The instance's storage is encrypted at rest",
                terraform_attribute="storage_encrypted",
            ),
        ),
        cli=(
            "aws rds copy-db-snapshot --source-db-snapshot-identifier <snap> "
            "--target-db-snapshot-identifier <snap-encrypted> --kms-key-id <key>",
            "aws rds restore-db-instance-from-db-snapshot "
            "--db-instance-identifier <new-id> "
            "--db-snapshot-identifier <snap-encrypted>",
        ),
        notes=(
            "Encryption cannot be enabled in place, so the CLI above recreates "
            "the instance rather than modifying it. Preventive enforcement "
            "would be an AWS Config rule or an SCP; neither is generated yet."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["2.3.1"],
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
            return RuleResult.unknown(f"RDS configuration unavailable: {failure}")

        encrypted = resource.get("storage_encrypted")
        if encrypted is None:
            return RuleResult.unknown("RDS encryption setting missing from snapshot")

        evidence = {
            "storage_encrypted": encrypted,
            "kms_key_id": resource.get("KmsKeyId"),
            "engine": resource.get("Engine"),
            "region": resource.region,
        }
        if encrypted:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} stores its data unencrypted",
        )


class AwsDatabasePatchingRule(SecurityRule):
    rule_id = "AWS-DB-003"
    name = "RDS instance does not take minor version upgrades"
    description = (
        "An RDS instance has automatic minor version upgrades switched off, so "
        "engine security patches are applied only when somebody remembers."
    )
    category = "database"
    provider = Provider.AWS
    severity = Severity.MEDIUM
    # Nothing to exploit directly. It is the mechanism that keeps the engine's
    # own vulnerabilities from accumulating, and turning it off is how a
    # database ends up years behind.
    exploitability = 2
    applies_to: ClassVar[list[ResourceType]] = RDS_TYPES
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.RDS_INSTANCES,
    )
    estimated_effort_minutes = 10
    rationale = (
        "Minor versions carry the engine's security fixes and are backwards "
        "compatible by definition. Off, they wait for a maintenance window "
        "somebody has to schedule — which in practice is how a database ends up "
        "several years behind on published vulnerabilities."
    )
    remediation = (
        "Turn it on and let it apply in the maintenance window:\n\n"
        "  aws rds modify-db-instance --db-instance-identifier <id> \\\n"
        "    --auto-minor-version-upgrade --apply-immediately\n\n"
        "Set the maintenance window to a time you are happy to take a brief "
        "failover; the upgrade itself is the same operation you would run by "
        "hand, on a schedule instead of on a reminder."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="auto_minor_version_upgrade",
                equals=True,
                describes="Minor engine versions are applied automatically",
                terraform_attribute="auto_minor_version_upgrade",
            ),
        ),
        cli=(
            "aws rds modify-db-instance --db-instance-identifier <id> "
            "--auto-minor-version-upgrade --apply-immediately",
        ),
        notes=(
            "Applied in the maintenance window, which is worth setting to a "
            "time a brief failover is acceptable."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["2.3.2"],
        "ISO_27001": ["A.8.8"],
        "NIST_CSF": ["ID.RA-1"],
        "NIST_800_53": ["SI-2"],
        "SOC2": ["CC7.1"],
        "PCI_DSS_4": ["6.3.3"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"RDS configuration unavailable: {failure}")

        automatic = resource.get("auto_minor_version_upgrade")
        if automatic is None:
            return RuleResult.unknown("Upgrade setting missing from snapshot")

        evidence = {
            "auto_minor_version_upgrade": automatic,
            "engine": resource.get("Engine"),
            "engine_version": resource.get("EngineVersion"),
            "region": resource.region,
        }
        if automatic:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} does not take minor version upgrades",
        )
