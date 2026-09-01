from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import ExpectedState, RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule


class AzurePublicDatabaseRule(SecurityRule):
    rule_id = "AZ-DB-001"
    name = "Database server publicly accessible"
    description = (
        "A managed database server accepts connections from public networks, or has a "
        "firewall rule permitting the entire internet address range. The database is then "
        "reachable by anyone who can guess or steal a credential."
    )
    category = "database"
    severity = Severity.CRITICAL
    exploitability = 5
    applies_to: ClassVar[list[ResourceType]] = [
        ResourceType.SQL_SERVER,
        ResourceType.POSTGRESQL_SERVER,
    ]
    # Both database listings, because the rule judges servers of both
    # kinds. Named individually rather than as a category so that a
    # future third database service failing does not silently cost this
    # rule a verdict it could still have reached.
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.SQL_SERVERS,
        AzureEvidence.POSTGRESQL_SERVERS,
    )
    estimated_effort_minutes = 30
    rationale = (
        "A database exposed to the internet is a direct route to your data. Credential "
        "stuffing, brute force and any future authentication bypass all become remotely "
        "exploitable, with no network barrier in the way."
    )
    remediation = (
        "Disable public network access and reach the database over a private endpoint.\n\n"
        "Azure Portal: SQL server / PostgreSQL server > Security > Networking > set 'Public "
        "network access' to Disable, then add a Private endpoint on the VNet your "
        "application runs in.\n\n"
        "Azure CLI (SQL):\n"
        "  az sql server update --name <server> --resource-group <rg> \\\n"
        "    --enable-public-network false\n\n"
        "If public access must stay on temporarily, delete any firewall rule spanning "
        "0.0.0.0 to 255.255.255.255 and replace it with the specific addresses that need "
        "access:\n"
        "  az sql server firewall-rule delete --name <rule> --server <server> "
        "--resource-group <rg>\n\n"
        "Note that the 'Allow Azure services' rule (0.0.0.0 to 0.0.0.0) permits connections "
        "from every Azure tenant, not only yours."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="public_network_access",
                equals="Disabled",
                describes="Public network access is disabled",
                # Declared for SQL only. The rule covers PostgreSQL flexible
                # servers as well, and their alias sits under a different
                # provider namespace -- so a single policy generated from this
                # would silently not apply to half the servers the rule judges.
                # The second alias goes in when it has been verified against the
                # published list, not before: an alias that looks plausible and
                # is not real fails the customer's deployment outright, exactly
                # as an invented RBAC action does (``rbac.py``).
                arm_alias="Microsoft.Sql/servers/publicNetworkAccess",
                terraform_attribute="public_network_access_enabled",
                # The provider inverts it: ARM disables, Terraform un-enables.
                terraform_value=False,
            ),
        ),
        cli=(
            "az sql server update --name <server> --resource-group <rg> "
            "--enable-public-network false",
            "az sql server firewall-rule delete --name <rule> --server <server> "
            "--resource-group <rg>",
        ),
        policy_resource_type="Microsoft.Sql/servers",
        notes=(
            "The firewall half of this rule is not expressible as a property "
            "condition -- it is about the contents of a child collection -- so "
            "the generated policy closes public network access and does not "
            "claim to close an over-broad firewall rule."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["4.1.1", "4.1.2"],
        "ISO_27001": ["A.8.20", "A.8.22"],
        "NIST_CSF": ["PR.AC-3", "PR.AC-5", "PR.DS-5"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
    }

    # Azure's own "allow all" firewall shape.
    ALL_ADDRESSES: ClassVar[tuple[str, str]] = ("0.0.0.0", "255.255.255.255")

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Database configuration unavailable: {failure}")

        public_access = resource.get("public_network_access")
        firewall_rules = resource.get("firewall_rules")

        if public_access is None and firewall_rules is None:
            return RuleResult.unknown("Database server configuration missing from snapshot")

        problems = []
        offending: list[dict] = []

        if public_access is not None and str(public_access).lower() == "enabled":
            problems.append("Public network access is enabled")

        for rule in firewall_rules or []:
            start = str(rule.get("start_ip_address", ""))
            end = str(rule.get("end_ip_address", ""))
            if (start, end) == self.ALL_ADDRESSES:
                problems.append(
                    f"Firewall rule '{rule.get('name')}' allows the entire internet"
                )
                offending.append(rule)
            elif start == "0.0.0.0" and end == "0.0.0.0":
                # Azure's "Allow Azure services" shortcut -- every Azure tenant,
                # not just this one.
                problems.append(
                    f"Firewall rule '{rule.get('name')}' allows all Azure services, "
                    "including other tenants"
                )
                offending.append(rule)

        evidence = {
            "public_network_access": public_access,
            "firewall_rule_count": len(firewall_rules or []),
            "offending_firewall_rules": offending,
            "private_endpoints": resource.get("private_endpoints", []),
        }

        # Public access enabled but locked down by specific firewall rules is a
        # defensible design; public access plus an open rule is not.
        if not offending and public_access is not None and str(public_access).lower() != "enabled":
            return RuleResult.passed(evidence)
        if not offending and not problems:
            return RuleResult.passed(evidence)
        if not offending:
            # Public access on, no explicit internet-wide rule found.
            if not firewall_rules:
                return RuleResult.failed(
                    evidence={**evidence, "problems": problems},
                    message=(
                        f"{resource.name} accepts public network connections with no "
                        "firewall rules restricting the source"
                    ),
                )
            return RuleResult.passed(
                {**evidence, "note": "Public access is restricted by explicit firewall rules"}
            )

        return RuleResult.failed(
            evidence={**evidence, "problems": problems},
            message=f"{resource.name} is reachable from the internet: {'; '.join(problems)}",
        )
