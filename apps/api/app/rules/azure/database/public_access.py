from typing import ClassVar

from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
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
    requires_collection: ClassVar[list[str]] = ["database"]
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

        failure = context.has_collection_error(*self.requires_collection)
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
