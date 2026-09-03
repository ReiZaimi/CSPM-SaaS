from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import Level, ResourceType, Severity
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
        "NIST_800_53": ["SC-7", "AC-3"],
        "SOC2": ["CC6.1", "CC6.6"],
        "PCI_DSS_4": ["1.3.1", "7.2.1"],
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

        # Whose internet. A rule spanning 0.0.0.0-255.255.255.255 puts the
        # server in front of everyone, which is the class tag. Azure's "allow
        # all Azure services" shortcut (0.0.0.0-0.0.0.0) puts it in front of
        # every Azure tenant -- a serious and frequently unintended gap, and
        # still an attacker who needs a subscription and a credential rather
        # than a scanner and an afternoon.
        azure_services_only = all(
            (str(r.get("start_ip_address", "")), str(r.get("end_ip_address", "")))
            == ("0.0.0.0", "0.0.0.0")
            for r in offending
        )

        return RuleResult.failed(
            evidence={**evidence, "problems": problems},
            exploitability=3 if azure_services_only else None,
            message=f"{resource.name} is reachable from the internet: {'; '.join(problems)}",
        )


class AzureDatabasePrivateConnectivityRule(SecurityRule):
    rule_id = "AZ-DB-002"
    name = "Sensitive database has no private connectivity"
    description = (
        "A database server holding sensitive data is reached over its public endpoint "
        "rather than through a private endpoint. Access is then controlled by a "
        "firewall list alone, and one wrong entry in that list is the whole database."
    )
    category = "database"
    severity = Severity.MEDIUM
    # Defence in depth rather than an opening. The firewall may well be correct
    # today; what is missing is the layer that would still hold if it were not.
    exploitability = 2
    applies_to: ClassVar[list[ResourceType]] = [
        ResourceType.SQL_SERVER,
        ResourceType.POSTGRESQL_SERVER,
    ]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.SQL_SERVERS,
        AzureEvidence.POSTGRESQL_SERVERS,
    )
    estimated_effort_minutes = 90
    rationale = (
        "A firewall allow-list is a single control with a single failure mode: somebody "
        "widens it. It is widened during an incident, during a migration, and by "
        "whoever is on call at three in the morning -- and the widening is invisible "
        "until someone audits it. A private endpoint removes the public route "
        "altogether, so a mistaken firewall entry stops being a data breach."
    )
    remediation = (
        "Put the server behind a private endpoint and turn its public endpoint off.\n\n"
        "Create the private endpoint in the virtual network the clients sit in, confirm "
        "name resolution through the private DNS zone, move the clients over, and only "
        "then disable public network access -- in that order, or the clients lose the "
        "database before they have the new route.\n\n"
        "Azure CLI:\n"
        "  az network private-endpoint create --resource-group <rg> --name <pe> \\\n"
        "    --vnet-name <vnet> --subnet <subnet> \\\n"
        "    --private-connection-resource-id <server-id> --group-id sqlServer \\\n"
        "    --connection-name <conn>\n"
        "  az sql server update --name <server> --resource-group <rg> \\\n"
        "    --enable-public-network false"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="public_network_access",
                equals="Disabled",
                describes="The server's public endpoint is turned off",
                terraform_attribute="public_network_access_enabled",
            ),
        ),
        # Who the expectation is about. Stated so a reader knows this is not a
        # demand on every database, and so a test builds an asset the rule will
        # actually judge rather than one it declines.
        applies_when={"data_sensitivity": Level.HIGH},
        cli=(
            "az network private-endpoint create --resource-group <rg> --name <pe> "
            "--vnet-name <vnet> --subnet <subnet> "
            "--private-connection-resource-id <server-id> --group-id sqlServer "
            "--connection-name <conn>",
            "az sql server update --name <server> --resource-group <rg> "
            "--enable-public-network false",
        ),
        notes=(
            "No policy is generated. Denying public network access at creation would "
            "block every deployment that has not yet built its private endpoint, and "
            "the endpoint is a separate resource in a separate network -- so the "
            "preventive form of this is a landing-zone decision rather than a rule on "
            "the server."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["4.1.1", "4.1.2"],
        "ISO_27001": ["A.8.20", "A.8.22"],
        "NIST_CSF": ["PR.AC-5", "PR.DS-5"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
        "NIST_800_53": ["SC-7"],
        "SOC2": ["CC6.6"],
        "PCI_DSS_4": ["1.3.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Database configuration unavailable: {failure}")

        # Scoped to databases that hold something worth this much work. A
        # development server behind a correct firewall does not need a private
        # endpoint, and raising it there is how a real finding gets lost among
        # the ones nobody was going to act on.
        if resource.data_sensitivity not in (Level.HIGH, Level.CRITICAL):
            return RuleResult.not_applicable(
                "Data sensitivity is not high enough to require private connectivity"
            )

        public_access = resource.get("public_network_access")
        private_endpoints = resource.get("private_endpoints")

        if public_access is None and private_endpoints is None:
            return RuleResult.unknown(
                "Database server connectivity configuration missing from snapshot"
            )

        has_private = bool(private_endpoints)
        public_on = str(public_access or "").lower() == "enabled"

        evidence = {
            "public_network_access": public_access,
            "private_endpoint_count": len(private_endpoints or []),
            "data_sensitivity": resource.data_sensitivity.value,
        }

        # The public endpoint being off is the outcome this rule wants, however
        # it was reached. A server nothing can dial is not waiting on a private
        # endpoint to be safe.
        if not public_on:
            return RuleResult.passed(evidence)
        if has_private:
            # Both routes exist. Worth narrowing eventually, and not this
            # finding: the private path is built, and what is left is turning
            # the public one off.
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"{resource.name} holds sensitive data and is reachable only over its "
                "public endpoint, with no private endpoint configured"
            ),
        )


class AzureDatabaseAuditingRule(SecurityRule):
    rule_id = "AZ-DB-003"
    name = "Database server keeps no audit trail"
    description = (
        "A SQL server has auditing turned off, or is auditing to nowhere. There is no "
        "record of who connected, what they queried, or what they took."
    )
    category = "database"
    severity = Severity.MEDIUM
    # Exploitable by nobody, like every logging gap. What it removes is the
    # ability to answer the question a breach ends on -- what did they read --
    # and for a database that question is the whole incident.
    exploitability = 1
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.SQL_SERVER]
    # Both, and the pair is the point. Without the server listing there are no
    # servers to judge; without the auditing read there is no audit posture to
    # judge them on. They fail independently -- a role predating v4 reads the
    # first perfectly well and is refused the second -- which is exactly why
    # they are separate keys, so that refusal costs this rule its verdict and
    # costs AZ-DB-001 nothing.
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.SQL_SERVERS,
        AzureEvidence.SQL_AUDITING,
    )
    estimated_effort_minutes = 45
    rationale = (
        "Auditing is off by default on every Azure SQL server, so this is a setting "
        "most customers have never turned on rather than one they turned off. Without "
        "it, a database breach is unbounded by evidence: there is no way to tell "
        "whether an attacker read one row or every row, and regulators treating the "
        "two the same is the expensive outcome.\n\n"
        "It matters most on exactly the servers that are also reachable — a public "
        "endpoint with no audit trail is the worst pairing in this catalogue, and "
        "AZ-DB-001 will be raising the other half of it."
    )
    remediation = (
        "Turn auditing on and send it somewhere that outlives the server.\n\n"
        "Azure Portal: SQL server > Security > Auditing > Enable Azure SQL Auditing > "
        "choose Log Analytics (or a storage account) > Save. Setting it at the server "
        "covers every database on it, which is why this check is on the server rather "
        "than per database.\n\n"
        "Azure CLI:\n"
        "  az sql server audit-policy update --name <server> --resource-group <rg> \\\n"
        "    --state Enabled --log-analytics-target-state Enabled \\\n"
        "    --log-analytics-workspace-resource-id <workspace-id>\n\n"
        "Retention is the part people miss: a storage account destination keeps "
        "records for the days you set and no longer, and breaches are found months "
        "late."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "az sql server audit-policy show --name <server> --resource-group <rg>",
            "az sql server audit-policy update --name <server> --resource-group <rg> "
            "--state Enabled --log-analytics-target-state Enabled "
            "--log-analytics-workspace-resource-id <workspace-id>",
        ),
        notes=(
            "No expected state, because this rule checks two things about one nested "
            "setting -- that auditing is on, and that it writes somewhere -- and the "
            "three comparisons a declaration may use express neither. A declaration "
            "saying only 'state is Enabled' would be worse than none: a customer would "
            "satisfy exactly what they were shown, still be auditing to nowhere, and "
            "watch the finding stay open.\n\n"
            "No policy either. Azure Policy can deploy an auditing setting through "
            "DeployIfNotExists, and it needs a destination workspace chosen per "
            "environment -- a landing-zone assignment rather than something this rule "
            "can generate without inventing where the customer's logs should go."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["4.1.1", "5.1.1"],
        "ISO_27001": ["A.8.15", "A.8.16"],
        "NIST_CSF": ["PR.PT-1", "DE.AE-3"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
        "NIST_800_53": ["AU-2", "SI-4"],
        "SOC2": ["CC7.2"],
        "PCI_DSS_4": ["10.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Database configuration unavailable: {failure}")

        auditing = resource.get("auditing")
        if auditing is None:
            # The per-server call failed, or the deployed role predates v4 and
            # answered 403. Either way this server's audit posture was not read,
            # and a server we could not ask is not a server without auditing.
            return RuleResult.unknown(
                "The server's auditing settings could not be read. If this persists, "
                "the deployed scanner role may predate the permission that reads them."
            )

        state = str(auditing.get("state") or "").lower()
        storage = auditing.get("storage_endpoint")
        log_analytics = auditing.get("log_analytics_enabled")

        evidence = {
            "auditing_state": auditing.get("state"),
            "retention_days": auditing.get("retention_days"),
            "storage_endpoint": storage,
            "log_analytics_enabled": log_analytics,
            "public_network_access": resource.get("public_network_access"),
        }

        if state != "enabled":
            return RuleResult.failed(
                evidence={**evidence, "problems": ["Auditing is not enabled"]},
                message=(
                    f"{resource.name} keeps no record of who connects to it or what "
                    "they query"
                ),
            )

        # Enabled with nowhere to write is the setting people believe they have
        # and do not. It is worth separating from off, because the fix is
        # different: one is a switch, the other is a destination.
        if not storage and log_analytics is not True:
            return RuleResult.failed(
                evidence={
                    **evidence,
                    "problems": ["Auditing is enabled but has no destination"],
                },
                message=(
                    f"Auditing is switched on for {resource.name} but writes nowhere, "
                    "so nothing is being kept"
                ),
            )

        return RuleResult.passed(evidence)
