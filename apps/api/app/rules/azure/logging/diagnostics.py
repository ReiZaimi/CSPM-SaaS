from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import Level, ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import Comparison, ExpectedState, RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule

# What "critical" means here. HIGH and CRITICAL only: MEDIUM is where an
# untagged, undeclared resource lands, and logging every one of those would make
# this a catalogue-wide requirement rather than a statement about the assets a
# customer said matter.
_CRITICAL_LEVELS = frozenset({Level.HIGH, Level.CRITICAL})


class AzureLoggingRule(SecurityRule):
    rule_id = "AZ-LOG-001"
    name = "Diagnostic logging not configured"
    description = (
        "A security-relevant resource has no diagnostic setting forwarding its logs to a "
        "Log Analytics workspace, storage account or event hub. Without those logs there is "
        "no record of what happened on this resource."
    )
    category = "logging"
    severity = Severity.MEDIUM
    exploitability = 1
    applies_to: ClassVar[list[ResourceType]] = [
        ResourceType.STORAGE_ACCOUNT,
        ResourceType.SQL_SERVER,
        ResourceType.POSTGRESQL_SERVER,
        ResourceType.NETWORK_SECURITY_GROUP,
    ]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.DIAGNOSTIC_SETTINGS,
    )
    estimated_effort_minutes = 120
    rationale = (
        "Logging does not prevent an incident, but without it you cannot detect one, scope "
        "it, or prove what an attacker did or did not reach. It is the difference between "
        "'we were breached' and 'we were breached, and here is exactly what they touched'."
    )
    remediation = (
        "Send this resource's diagnostic logs to a Log Analytics workspace.\n\n"
        "Azure Portal: select the resource > Monitoring > Diagnostic settings > Add "
        "diagnostic setting > tick the audit/security log categories > choose 'Send to Log "
        "Analytics workspace' > Save.\n\n"
        "Azure CLI:\n"
        "  az monitor diagnostic-settings create --name security-logs \\\n"
        "    --resource <resource-id> --workspace <workspace-id> \\\n"
        "    --logs '[{\"categoryGroup\":\"audit\",\"enabled\":true}]'\n\n"
        "Apply this at scale with an Azure Policy 'DeployIfNotExists' assignment rather than "
        "resource by resource."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="diagnostic_settings",
                comparison=Comparison.NOT_EMPTY,
                equals=None,
                describes=(
                    "At least one diagnostic setting sends this resource's logs "
                    "to a workspace, storage account or event hub"
                ),
                # A setting with no destination is not a setting for this
                # purpose, which is why the witness carries one: the rule reads
                # past the count to where the logs actually go.
                example={
                    "name": "<setting>",
                    "workspace_id": "<log analytics workspace resource id>",
                },
            ),
        ),
        cli=(
            "az monitor diagnostic-settings create --name send-to-la "
            "--resource <resource id> --workspace <workspace id> "
            '--logs \'[{"categoryGroup":"allLogs","enabled":true}]\'',
        ),
        notes=(
            "No policy is generated here, and the reason is different from the "
            "network rules': a diagnostic setting is created rather than "
            "configured, so the artifact would be a DeployIfNotExists policy "
            "with a remediation task and a managed identity behind it. That is "
            "a deployment CloudGuard would be asking a customer to trust, not a "
            "condition -- and it is worth building deliberately rather than "
            "generating from a one-line declaration."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["5.1.1", "5.3"],
        "ISO_27001": ["A.8.15", "A.8.16"],
        "NIST_CSF": ["DE.AE-3", "PR.PT-1"],
        "GDPR": ["5(2)", "32(1)(d)", "33"],
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
            return RuleResult.unknown(f"Diagnostic settings unavailable: {failure}")

        settings = resource.get("diagnostic_settings")
        if settings is None:
            return RuleResult.unknown("Diagnostic settings were not collected for this resource")

        active = [
            s
            for s in settings
            if s.get("workspace_id") or s.get("storage_account_id") or s.get("event_hub_id")
        ]

        evidence = {
            "diagnostic_setting_count": len(settings),
            "destinations": [
                {
                    "name": s.get("name"),
                    "workspace": bool(s.get("workspace_id")),
                    "storage": bool(s.get("storage_account_id")),
                    "event_hub": bool(s.get("event_hub_id")),
                }
                for s in settings
            ],
        }

        if active:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} has no diagnostic setting sending logs anywhere",
        )


class AzureActivityLogExportRule(SecurityRule):
    rule_id = "AZ-LOG-002"
    name = "Subscription activity log is not exported"
    description = (
        "The subscription's activity log is not being sent anywhere. It records every "
        "control-plane action -- who created, changed or deleted what -- and Azure "
        "keeps it for 90 days by default, after which it is gone."
    )
    category = "logging"
    severity = Severity.MEDIUM
    # Exploitable by nobody. What it removes is the ability to answer questions
    # afterwards, and an attacker who deletes what they touched leaves nothing
    # behind at all.
    exploitability = 1
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.SUBSCRIPTION]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.DIAGNOSTIC_SETTINGS,
    )
    estimated_effort_minutes = 60
    rationale = (
        "This is the log an investigation starts from, and the one that answers the "
        "question every incident ends on: what else did they touch. Per-resource "
        "logging says what happened *to* a resource; the activity log says who did it, "
        "from where, and what else they did in the same hour -- including to resources "
        "that no longer exist, which are the ones that matter most.\n\n"
        "The 90-day default is the real problem. Breaches are found months late, and a "
        "log that has already rolled over cannot be recovered by noticing."
    )
    remediation = (
        "Export the activity log to a Log Analytics workspace.\n\n"
        "Azure Portal: Monitor > Activity log > Export Activity Logs > Add diagnostic "
        "setting > tick Administrative, Security and Policy at minimum > Send to Log "
        "Analytics workspace > Save.\n\n"
        "Azure CLI:\n"
        "  az monitor diagnostic-settings subscription create \\\n"
        "    --name activity-log-export --location <region> \\\n"
        "    --workspace <workspace-id> \\\n"
        "    --logs '[{\"category\":\"Administrative\",\"enabled\":true},"
        "{\"category\":\"Security\",\"enabled\":true},"
        "{\"category\":\"Policy\",\"enabled\":true}]'\n\n"
        "Set the workspace retention to match how long you would want to investigate "
        "backwards -- the export is what makes retention yours to choose rather than "
        "Azure's."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="diagnostic_settings",
                comparison=Comparison.NOT_EMPTY,
                equals=None,
                describes=(
                    "A subscription diagnostic setting sends the activity log to a "
                    "workspace, storage account or event hub"
                ),
                example={
                    "name": "activity-log-export",
                    "workspace_id": "/subscriptions/<sub>/resourceGroups/<rg>"
                    "/providers/Microsoft.OperationalInsights/workspaces/<workspace>",
                },
            ),
        ),
        cli=(
            "az monitor diagnostic-settings subscription create "
            "--name activity-log-export --location <region> --workspace <workspace-id> "
            "--logs '[{\"category\":\"Administrative\",\"enabled\":true},"
            "{\"category\":\"Security\",\"enabled\":true}]'",
        ),
        notes=(
            "No policy is generated. A subscription diagnostic setting is not a "
            "property of a resource type Azure Policy evaluates, so the preventive "
            "form of this is a landing-zone assignment at the management group rather "
            "than a rule on the subscription."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["5.1.1", "5.3"],
        "ISO_27001": ["A.8.15", "A.8.16"],
        "NIST_CSF": ["PR.PT-1", "DE.AE-3"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
        "NIST_800_53": ["AU-2", "AU-11", "SI-4"],
        "SOC2": ["CC7.1", "CC7.2"],
        "PCI_DSS_4": ["10.2.1", "10.5.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Diagnostic settings unavailable: {failure}")

        settings = resource.get("diagnostic_settings")
        if settings is None:
            # The collector records the string 'error: ...' per resource it
            # could not read, and the normalizer turns that into None. A
            # subscription whose settings could not be read is not one without
            # them.
            return RuleResult.unknown(
                "The subscription's diagnostic settings could not be read"
            )

        # A setting with no destination exports nothing. Counting it would let
        # an empty shell of a setting answer this rule.
        exporting = [
            s
            for s in settings
            if s.get("workspace_id") or s.get("storage_account_id") or s.get("event_hub_id")
        ]

        evidence = {
            "diagnostic_settings": settings,
            "exporting_setting_count": len(exporting),
            "destinations": [
                s.get("workspace_id") or s.get("storage_account_id") or s.get("event_hub_id")
                for s in exporting
            ],
        }

        if exporting:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=(
                "The activity log for this subscription is not exported anywhere, so "
                "the record of who changed what is kept for 90 days and then lost"
            ),
        )


class AzureCriticalResourceLoggingRule(SecurityRule):
    """The same question as AZ-LOG-001, asked of the resources it does not cover.

    Deliberately disjoint from it. AZ-LOG-001 judges storage accounts, database
    servers and network security groups; this judges key vaults and virtual
    machines, and only where the estate says the asset matters. Overlapping the
    two would raise two findings for one missing diagnostic setting, which is a
    second row to close and a second deduction from the security score for one
    piece of work.
    """

    rule_id = "AZ-LOG-004"
    name = "Critical resource keeps no record of what happens to it"
    description = (
        "A business-critical or sensitive resource has no diagnostic setting sending its "
        "logs anywhere. For a key vault that means no record of which identity read which "
        "secret; for a machine it means no record of what ran on it. Neither can be "
        "reconstructed afterwards -- the events are not stored and then discarded, they are "
        "never written."
    )
    category = "logging"
    severity = Severity.MEDIUM
    exploitability = 1
    applies_to: ClassVar[list[ResourceType]] = [
        ResourceType.KEY_VAULT,
        ResourceType.VIRTUAL_MACHINE,
    ]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.DIAGNOSTIC_SETTINGS,
    )
    estimated_effort_minutes = 90
    rationale = (
        "The value of a log is decided before the incident, not during it. On the assets "
        "that matter most, the absence of one turns every question an investigator asks -- "
        "what was read, by whom, when it started -- into an answer nobody can give, and "
        "turns a bounded incident into a disclosure with no scope."
    )
    remediation = (
        "Send this resource's diagnostic logs to a Log Analytics workspace.\n\n"
        "Azure Portal: select the resource > Monitoring > Diagnostic settings > Add "
        "diagnostic setting > tick the audit and security categories > Send to Log "
        "Analytics workspace > Save.\n\n"
        "Azure CLI:\n"
        "  az monitor diagnostic-settings create --name security-logs \\\n"
        "    --resource <resource-id> --workspace <workspace-id> \\\n"
        "    --logs '[{\"categoryGroup\":\"audit\",\"enabled\":true}]'\n\n"
        "Do it once across the estate with an Azure Policy assignment that deploys the "
        "setting, rather than per resource: the resources created next month are the ones "
        "a manual pass will miss."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="diagnostic_settings",
                comparison=Comparison.NOT_EMPTY,
                equals=None,
                describes="The resource sends its logs to a destination that keeps them",
                example={"name": "security-logs", "workspace_id": "<workspace>"},
            ),
        ),
        cli=(
            "az monitor diagnostic-settings create --name security-logs "
            "--resource <resource-id> --workspace <workspace-id> "
            "--logs '[{\"categoryGroup\":\"audit\",\"enabled\":true}]'",
        ),
        notes=(
            "Azure Policy has built-in DeployIfNotExists definitions that add "
            "diagnostic settings per resource type. None is generated here: the "
            "policy needs a workspace id that is this customer's own, and a "
            "generated definition naming a placeholder would deploy nothing."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["5.3", "5.1.1"],
        "ISO_27001": ["A.8.15", "A.8.16"],
        "NIST_CSF": ["PR.PT-1", "DE.AE-3", "DE.CM-1"],
        "GDPR": ["30", "32(1)(d)", "33"],
        "NIST_800_53": ["AU-2", "AU-6"],
        "SOC2": ["CC7.2", "CC7.3"],
        "PCI_DSS_4": ["10.2.1", "10.3.2"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Diagnostic settings unavailable: {failure}")

        # A key vault is critical whatever anybody declared -- it holds the
        # credentials to everything else, which is why the context engine gives
        # it a floor rather than an inference. A machine is judged on what the
        # estate says about it.
        matters = resource.resource_type == ResourceType.KEY_VAULT or bool(
            _CRITICAL_LEVELS & {resource.criticality, resource.data_sensitivity}
        )
        if not matters:
            return RuleResult.not_applicable(
                "This resource is not marked business-critical or sensitive"
            )

        settings = resource.get("diagnostic_settings")
        if settings is None:
            return RuleResult.unknown("Diagnostic settings missing from snapshot")

        if settings:
            return RuleResult.passed(
                {"diagnostic_setting_count": len(settings), "logs_retained": True}
            )

        return RuleResult.failed(
            evidence={
                "diagnostic_setting_count": 0,
                "criticality": resource.criticality.value,
                "data_sensitivity": resource.data_sensitivity.value,
                "resource_type": resource.resource_type.value,
            },
            message=(
                f"{resource.name} matters to this business and keeps no record of "
                "what happens to it"
            ),
        )
