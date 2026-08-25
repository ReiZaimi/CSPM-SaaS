from typing import ClassVar

from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.rules.base import RuleContext, RuleResult, SecurityRule


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
    requires_collection: ClassVar[list[str]] = ["logging"]
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
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["5.1.1", "5.3"],
        "ISO_27001": ["A.8.15", "A.8.16"],
        "NIST_CSF": ["DE.AE-3", "PR.PT-1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_collection)
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
