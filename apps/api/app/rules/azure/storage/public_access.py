"""Storage rules. The classic cloud data-leak shape."""

from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import ExpectedState, RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule


class AzurePublicStorageRule(SecurityRule):
    rule_id = "AZ-STO-001"
    name = "Storage account allows public access"
    description = (
        "A storage account permits anonymous public read access to blob data, or accepts "
        "connections from any network. Anyone who learns or guesses the container URL can "
        "read its contents without credentials."
    )
    category = "storage"
    severity = Severity.HIGH
    exploitability = 5
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.STORAGE_ACCOUNT]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.STORAGE_ACCOUNTS,
    )
    estimated_effort_minutes = 20
    rationale = (
        "Publicly readable storage is the single most common source of large cloud data "
        "breaches. It requires no exploit — the data is simply served to whoever asks."
    )
    remediation = (
        "Disable anonymous blob access and restrict network access to the storage account.\n\n"
        "Azure Portal: Storage account > Settings > Configuration > set 'Allow Blob "
        "anonymous access' to Disabled. Then Security + networking > Networking > set "
        "'Public network access' to 'Enabled from selected virtual networks and IP "
        "addresses' (or Disabled) and add only the ranges that need it.\n\n"
        "Azure CLI:\n"
        "  az storage account update --name <account> --resource-group <rg> \\\n"
        "    --allow-blob-public-access false --default-action Deny\n\n"
        "Where a container genuinely must be public, serve it through a CDN or a "
        "time-limited SAS token rather than leaving the container itself anonymous."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="allow_blob_public_access",
                equals=False,
                describes="Anonymous blob access is disabled",
                arm_alias="Microsoft.Storage/storageAccounts/allowBlobPublicAccess",
                terraform_attribute="allow_nested_items_to_be_public",
            ),
            ExpectedState(
                field="network_default_action",
                equals="Deny",
                describes="Network rules default to Deny, allowing only named ranges",
                arm_alias="Microsoft.Storage/storageAccounts/networkAcls.defaultAction",
                terraform_attribute="network_rules.default_action",
            ),
        ),
        cli=(
            "az storage account update --name <account> --resource-group <rg> "
            "--allow-blob-public-access false --default-action Deny",
        ),
        policy_resource_type="Microsoft.Storage/storageAccounts",
        # Deny rather than Audit: an account created with anonymous access on is
        # exposed from the moment it exists, and no deployment needs it to pass
        # through unblocked first.
        policy_effect="Deny",
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["3.7", "3.8"],
        "ISO_27001": ["A.5.10", "A.8.3"],
        "NIST_CSF": ["PR.AC-3", "PR.DS-5"],
        "GDPR": ["5(1)(f)", "25", "32(1)(b)"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Storage configuration unavailable: {failure}")

        allow_blob_public = resource.get("allow_blob_public_access")
        network_default = resource.get("network_default_action")
        public_network = resource.get("public_network_access")

        # Both signals absent means we never saw the account's configuration.
        if allow_blob_public is None and network_default is None:
            return RuleResult.unknown("Storage account configuration missing from snapshot")

        problems = []
        if allow_blob_public is True:
            problems.append("Anonymous blob public access is enabled")
        if network_default is not None and str(network_default).lower() == "allow":
            problems.append("Network access rules default to Allow (open to all networks)")
        if public_network is not None and str(public_network).lower() == "enabled" and (
            network_default is not None and str(network_default).lower() == "allow"
        ):
            problems.append("Public network access is enabled without network restrictions")

        evidence = {
            "allow_blob_public_access": allow_blob_public,
            "network_default_action": network_default,
            "public_network_access": public_network,
            "public_containers": resource.get("public_containers", []),
        }

        if not problems:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence={**evidence, "problems": problems},
            message=f"{resource.name} is publicly accessible: {'; '.join(problems)}",
        )


class AzureStorageEncryptionRule(SecurityRule):
    rule_id = "AZ-STO-002"
    name = "Storage account transport and encryption settings insufficient"
    description = (
        "A storage account accepts unencrypted HTTP connections, permits an outdated TLS "
        "version, or allows shared-key authorization. Data in transit can then be "
        "intercepted or downgraded."
    )
    category = "storage"
    severity = Severity.HIGH
    exploitability = 2
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.STORAGE_ACCOUNT]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.STORAGE_ACCOUNTS,
    )
    estimated_effort_minutes = 20
    rationale = (
        "Without enforced HTTPS and a current TLS version, credentials and data can be read "
        "or altered in transit by anyone positioned on the network path."
    )
    remediation = (
        "Require secure transfer and a minimum TLS version of 1.2.\n\n"
        "Azure Portal: Storage account > Configuration > set 'Secure transfer required' to "
        "Enabled and 'Minimum TLS version' to Version 1.2.\n\n"
        "Azure CLI:\n"
        "  az storage account update --name <account> --resource-group <rg> \\\n"
        "    --https-only true --min-tls-version TLS1_2\n\n"
        "Also consider disabling shared-key access so all callers authenticate through "
        "Entra ID:\n"
        "  az storage account update --name <account> --resource-group <rg> \\\n"
        "    --allow-shared-key-access false"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="https_traffic_only",
                equals=True,
                describes="Secure transfer required is enabled",
                arm_alias="Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly",
                terraform_attribute="https_traffic_only",
            ),
            ExpectedState(
                field="min_tls_version",
                equals="TLS1_2",
                # The rule accepts 1.3 as well, so the policy must too: pinned
                # to equality it would refuse an account configured better than
                # asked, and a customer would find the policy and the check
                # disagreeing about the same account.
                also_accepts=("TLS1_3",),
                describes="The minimum TLS version is 1.2 or higher",
                arm_alias="Microsoft.Storage/storageAccounts/minimumTlsVersion",
                terraform_attribute="min_tls_version",
            ),
        ),
        cli=(
            "az storage account update --name <account> --resource-group <rg> "
            "--https-only true --min-tls-version TLS1_2",
        ),
        policy_resource_type="Microsoft.Storage/storageAccounts",
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["3.1", "3.15"],
        "ISO_27001": ["A.8.24"],
        "NIST_CSF": ["PR.DS-2"],
        "GDPR": ["5(1)(f)", "32(1)(a)"],
    }

    ACCEPTABLE_TLS: ClassVar[set[str]] = {"tls1_2", "tls1_3"}

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Storage configuration unavailable: {failure}")

        https_only = resource.get("https_traffic_only")
        min_tls = resource.get("min_tls_version")

        if https_only is None and min_tls is None:
            return RuleResult.unknown("Storage encryption settings missing from snapshot")

        problems = []
        if https_only is False:
            problems.append("Unencrypted HTTP traffic is permitted")
        if min_tls is not None:
            normalized = str(min_tls).lower().replace(".", "_")
            if normalized not in self.ACCEPTABLE_TLS:
                problems.append(f"Minimum TLS version is {min_tls}, below TLS 1.2")

        evidence = {
            "https_traffic_only": https_only,
            "min_tls_version": min_tls,
            "allow_shared_key_access": resource.get("allow_shared_key_access"),
            "infrastructure_encryption": resource.get("infrastructure_encryption"),
        }

        if not problems:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence={**evidence, "problems": problems},
            message=f"{resource.name} transport security is insufficient: {'; '.join(problems)}",
        )
