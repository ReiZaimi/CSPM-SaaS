"""Key vault rules: whether the vault survives, and who can reach it.

Both read the *management plane* -- the vault's own configuration -- because
that is all CloudGuard is permitted to read. Nothing here knows what keys or
secrets a vault holds, and the role deliberately does not ask: a product that
can tell you your vault is deletable without being able to read a single secret
in it is making a stronger security claim than one that can do both.
"""

from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import ExpectedState, RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule


class AzureKeyVaultDeletionRule(SecurityRule):
    rule_id = "AZ-KV-001"
    name = "Key vault can be permanently destroyed"
    description = (
        "A key vault has soft delete or purge protection turned off. Its keys and "
        "secrets can be deleted and then purged, and everything they encrypt becomes "
        "unrecoverable -- by an attacker who reaches the vault, or by anybody who runs "
        "the wrong command."
    )
    category = "secrets"
    severity = Severity.HIGH
    # Needs a foothold with rights over the vault first, which is why this is
    # not the anonymous-access number. What it removes is the ability to undo,
    # and no amount of privilege elsewhere restores a purged key.
    exploitability = 2
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.KEY_VAULT]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (AzureEvidence.KEY_VAULTS,)
    estimated_effort_minutes = 10
    rationale = (
        "This is the difference between an incident and a permanent loss. Disks, "
        "databases and backups encrypted with a customer-managed key are readable only "
        "while that key exists -- purge it and the ciphertext is all that is left. "
        "Ransomware operators purge vaults for exactly this reason, and so does an "
        "administrator with the wrong subscription selected."
    )
    remediation = (
        "Turn on soft delete and purge protection.\n\n"
        "Both are one-way: once purge protection is enabled it cannot be turned off "
        "for the life of the vault, which is the property that makes it worth "
        "anything. A deleted vault or secret then sits recoverable for the retention "
        "period instead of vanishing.\n\n"
        "Azure CLI:\n"
        "  az keyvault update --name <vault> --resource-group <rg> \\\n"
        "    --enable-purge-protection true\n\n"
        "Soft delete is enabled and non-disableable on vaults created recently; an "
        "older vault may still have it off, and enabling purge protection requires it."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="soft_delete",
                equals=True,
                describes="Deleted vaults and secrets are recoverable",
                arm_alias="Microsoft.KeyVault/vaults/enableSoftDelete",
                terraform_attribute="soft_delete_retention_days",
            ),
            ExpectedState(
                field="purge_protection",
                equals=True,
                describes="A deleted vault cannot be purged before its retention ends",
                arm_alias="Microsoft.KeyVault/vaults/enablePurgeProtection",
                terraform_attribute="purge_protection_enabled",
            ),
        ),
        cli=(
            "az keyvault update --name <vault> --resource-group <rg> "
            "--enable-purge-protection true",
        ),
        policy_resource_type="Microsoft.KeyVault/vaults",
        # Deny at creation. Enabling purge protection later is possible and
        # irreversible; a vault created without it has a window in which
        # everything it holds is destroyable, and no deployment needs that
        # window.
        policy_effect="Deny",
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["8"],
        "ISO_27001": ["A.8.13", "A.8.24"],
        "NIST_CSF": ["PR.DS-1", "PR.IP-4"],
        "GDPR": ["32(1)(c)"],
        "NIST_800_53": ["CP-9", "SC-12", "AU-9"],
        "SOC2": ["A1.2"],
        "PCI_DSS_4": ["3.6.1", "10.3.2"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Key vault configuration unavailable: {failure}")

        soft_delete = resource.get("soft_delete")
        purge_protection = resource.get("purge_protection")

        if soft_delete is None and purge_protection is None:
            return RuleResult.unknown(
                "Key vault recovery configuration missing from snapshot"
            )

        problems = []
        if soft_delete is False:
            problems.append("Soft delete is off, so a deleted secret is gone at once")
        # Absent means off. Unlike soft delete, Azure has never defaulted this
        # on, and the field is omitted rather than returned false when it has
        # not been set -- so reading absence as UNKNOWN here would report
        # nothing for the overwhelming majority of vaults that genuinely lack
        # it.
        if purge_protection is not True:
            problems.append(
                "Purge protection is off, so a deleted vault can be destroyed "
                "before its retention period ends"
            )

        evidence = {
            "soft_delete": soft_delete,
            "purge_protection": purge_protection,
            "soft_delete_retention_days": resource.get("soft_delete_retention_days"),
        }

        if not problems:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence={**evidence, "problems": problems},
            message=(
                f"{resource.name} and everything in it can be permanently destroyed: "
                + "; ".join(problems)
            ),
        )


class AzureKeyVaultNetworkRule(SecurityRule):
    rule_id = "AZ-KV-002"
    name = "Key vault answers the whole internet"
    description = (
        "A key vault accepts connections from any network. Its access controls are "
        "then the only thing between a stolen credential and the secrets it holds, "
        "with no network boundary in front of them."
    )
    category = "secrets"
    severity = Severity.HIGH
    # A credential still has to be stolen, so this is not anonymous access. It
    # is the class of credential that gets phished and sprayed, and the target
    # is the credential store.
    exploitability = 4
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.KEY_VAULT]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (AzureEvidence.KEY_VAULTS,)
    estimated_effort_minutes = 60
    rationale = (
        "Everything else in a tenant has a fallback if it is breached; the vault is "
        "the fallback. Reachable from anywhere, a leaked service principal secret or a "
        "phished session is enough to read every key it holds -- from any network in "
        "the world, at any hour, with nothing to attribute the connection to."
    )
    remediation = (
        "Set the vault's network rules to deny by default and add only what needs to "
        "reach it.\n\n"
        "Add the virtual networks and address ranges your workloads connect from, or "
        "put the vault behind a private endpoint and turn public network access off "
        "entirely. Check the vault's diagnostic logs for the addresses currently "
        "reaching it before changing this -- a vault that stops answering takes every "
        "workload that reads a secret at start-up with it.\n\n"
        "Azure CLI:\n"
        "  az keyvault network-rule add --name <vault> --resource-group <rg> \\\n"
        "    --vnet-name <vnet> --subnet <subnet>\n"
        "  az keyvault update --name <vault> --resource-group <rg> \\\n"
        "    --default-action Deny"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="network_default_action",
                equals="Deny",
                describes="Network rules default to Deny, allowing only named networks",
                arm_alias="Microsoft.KeyVault/vaults/networkAcls.defaultAction",
                terraform_attribute="network_acls.default_action",
            ),
        ),
        cli=(
            "az keyvault network-rule add --name <vault> --resource-group <rg> "
            "--vnet-name <vnet> --subnet <subnet>",
            "az keyvault update --name <vault> --resource-group <rg> "
            "--default-action Deny",
        ),
        policy_resource_type="Microsoft.KeyVault/vaults",
        # Audit rather than Deny. A vault is often created before the network
        # it will live behind exists, and denying that outright breaks
        # legitimate deployments in a way the storage equivalent does not --
        # there, the unsafe setting is anonymous read, and here it is the
        # absence of a network boundary that may genuinely arrive a step later.
        policy_effect="Audit",
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["8"],
        "ISO_27001": ["A.8.20", "A.8.24"],
        "NIST_CSF": ["PR.AC-5", "PR.DS-5"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
        "NIST_800_53": ["SC-7", "SC-12", "IA-5"],
        "SOC2": ["CC6.6", "CC6.1"],
        "PCI_DSS_4": ["3.6.1", "7.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Key vault configuration unavailable: {failure}")

        default_action = resource.get("network_default_action")
        public_access = resource.get("public_network_access")

        if default_action is None and public_access is None:
            return RuleResult.unknown(
                "Key vault network configuration missing from snapshot"
            )

        evidence = {
            "network_default_action": default_action,
            "public_network_access": public_access,
            "ip_rule_count": len(resource.get("ip_rules", []) or []),
            "virtual_network_rule_count": len(
                resource.get("virtual_network_rules", []) or []
            ),
            "rbac_authorization": resource.get("rbac_authorization"),
        }

        # Either boundary is enough. A vault with public access off is not
        # reachable whatever its ACL says, and one defaulting to Deny answers
        # only the networks it names.
        if str(public_access or "").lower() == "disabled":
            return RuleResult.passed(evidence)
        if str(default_action or "").lower() == "deny":
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            # Access policies are per-principal and RBAC is per-principal;
            # neither narrows the network. But a vault still on legacy access
            # policies has the weaker of the two authorization models in front
            # of it, so the network being open matters more, not less -- this
            # steps *down* only where the vault at least uses RBAC.
            exploitability=3 if resource.get("rbac_authorization") is True else None,
            message=(
                f"{resource.name} accepts connections from any network, with only its "
                "access controls in front of the secrets it holds"
            ),
        )
