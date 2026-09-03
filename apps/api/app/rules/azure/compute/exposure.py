"""Compute exposure.

This is the rule that shows why ``resource_relationships`` exists. "An NSG
allows RDP" and "a VM has a public IP" are each mild on their own; the
combination — a machine the internet can route to, with an administrative port
open — is the thing that actually gets exploited.
"""

from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import RemediationSpec
from app.rules.azure.network.exposure import _find_public_port
from app.rules.base import RuleContext, RuleResult, SecurityRule

ADMIN_SERVICES = {3389: "RDP", 22: "SSH", 5985: "WinRM", 5986: "WinRM over HTTPS"}


class AzureExposedComputeRule(SecurityRule):
    rule_id = "AZ-CMP-001"
    name = "Internet-facing virtual machine with an administrative port open"
    description = (
        "A virtual machine has a public IP address and a network security group that permits "
        "an administrative service from any source. Unlike an unattached NSG rule, this "
        "combination is directly reachable and therefore directly exploitable."
    )
    category = "compute"
    severity = Severity.HIGH
    exploitability = 4
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.VIRTUAL_MACHINE]
    # A VM's exposure is read through its interfaces, their public IPs
    # and the NSGs guarding them, so all four are load-bearing.
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.VIRTUAL_MACHINES,
        AzureEvidence.NETWORK_INTERFACES,
        AzureEvidence.PUBLIC_IP_ADDRESSES,
        AzureEvidence.NETWORK_SECURITY_GROUPS,
    )
    estimated_effort_minutes = 45
    rationale = (
        "This machine is routable from the internet and accepts administrative logins from "
        "anywhere. It is being scanned right now — internet-wide scans find a new public IP "
        "within minutes."
    )
    remediation = (
        "Remove the machine's exposure rather than only tightening the port rule.\n\n"
        "1. Restrict the NSG rule's source to your VPN or office range (fastest mitigation).\n"
        "2. Remove the public IP entirely and connect through Azure Bastion:\n"
        "     az network nic ip-config update --name <ipconfig> --nic-name <nic> \\\n"
        "       --resource-group <rg> --remove publicIpAddress\n"
        "3. Where occasional public access is unavoidable, enable just-in-time VM access in "
        "Microsoft Defender for Cloud so the port opens only on approved request."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        # Also empty, and for a different reason again. This rule is about a
        # *relationship*: a machine with a public address, and the network
        # security groups that govern it admitting a management port. Neither
        # half is a setting on the VM -- the fix lands on the NSG, where
        # AZ-NET-001 and AZ-NET-002 already declare it -- so an expected state
        # here would describe an asset that cannot satisfy it alone.
        expected=(),
        cli=(
            "az network nic ip-config update --name <ipconfig> --nic-name <nic> "
            "--resource-group <rg> --remove publicIpAddress",
            "az network nsg rule update --resource-group <rg> --nsg-name <nsg> "
            "--name <rule> --source-address-prefixes <your.ip.range/24>",
        ),
        notes=(
            "Two ways to close it and they are not equivalent: remove the "
            "public address, or narrow the rules that admit management ports "
            "to it. The first ends the exposure; the second ends this "
            "exposure. Reach the machine through Azure Bastion or just-in-time "
            "access rather than a standing public address."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["6.1", "6.2"],
        "ISO_27001": ["A.8.20", "A.8.22"],
        "NIST_CSF": ["PR.AC-3", "PR.AC-5"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
        "NIST_800_53": ["AC-17", "SC-7"],
        "SOC2": ["CC6.6"],
        "PCI_DSS_4": ["1.3.1", "1.4.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Compute or network data unavailable: {failure}")

        has_public_ip = resource.get("has_public_ip")
        if has_public_ip is None:
            return RuleResult.unknown("Network attachment for this VM is missing from snapshot")

        if not has_public_ip:
            return RuleResult.passed(
                {"has_public_ip": False, "reason": "No public IP address attached"}
            )

        # The NSGs that actually govern traffic to this machine, walked through
        # the relationship graph rather than guessed by name.
        guarding_nsgs = context.get_related_inverse(resource, "protects")
        if not guarding_nsgs:
            return RuleResult.unknown(
                "VM has a public IP but no governing network security group was resolved"
            )

        exposed: list[dict] = []
        for nsg in guarding_nsgs:
            for port, service in ADMIN_SERVICES.items():
                found = _find_public_port(nsg, (port,), {"tcp"})
                if found:
                    match, _ = found
                    exposed.append(
                        {
                            "service": service,
                            "port": port,
                            "nsg": nsg.name,
                            "nsg_rule_name": match.get("name"),
                            "source": match.get("source"),
                        }
                    )

        evidence = {
            "has_public_ip": True,
            "public_ips": resource.get("public_ips", []),
            "guarding_nsgs": [n.name for n in guarding_nsgs],
            "exposed_services": exposed,
        }

        if not exposed:
            return RuleResult.passed(evidence)

        services = ", ".join(sorted({e["service"] for e in exposed}))
        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"{resource.name} is internet-facing with {services} open to any source address"
            ),
        )


class AzureUnguardedVmRule(SecurityRule):
    rule_id = "AZ-CMP-002"
    name = "Virtual machine governed by no network security group"
    description = (
        "No network security group applies to this machine, at its network interface or "
        "at its subnet. Nothing filters what may reach it from elsewhere in the virtual "
        "network, so anything that gets a foothold on the network reaches it directly."
    )
    category = "compute"
    severity = Severity.MEDIUM
    # A position on the network first, which is what separates this from
    # AZ-CMP-001. That rule is about a machine the internet can already reach;
    # this one is about how far an attacker travels once inside.
    exploitability = 2
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.VIRTUAL_MACHINE]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.VIRTUAL_MACHINES,
        AzureEvidence.NETWORK_INTERFACES,
        AzureEvidence.NETWORK_SECURITY_GROUPS,
    )
    estimated_effort_minutes = 30
    rationale = (
        "Segmentation is what turns one compromised machine into one compromised "
        "machine. Without a security group, an attacker who reaches any host on this "
        "network reaches this one too -- every port, from every peer -- and the lateral "
        "movement that follows is the difference between an incident and a breach."
    )
    remediation = (
        "Apply a network security group, preferably at the subnet so every machine in "
        "it inherits the same rules.\n\n"
        "Start by denying inbound from the virtual network and allowing back only the "
        "ports this workload actually serves. Azure's default rules already permit all "
        "traffic within the virtual network, which is what this finding is about.\n\n"
        "Azure CLI:\n"
        "  az network nsg create --resource-group <rg> --name <nsg>\n"
        "  az network vnet subnet update --resource-group <rg> --vnet-name <vnet> \\\n"
        "    --name <subnet> --network-security-group <nsg>\n\n"
        "Use NSG flow logs first if you are unsure what currently talks to this machine."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "az network nsg create --resource-group <rg> --name <nsg>",
            "az network vnet subnet update --resource-group <rg> --vnet-name <vnet> "
            "--name <subnet> --network-security-group <nsg>",
        ),
        notes=(
            "No expected state and no policy. What must change is the existence of a "
            "relationship -- a security group attached to this machine's subnet or "
            "interface -- rather than a field on the machine, and the check reads that "
            "relationship from the graph. A policy could require an NSG on new subnets "
            "and would say nothing about the ones already deployed, which are the ones "
            "this finding is about."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["6.5"],
        "ISO_27001": ["A.8.20", "A.8.22"],
        "NIST_CSF": ["PR.AC-5", "PR.PT-4"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
        "NIST_800_53": ["SC-7", "CM-7"],
        "SOC2": ["CC6.6"],
        "PCI_DSS_4": ["1.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Network configuration unavailable: {failure}")

        # The normalizer sets this to None when the machine names interfaces
        # that were never collected. Its security groups hang off those
        # interfaces, so "no groups found" and "we could not look" are the same
        # observation here and only one of them is a finding.
        if resource.get("has_public_ip") is None:
            return RuleResult.unknown(
                "This machine's network interfaces were not collected, so the "
                "security groups attached to them could not be resolved"
            )

        guarding = context.get_related_inverse(resource, "protects")
        if guarding:
            return RuleResult.passed(
                {"guarding_nsgs": [n.name for n in guarding]}
            )

        return RuleResult.failed(
            evidence={
                "guarding_nsgs": [],
                "has_public_ip": resource.get("has_public_ip"),
                "network_interfaces": resource.get("network_interfaces", []),
            },
            # Already reachable from the internet, so an attacker needs no
            # foothold on the network to start with. AZ-CMP-001 names the open
            # port; this names the absence of anything that would have stopped
            # it, and at that point the missing segmentation is not a
            # second-order problem.
            exploitability=4 if resource.get("has_public_ip") else None,
            message=(
                f"No network security group governs {resource.name}"
                + (
                    ", which also holds a public IP address"
                    if resource.get("has_public_ip")
                    else ""
                )
            ),
        )
