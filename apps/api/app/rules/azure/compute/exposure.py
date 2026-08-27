"""Compute exposure.

This is the rule that shows why ``resource_relationships`` exists. "An NSG
allows RDP" and "a VM has a public IP" are each mild on their own; the
combination — a machine the internet can route to, with an administrative port
open — is the thing that actually gets exploited.
"""

from typing import ClassVar

from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
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
    requires_collection: ClassVar[list[str]] = ["compute", "network"]
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
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["6.1", "6.2"],
        "ISO_27001": ["A.8.20", "A.8.22"],
        "NIST_CSF": ["PR.AC-3", "PR.AC-5"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_collection)
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
                match = _find_public_port(nsg, port, {"tcp"})
                if match:
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
