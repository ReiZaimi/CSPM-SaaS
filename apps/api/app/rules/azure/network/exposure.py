"""Network exposure rules: what the internet can reach.

All three read normalized NSG rules of the shape produced by
``app.connectors.azure.normalizer``:

    {"name", "direction", "access", "protocol", "source", "destination_ports",
     "priority"}
"""

from typing import Any, ClassVar

from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.rules.base import RuleContext, RuleResult, SecurityRule

# Source ranges that mean "anyone on the internet". Azure spells this several
# ways and they are not interchangeable strings to a human reader.
PUBLIC_SOURCES = {"0.0.0.0/0", "*", "internet", "any", "::/0"}


def _is_public(source: str | None) -> bool:
    return (source or "").strip().lower() in PUBLIC_SOURCES


def _port_matches(port_spec: str, target: int) -> bool:
    """Azure port specs are '3389', '*', '3000-4000' or a comma-joined mix."""
    for token in str(port_spec).split(","):
        token = token.strip()
        if not token:
            continue
        if token == "*":
            return True
        if "-" in token:
            low, _, high = token.partition("-")
            try:
                if int(low) <= target <= int(high):
                    return True
            except ValueError:
                continue
        else:
            try:
                if int(token) == target:
                    return True
            except ValueError:
                continue
    return False


def _inbound_allow_rules(resource: CloudResource) -> list[dict[str, Any]] | None:
    rules = resource.get("security_rules")
    if rules is None:
        return None
    return [
        r
        for r in rules
        if str(r.get("direction", "")).lower() == "inbound"
        and str(r.get("access", "")).lower() == "allow"
    ]


def _find_public_port(resource: CloudResource, port: int, protocols: set[str]) -> dict | None:
    rules = _inbound_allow_rules(resource)
    if rules is None:
        return None
    for rule in rules:
        protocol = str(rule.get("protocol", "*")).lower()
        if protocol not in protocols and protocol != "*":
            continue
        if not _is_public(rule.get("source")):
            continue
        for port_spec in rule.get("destination_ports", []) or []:
            if _port_matches(port_spec, port):
                return rule
    return None


def _attachment_evidence(resource: CloudResource, context: RuleContext) -> dict[str, Any]:
    """An unattached NSG allowing RDP is noise, not a Critical finding.

    We still report it -- silently dropping it would be its own kind of lie --
    but the evidence says so, and the normalizer scores exposure lower, which
    flows through to a lower risk score (RULE_ENGINE.md section 1).
    """
    attached = context.get_related(resource, "protects")
    return {
        "attached": bool(attached),
        "attached_to": [r.name for r in attached],
    }


class _PublicPortRule(SecurityRule):
    """Shared logic for 'port X is open to the whole internet'."""

    port: int
    protocols: ClassVar[set[str]] = {"tcp"}
    service: str = ""
    requires_collection: ClassVar[list[str]] = ["network"]
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.NETWORK_SECURITY_GROUP]

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_collection)
        if failure:
            return RuleResult.unknown(f"Network configuration unavailable: {failure}")

        if _inbound_allow_rules(resource) is None:
            # The NSG exists but its rule list never arrived. Saying PASS here
            # would be inventing evidence we do not have.
            return RuleResult.unknown("Security rule list missing from snapshot")

        match = _find_public_port(resource, self.port, self.protocols)
        if match is None:
            return RuleResult.passed(
                {"service": self.service, "port": self.port, "public_access": False}
            )

        return RuleResult.failed(
            evidence={
                "service": self.service,
                "source": match.get("source"),
                "protocol": match.get("protocol"),
                "port": self.port,
                "nsg_rule_name": match.get("name"),
                "priority": match.get("priority"),
                **_attachment_evidence(resource, context),
            },
            message=(
                f"{self.service} on port {self.port} is reachable from the entire internet "
                f"via NSG rule '{match.get('name')}'"
            ),
        )


class AzurePublicRdpRule(_PublicPortRule):
    rule_id = "AZ-NET-001"
    name = "RDP exposed to the internet"
    description = (
        "A network security group permits inbound RDP (TCP/3389) from any source address. "
        "Remote Desktop endpoints reachable from the open internet are found and "
        "password-sprayed continuously by automated scanners."
    )
    category = "network"
    severity = Severity.CRITICAL
    exploitability = 5
    port = 3389
    service = "RDP"
    estimated_effort_minutes = 15
    rationale = (
        "Anyone on the internet can attempt to log in to this machine. RDP brute-force is "
        "one of the most common initial access routes for ransomware."
    )
    remediation = (
        "Restrict the inbound rule's source from Any/0.0.0.0/0 to your VPN range, office IP "
        "range, or an approved address list.\n\n"
        "Azure Portal: Network security group > Inbound security rules > select the rule > "
        "set Source to 'IP Addresses' and enter the approved range > Save.\n\n"
        "Azure CLI:\n"
        "  az network nsg rule update --resource-group <rg> --nsg-name <nsg> \\\n"
        "    --name <rule> --source-address-prefixes <your.ip.range/24>\n\n"
        "Better still, remove the public rule entirely and reach the machine through "
        "Azure Bastion or a just-in-time access policy."
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["6.1"],
        "ISO_27001": ["A.8.20", "A.8.23"],
        "NIST_CSF": ["PR.AC-5"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
    }


class AzurePublicSshRule(_PublicPortRule):
    rule_id = "AZ-NET-002"
    name = "SSH exposed to the internet"
    description = (
        "A network security group permits inbound SSH (TCP/22) from any source address, "
        "exposing the host to continuous automated credential attacks."
    )
    category = "network"
    severity = Severity.HIGH
    exploitability = 4
    port = 22
    service = "SSH"
    estimated_effort_minutes = 15
    rationale = (
        "Anyone on the internet can attempt to authenticate to this host. Even with key-only "
        "authentication, an exposed SSH port leaks host availability and invites exploitation "
        "of any future SSH vulnerability."
    )
    remediation = (
        "Restrict the inbound rule's source from Any/0.0.0.0/0 to your VPN or office range.\n\n"
        "Azure CLI:\n"
        "  az network nsg rule update --resource-group <rg> --nsg-name <nsg> \\\n"
        "    --name <rule> --source-address-prefixes <your.ip.range/24>\n\n"
        "Prefer Azure Bastion or just-in-time access over a standing public SSH rule."
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["6.2"],
        "ISO_27001": ["A.8.20"],
        "NIST_CSF": ["PR.AC-5"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
    }


class AzureOpenNsgRule(SecurityRule):
    """Everything else the internet can reach that probably should not be.

    Deliberately narrower than "any public inbound rule": HTTP/HTTPS on 80/443
    is usually the entire point of the workload. This rule is about
    administrative and data-tier ports, which are almost never meant to be
    world-reachable.
    """

    rule_id = "AZ-NET-003"
    name = "Unrestricted inbound NSG rule"
    description = (
        "A network security group allows unrestricted inbound access from any source to "
        "administrative or database ports, or to every port at once."
    )
    category = "network"
    severity = Severity.HIGH
    exploitability = 4
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.NETWORK_SECURITY_GROUP]
    requires_collection: ClassVar[list[str]] = ["network"]
    estimated_effort_minutes = 30
    rationale = (
        "Management and database ports open to the internet give an attacker a direct path to "
        "the service without ever touching your application layer."
    )
    remediation = (
        "Review each unrestricted inbound rule and narrow its source to the smallest network "
        "range that needs it. Where a service must be public, put it behind a load balancer, "
        "Application Gateway or Front Door rather than exposing the port directly.\n\n"
        "Azure CLI:\n"
        "  az network nsg rule list --resource-group <rg> --nsg-name <nsg> -o table\n"
        "  az network nsg rule update --resource-group <rg> --nsg-name <nsg> \\\n"
        "    --name <rule> --source-address-prefixes <approved.range/24>"
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["6.5"],
        "ISO_27001": ["A.8.20", "A.8.22"],
        "NIST_CSF": ["PR.AC-5", "PR.PT-4"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
    }

    # Ports whose exposure is a finding in its own right. 80/443 are absent on
    # purpose -- a public web server is a design, not a defect.
    SENSITIVE_PORTS: ClassVar[dict[int, str]] = {
        135: "RPC",
        137: "NetBIOS",
        139: "NetBIOS",
        445: "SMB",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        5432: "PostgreSQL",
        5601: "Kibana",
        6379: "Redis",
        9200: "Elasticsearch",
        11211: "Memcached",
        27017: "MongoDB",
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_collection)
        if failure:
            return RuleResult.unknown(f"Network configuration unavailable: {failure}")

        inbound = _inbound_allow_rules(resource)
        if inbound is None:
            return RuleResult.unknown("Security rule list missing from snapshot")

        violations: list[dict[str, Any]] = []
        for rule in inbound:
            if not _is_public(rule.get("source")):
                continue
            ports = rule.get("destination_ports", []) or []

            if any(str(p).strip() == "*" for p in ports):
                violations.append(
                    {
                        "nsg_rule_name": rule.get("name"),
                        "source": rule.get("source"),
                        "ports": "all",
                        "reason": "Every port is open to the internet",
                    }
                )
                continue

            for port, service in self.SENSITIVE_PORTS.items():
                if any(_port_matches(p, port) for p in ports):
                    violations.append(
                        {
                            "nsg_rule_name": rule.get("name"),
                            "source": rule.get("source"),
                            "port": port,
                            "service": service,
                            "reason": f"{service} is reachable from the internet",
                        }
                    )

        if not violations:
            return RuleResult.passed({"unrestricted_rules": 0})

        return RuleResult.failed(
            evidence={
                "violations": violations,
                "violation_count": len(violations),
                **_attachment_evidence(resource, context),
            },
            message=(
                f"{len(violations)} unrestricted inbound rule(s) expose sensitive ports "
                f"to the internet"
            ),
        )
