"""Network exposure rules: what the internet can reach.

All three read normalized NSG rules of the shape produced by
``app.connectors.azure.normalizer``:

    {"name", "direction", "access", "protocol", "source", "destination_ports",
     "priority"}
"""

from typing import Any, ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import Comparison, ExpectedState, RemediationSpec
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


def _find_public_port(
    resource: CloudResource, ports: tuple[int, ...], protocols: set[str]
) -> tuple[dict, int] | None:
    """The first rule opening any of these ports to the internet, and which one.

    Several ports rather than one, because a service is not always a port.
    WinRM listens on 5985 and 5986 and either is the same finding with the same
    fix -- reporting them as two findings would ask a customer to close the
    same door twice.
    """
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
            for port in ports:
                if _port_matches(port_spec, port):
                    return rule, port
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
    # Further ports the same service listens on, judged as one finding. Empty
    # for a single-port service, which is both existing rules.
    also_ports: ClassVar[tuple[int, ...]] = ()
    protocols: ClassVar[set[str]] = {"tcp"}
    service: str = ""
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.NETWORK_SECURITY_GROUPS,
        AzureEvidence.NETWORK_INTERFACES,
    )
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.NETWORK_SECURITY_GROUP]


    @classmethod
    def _ports(cls) -> tuple[int, ...]:
        return (cls.port, *cls.also_ports)

    @classmethod
    def _spec(cls) -> RemediationSpec:
        """The declaration, built from the port this subclass checks.

        Written once here rather than twice below, because the two subclasses
        differ in exactly the two values that appear in it -- and a copy per
        port is how the RDP declaration ends up describing SSH after somebody
        edits one of them.
        """
        return RemediationSpec(
            expected=(
                ExpectedState(
                    field="security_rules",
                    comparison=Comparison.NONE_MATCHING,
                    equals=None,
                    describes=(
                        f"No inbound rule allows {cls.service} "
                        f"(TCP/{'/'.join(str(p) for p in cls._ports())}) "
                        "from the internet"
                    ),
                    # The witness: a rule of exactly this shape is what the
                    # check looks for, which is both the clearest way to say
                    # what "fixed" means and the thing a test needs to build an
                    # asset this rule must fail.
                    example={
                        "name": "<rule>",
                        "direction": "Inbound",
                        "access": "Allow",
                        "protocol": "Tcp",
                        "source": "0.0.0.0/0",
                        "destination_ports": [str(cls.port)],
                    },
                ),
            ),
            cli=(
                "az network nsg rule update --resource-group <rg> --nsg-name <nsg> "
                "--name <rule> --source-address-prefixes <your.ip.range/24>",
                "az network nsg rule delete --resource-group <rg> --nsg-name <nsg> "
                "--name <rule>",
            ),
            notes=(
                "No policy is generated. Azure Policy can reach into an NSG's "
                "rules through a count expression, and neither the alias nor "
                "the expression has been verified against a real deployment "
                "from here -- an unverified string fails the whole definition "
                "atomically, which the customer sees as 'Deployment Failed'. "
                "Prefer Azure Bastion or just-in-time access over a standing "
                "public rule."
            ),
        )

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Network configuration unavailable: {failure}")

        if _inbound_allow_rules(resource) is None:
            # The NSG exists but its rule list never arrived. Saying PASS here
            # would be inventing evidence we do not have.
            return RuleResult.unknown("Security rule list missing from snapshot")

        found = _find_public_port(resource, self._ports(), self.protocols)
        if found is None:
            return RuleResult.passed(
                {
                    "service": self.service,
                    "ports": list(self._ports()),
                    "public_access": False,
                }
            )

        match, open_port = found
        attachment = _attachment_evidence(resource, context)
        return RuleResult.failed(
            evidence={
                "service": self.service,
                "source": match.get("source"),
                "protocol": match.get("protocol"),
                "port": open_port,
                "nsg_rule_name": match.get("name"),
                "priority": match.get("priority"),
                **attachment,
            },
            # An NSG governing nothing carries the same rule and none of the
            # reach. Nobody can connect to a machine it does not protect, so
            # what is left is a latent mistake: real, worth fixing before it is
            # attached to something, and not the thing being scanned for RDP
            # right now. The distinction is already drawn in AZ-CMP-001's own
            # description ("unlike an unattached NSG rule") and in the note on
            # ``ResourceRelationship``; this is where it reaches the score.
            exploitability=None if attachment["attached"] else 1,
            message=(
                f"{self.service} on port {open_port} is reachable from the entire internet "
                f"via NSG rule '{match.get('name')}'"
                + ("" if attachment["attached"] else ", but the group protects nothing")
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
    remediation_spec: ClassVar[RemediationSpec | None] = None  # set below
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["6.1"],
        "ISO_27001": ["A.8.20", "A.8.23"],
        "NIST_CSF": ["PR.AC-5"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
        "NIST_800_53": ["AC-17", "SC-7"],
        "SOC2": ["CC6.6"],
        "PCI_DSS_4": ["1.3.1", "1.4.1"],
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
    remediation_spec: ClassVar[RemediationSpec | None] = None  # set below
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["6.2"],
        "ISO_27001": ["A.8.20"],
        "NIST_CSF": ["PR.AC-5"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
        "NIST_800_53": ["AC-17", "SC-7"],
        "SOC2": ["CC6.6"],
        "PCI_DSS_4": ["1.3.1", "1.4.1"],
    }


class AzurePublicWinRmRule(_PublicPortRule):
    rule_id = "AZ-NET-004"
    name = "WinRM exposed to the internet"
    description = (
        "A network security group permits inbound Windows Remote Management (TCP/5985 "
        "or TCP/5986) from any source address. WinRM executes commands on the host as "
        "the authenticating account, so an exposed listener is a remote shell waiting "
        "for a credential."
    )
    category = "network"
    severity = Severity.CRITICAL
    # The same class as RDP, and for a stronger reason. RDP at least presents a
    # session; WinRM is a scripted command channel, so a sprayed credential
    # becomes code execution without a human at either end. 5985 carries the
    # credential over unencrypted HTTP by default, which is why it is the
    # primary port here rather than the secondary one.
    exploitability = 5
    port = 5985
    also_ports: ClassVar[tuple[int, ...]] = (5986,)
    service = "WinRM"
    estimated_effort_minutes = 15
    rationale = (
        "WinRM is remote command execution by design. Exposed to the internet it is "
        "sprayed by the same automation that finds RDP, and a success is a shell rather "
        "than a login prompt -- with 5985 handing the credential over in the clear."
    )
    remediation = (
        "Remove the public rule. WinRM should never be reachable from the internet.\n\n"
        "Reach the host through Azure Bastion, or run commands through the VM agent "
        "with `az vm run-command`, which needs no inbound port at all. Where a "
        "management network genuinely must reach WinRM, narrow the source to that "
        "range and use 5986 so the channel is encrypted.\n\n"
        "Azure CLI:\n"
        "  az network nsg rule delete --resource-group <rg> --nsg-name <nsg> \\\n"
        "    --name <rule>\n"
        "  az network nsg rule update --resource-group <rg> --nsg-name <nsg> \\\n"
        "    --name <rule> --source-address-prefixes <management.range/24>"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = None  # set below
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["6.5"],
        "ISO_27001": ["A.8.20", "A.8.23"],
        "NIST_CSF": ["PR.AC-5", "PR.PT-4"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
        "NIST_800_53": ["AC-17", "SC-7"],
        "SOC2": ["CC6.6"],
        "PCI_DSS_4": ["1.3.1", "1.4.1"],
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
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.NETWORK_SECURITY_GROUPS,
        AzureEvidence.NETWORK_INTERFACES,
    )
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
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="security_rules",
                comparison=Comparison.NONE_MATCHING,
                equals=None,
                describes=(
                    "No inbound rule allows a management or database port, or "
                    "every port at once, from the internet"
                ),
                example={
                    "name": "<rule>",
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "*",
                    "source": "0.0.0.0/0",
                    "destination_ports": ["*"],
                },
            ),
        ),
        cli=(
            "az network nsg rule list --resource-group <rg> --nsg-name <nsg> -o table",
            "az network nsg rule update --resource-group <rg> --nsg-name <nsg> "
            "--name <rule> --source-address-prefixes <approved.range/24>",
        ),
        notes=(
            "80 and 443 are deliberately not part of this expectation: a public "
            "web server is a design rather than a defect. No policy is "
            "generated, for the reason recorded on AZ-NET-001."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["6.5"],
        "ISO_27001": ["A.8.20", "A.8.22"],
        "NIST_CSF": ["PR.AC-5", "PR.PT-4"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
        "NIST_800_53": ["SC-7", "CM-7"],
        "SOC2": ["CC6.6"],
        "PCI_DSS_4": ["1.2.1", "1.3.1"],
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

        failure = context.has_collection_error(*self.requires_evidence)
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


# Bound after the classes exist, because the declaration is derived from each
# subclass's own port and service. Assigning it inside the class body would need
# the values before the class is finished.
AzurePublicRdpRule.remediation_spec = AzurePublicRdpRule._spec()
AzurePublicSshRule.remediation_spec = AzurePublicSshRule._spec()
AzurePublicWinRmRule.remediation_spec = AzurePublicWinRmRule._spec()
