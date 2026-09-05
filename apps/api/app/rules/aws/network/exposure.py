"""Security group rules: what the whole internet can reach.

One class per exposed service rather than one rule listing ports, for the same
reason the Azure network rules split: a finding is what a customer acts on, and
"SSH is open to the world" and "your database port is open to the world" are two
different afternoons with two different fixes.

The ingress shape is read the same way every time, so the parsing lives in one
place below and each rule declares the ports it cares about.
"""

from typing import Any, ClassVar

from app.connectors.aws.evidence import AwsEvidence
from app.core.enums import (
    Provider,
    RelationshipType,
    ResourceType,
    RuleScope,
    Severity,
)
from app.domain.resource import CloudResource
from app.remediation import Comparison, ExpectedState, RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule

# What "the whole internet" is spelled as, in both address families. The
# security-group rules read ``open_ingress``, which the normalizer has already
# reduced to entries matching these -- but a network ACL is judged from its raw
# entries, because an ACL is not an asset and never reaches the normalizer.
ANY_IPV4 = "0.0.0.0/0"
ANY_IPV6 = "::/0"

# Ports whose exposure is a finding rather than a configuration choice. Named
# here for the ACL rule; each port rule below declares its own.
ADMIN_PORTS = frozenset({22, 3389})


def open_to_the_world(group: CloudResource, ports: set[int]) -> list[dict[str, Any]]:
    """Every ingress rule of this group that reaches one of these ports.

    Reads ``open_ingress``, which the normalizer derives: the entries there are
    already the ones admitting the whole internet in either address family, so
    what is left here is the port question.

    An entry covering all ports is not a narrower rule than one naming 22 -- the
    ``-1`` protocol means every port there is -- so it matches whatever was
    asked for.
    """
    found: list[dict[str, Any]] = []
    for entry in group.get("open_ingress", []) or []:
        if entry.get("all_ports"):
            found.append({**entry, "ports": "all"})
            continue
        start, end = entry.get("from_port"), entry.get("to_port")
        if start is None or end is None:
            continue
        covered = sorted(p for p in ports if int(start) <= p <= int(end))
        if covered:
            found.append({**entry, "ports": covered})
    return found


def _open_rule(port: int) -> dict[str, Any]:
    """One ingress rule that a port rule must refuse.

    Carried on the declaration so a test can build the asset the rule should
    fail, rather than taking the rule's word for what an open rule looks like.
    """
    return {
        "protocol": "tcp",
        "from_port": port,
        "to_port": port,
        "all_ports": False,
        "sources": ["0.0.0.0/0"],
    }


class _OpenPortRule(SecurityRule):
    """Shared evaluation for "this port is reachable from anywhere".

    Not a rule itself -- it is absent from the registry, declares no id, and
    exists so five rules do not each grow their own copy of the ingress parser.
    """

    provider = Provider.AWS
    category = "network"
    ports: ClassVar[set[int]] = set()
    service: str = ""
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.NETWORK_SECURITY_GROUP]
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.SECURITY_GROUPS,
    )
    estimated_effort_minutes = 15

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Security groups unavailable: {failure}")

        if "open_ingress" not in resource.metadata:
            return RuleResult.unknown("Security group rules missing from snapshot")

        exposed = open_to_the_world(resource, self.ports)
        # What the group is actually in front of. A group attached to nothing is
        # still a misconfiguration and still worth fixing, but it exposes no
        # host today -- and the score should say so rather than treating a
        # forgotten template as an open door.
        protecting = context.get_related(resource, RelationshipType.PROTECTS.value)
        evidence = {
            "region": resource.region,
            "group_id": resource.provider_resource_id,
            "open_rules": exposed,
            "attached_to": [r.provider_resource_id for r in protecting],
        }

        if not exposed:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            exploitability=None if protecting else 2,
            message=(
                f"{resource.name} allows {self.service} from the whole internet"
                + (f", in front of {len(protecting)} instance(s)" if protecting else
                   " (attached to nothing today)")
            ),
        )


class AwsPublicSshRule(_OpenPortRule):
    rule_id = "AWS-NET-001"
    name = "SSH is open to the internet"
    description = (
        "A security group allows inbound TCP/22 from 0.0.0.0/0 or ::/0. Every host it "
        "guards is reachable by anyone, and is subject to continuous credential "
        "spraying from the moment it exists."
    )
    severity = Severity.HIGH
    exploitability = 4
    ports: ClassVar[set[int]] = {22}
    service = "SSH"
    rationale = (
        "Internet-facing SSH is scanned and sprayed continuously. It is one of the two "
        "most common initial-access routes into a cloud estate."
    )
    remediation = (
        "Remove the 0.0.0.0/0 ingress rule and reach the host another way.\n\n"
        "AWS CLI:\n"
        "  aws ec2 revoke-security-group-ingress --group-id <sg-id> \\\n"
        "    --protocol tcp --port 22 --cidr 0.0.0.0/0\n\n"
        "Then use SSM Session Manager, which needs no inbound rule at all:\n"
        "  aws ssm start-session --target <instance-id>\n\n"
        "If direct SSH is required, restrict the source to your own ranges."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="open_ingress",
                equals=None,
                comparison=Comparison.NONE_MATCHING,
                example=_open_rule(22),
                describes="No ingress rule admits TCP/22 from the whole internet",
                terraform_attribute="aws_security_group_rule.cidr_blocks",
            ),
        ),
        cli=(
            "aws ec2 revoke-security-group-ingress --group-id <sg-id> "
            "--protocol tcp --port 22 --cidr 0.0.0.0/0",
        ),
        notes=(
            "Preventive enforcement on AWS would be an AWS Config rule or an "
            "SCP. Neither is generated yet."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["5.2"],
        "ISO_27001": ["A.8.20", "A.8.22"],
        "NIST_CSF": ["PR.AC-5"],
        "NIST_800_53": ["SC-7", "AC-17"],
        "SOC2": ["CC6.6"],
        "PCI_DSS_4": ["1.3.1"],
    }


class AwsPublicRdpRule(_OpenPortRule):
    rule_id = "AWS-NET-002"
    name = "RDP is open to the internet"
    description = (
        "A security group allows inbound TCP/3389 from 0.0.0.0/0 or ::/0, exposing "
        "Windows remote desktop to the entire internet."
    )
    severity = Severity.CRITICAL
    exploitability = 4
    ports: ClassVar[set[int]] = {3389}
    service = "RDP"
    rationale = (
        "Internet-facing RDP is the most common initial-access route in ransomware "
        "incidents, and the protocol has a long history of pre-authentication flaws."
    )
    remediation = (
        "Remove the 0.0.0.0/0 ingress rule.\n\n"
        "AWS CLI:\n"
        "  aws ec2 revoke-security-group-ingress --group-id <sg-id> \\\n"
        "    --protocol tcp --port 3389 --cidr 0.0.0.0/0\n\n"
        "Use SSM Session Manager or a bastion in a private subnet instead."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="open_ingress",
                equals=None,
                comparison=Comparison.NONE_MATCHING,
                example=_open_rule(3389),
                describes="No ingress rule admits TCP/3389 from the whole internet",
                terraform_attribute="aws_security_group_rule.cidr_blocks",
            ),
        ),
        cli=(
            "aws ec2 revoke-security-group-ingress --group-id <sg-id> "
            "--protocol tcp --port 3389 --cidr 0.0.0.0/0",
        ),
        notes=(
            "Preventive enforcement on AWS would be an AWS Config rule or an "
            "SCP. Neither is generated yet."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["5.2"],
        "ISO_27001": ["A.8.20", "A.8.22"],
        "NIST_CSF": ["PR.AC-5"],
        "NIST_800_53": ["SC-7", "AC-17"],
        "SOC2": ["CC6.6"],
        "PCI_DSS_4": ["1.3.1"],
    }


class AwsPublicDatabasePortRule(_OpenPortRule):
    rule_id = "AWS-NET-003"
    name = "A database port is open to the internet"
    description = (
        "A security group allows a database port inbound from 0.0.0.0/0 or ::/0. "
        "The engine is then reachable by anyone who can guess a credential."
    )
    severity = Severity.CRITICAL
    exploitability = 4
    # PostgreSQL, MySQL/MariaDB, SQL Server, Oracle, Redis, MongoDB. Chosen
    # because RDS and ElastiCache use them by default, so an open rule here is
    # very often in front of a real datastore rather than a placeholder.
    ports: ClassVar[set[int]] = {5432, 3306, 1433, 1521, 6379, 27017}
    service = "a database port"
    rationale = (
        "A database exposed to the internet turns a leaked or weak credential into "
        "direct access to the data, with no other control in the way."
    )
    remediation = (
        "Remove the public ingress rule and keep database access inside the VPC.\n\n"
        "AWS CLI:\n"
        "  aws ec2 revoke-security-group-ingress --group-id <sg-id> \\\n"
        "    --protocol tcp --port <port> --cidr 0.0.0.0/0\n\n"
        "Allow only the security group of the application tier as the source:\n"
        "  aws ec2 authorize-security-group-ingress --group-id <sg-id> \\\n"
        "    --protocol tcp --port <port> --source-group <app-sg-id>"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="open_ingress",
                equals=None,
                comparison=Comparison.NONE_MATCHING,
                example=_open_rule(5432),
                describes=(
                    "No ingress rule admits a database port from the whole internet"
                ),
                terraform_attribute="aws_security_group_rule.cidr_blocks",
            ),
        ),
        cli=(
            "aws ec2 revoke-security-group-ingress --group-id <sg-id> "
            "--protocol tcp --port <port> --cidr 0.0.0.0/0",
        ),
        notes=(
            "Preventive enforcement on AWS would be an AWS Config rule or an "
            "SCP. Neither is generated yet."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["5.2"],
        "ISO_27001": ["A.8.20"],
        "NIST_CSF": ["PR.AC-5", "PR.DS-5"],
        "NIST_800_53": ["SC-7"],
        "SOC2": ["CC6.6"],
        "PCI_DSS_4": ["1.3.1"],
    }


class AwsOpenNetworkAclRule(SecurityRule):
    rule_id = "AWS-NET-004"
    name = "A network ACL allows an admin port from the internet"
    description = (
        "A subnet's network ACL admits SSH or RDP from 0.0.0.0/0. The ACL is "
        "evaluated before any security group, so it is the outer door — and "
        "unlike a security group it is stateless, which is why an over-broad "
        "one is usually written and then forgotten."
    )
    category = "network"
    provider = Provider.AWS
    severity = Severity.MEDIUM
    # On its own it opens nothing: a security group still has to allow the
    # traffic. It is a layer that should have said no and did not.
    exploitability = 2
    scope = RuleScope.AGGREGATE
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.NETWORK_ACLS,
    )
    estimated_effort_minutes = 25
    rationale = (
        "Defence in depth is the whole argument for a network ACL: it is the "
        "control that still says no when a security group is edited wrongly. "
        "One that admits the internet has stopped being that."
    )
    remediation = (
        "Remove or narrow the entry:\n\n"
        "  aws ec2 describe-network-acls --network-acl-ids <acl-id>\n"
        "  aws ec2 delete-network-acl-entry --network-acl-id <acl-id> \\\n"
        "    --rule-number <n> --ingress\n\n"
        "Network ACLs are stateless, so a replacement rule needs the return "
        "traffic allowed on the ephemeral port range as well — which is why the "
        "usual fix is to leave the ACL permissive and rely on security groups, "
        "and why this check is MEDIUM rather than HIGH."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        # Aggregate: a subnet ACL is not modelled as an asset, so there is no
        # resource an expected state could be checked against.
        expected=(),
        cli=(
            "aws ec2 delete-network-acl-entry --network-acl-id <acl-id> "
            "--rule-number <n> --ingress",
        ),
        notes=(
            "Network ACLs are stateless. A narrower ingress rule needs the "
            "matching ephemeral-port egress, or the connection completes one "
            "way only."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["5.1"],
        "ISO_27001": ["A.8.20", "A.8.22"],
        "NIST_CSF": ["PR.AC-5"],
        "NIST_800_53": ["SC-7"],
        "SOC2": ["CC6.6"],
        "PCI_DSS_4": ["1.3.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Network ACLs unavailable: {failure}")

        acls = context.controls.get("network_acls") or []
        if not acls:
            return RuleResult.not_applicable("This account has no network ACL")

        open_acls: list[dict[str, Any]] = []
        for acl in acls:
            entries = [
                entry
                for entry in acl.get("Entries") or []
                if _acl_entry_admits_admin_port(entry)
            ]
            if entries:
                open_acls.append(
                    {
                        "network_acl_id": acl.get("NetworkAclId"),
                        "region": acl.get("region"),
                        "entries": entries,
                    }
                )

        evidence = {"checked": len(acls), "open": open_acls}
        if not open_acls:
            return RuleResult.passed(evidence)

        named = ", ".join(str(a["network_acl_id"]) for a in open_acls)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{len(open_acls)} network ACL(s) admit an admin port: {named}",
        )


def _acl_entry_admits_admin_port(entry: dict[str, Any]) -> bool:
    """Whether one ACL entry lets the internet reach 22 or 3389.

    A ``deny`` entry is not a finding whatever it covers, and an egress entry is
    not ingress. Both are checked first, because an entry list read without them
    reports every well-written ACL as open.
    """
    if entry.get("Egress"):
        return False
    if str(entry.get("RuleAction", "allow")).lower() != "allow":
        return False
    if entry.get("CidrBlock") != ANY_IPV4 and entry.get("Ipv6CidrBlock") != ANY_IPV6:
        return False

    ports = entry.get("PortRange")
    if not ports:
        # No port range means every port, which is broader than naming one.
        return True
    start, end = ports.get("From"), ports.get("To")
    if start is None or end is None:
        return True
    return any(port in ADMIN_PORTS for port in range(int(start), int(end) + 1))


class AwsDefaultSecurityGroupRule(SecurityRule):
    rule_id = "AWS-NET-005"
    name = "A default security group carries rules"
    description = (
        "A VPC's default security group has ingress or egress rules on it. "
        "Anything launched without a security group named gets this one, so a "
        "permissive default is inherited by whatever somebody forgets to "
        "configure."
    )
    category = "network"
    provider = Provider.AWS
    severity = Severity.MEDIUM
    exploitability = 2
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.NETWORK_SECURITY_GROUP]
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.SECURITY_GROUPS,
    )
    estimated_effort_minutes = 15
    rationale = (
        "The default group cannot be deleted and is applied by omission, which "
        "makes it the one group nobody chooses and everybody can end up in. "
        "Empty, it fails closed."
    )
    remediation = (
        "Strip it and use named groups instead:\n\n"
        "  aws ec2 revoke-security-group-ingress --group-id <sg-id> "
        "--ip-permissions <rules>\n"
        "  aws ec2 revoke-security-group-egress --group-id <sg-id> "
        "--ip-permissions <rules>\n\n"
        "Check what is attached first — anything relying on the default will "
        "lose connectivity, and the fix for that is a group of its own rather "
        "than putting the rules back."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="has_any_rule",
                equals=False,
                describes="The default security group carries no rules",
                terraform_attribute="aws_default_security_group",
            ),
        ),
        cli=(
            "aws ec2 revoke-security-group-egress --group-id <sg-id> "
            "--ip-permissions <rules>",
        ),
        # Only about the default group. Every other group is judged on what it
        # admits, which is what the port rules above do.
        applies_when={"is_default": True},
        notes=(
            "The default group cannot be deleted, only emptied. Check what is "
            "attached first: anything relying on it loses connectivity."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["5.4"],
        "ISO_27001": ["A.8.20"],
        "NIST_CSF": ["PR.AC-5"],
        "NIST_800_53": ["SC-7", "CM-7"],
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
            return RuleResult.unknown(f"Security groups unavailable: {failure}")

        if not resource.get("is_default"):
            return RuleResult.not_applicable(
                f"{resource.name} is not a default security group"
            )

        has_rules = resource.get("has_any_rule")
        if has_rules is None:
            return RuleResult.unknown("Security group rules missing from snapshot")

        evidence = {
            "group_id": resource.provider_resource_id,
            "region": resource.region,
            "has_any_rule": has_rules,
        }
        if not has_rules:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"The default security group in {resource.region or 'this region'} "
                "carries rules"
            ),
        )
