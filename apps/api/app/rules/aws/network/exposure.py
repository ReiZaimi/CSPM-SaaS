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
from app.core.enums import Provider, RelationshipType, ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import Comparison, ExpectedState, RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule


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
