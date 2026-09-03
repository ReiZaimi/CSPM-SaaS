"""Rules over Microsoft Defender for Cloud's own findings.

The line these hold is worth stating, because it is easy to cross. Defender has
already reached a verdict on every asset it assesses, and mirroring those
verdicts as CloudGuard rules would be re-reporting somebody else's product: two
hundred assessments become two hundred findings, none of which the customer
could not already see in the Azure portal.

What CloudGuard has that Defender does not is the graph. Defender can say a
machine has an unremediated critical vulnerability; it does not weigh that
against whether the machine answers the internet, runs as an identity that can
act across the subscription, or sits one hop from the storage account holding
the customer's data. So these rules treat an assessment as *evidence* and reach
their own conclusion from it plus what CloudGuard established itself.

Severity is Microsoft's, kept under Microsoft's name. The two scales were tuned
by different people for different purposes, and quietly equating them would put
somebody else's judgement inside this product's risk formula.
"""

from typing import Any, ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import Level, ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule

# Defender's own severities, worst first.
SERIOUS = {"high", "medium"}


def _findings(resource: CloudResource) -> list[dict[str, Any]] | None:
    """This asset's unhealthy assessments, or None if Defender never spoke.

    None and ``[]`` are different answers and the difference decides the
    verdict. An empty list is Defender having assessed this subscription and
    found nothing wrong with this asset. None is no assessment reaching it at
    all -- Defender not enabled, the plan not covering this resource type, or
    the listing refused -- and calling that clean would be reporting an
    absence of evidence as evidence of absence, on the one class of finding
    where a customer is most likely to believe it.
    """
    found = resource.get("security_assessments")
    if found is None:
        return None
    return [f for f in found if isinstance(f, dict)]


def _matching(findings: list[dict[str, Any]], *words: str) -> list[dict[str, Any]]:
    """Findings whose category or title mentions any of these words.

    Matched on Defender's *category* first, which is the stable field, and on
    the title only as a fallback. Microsoft rewords display names between
    releases; a check resting on the wording alone stops matching without ever
    failing, which is the silent kind.
    """
    hits = []
    for finding in findings:
        haystack = " ".join(
            [
                *(str(c) for c in finding.get("categories") or []),
                str(finding.get("title") or ""),
            ]
        ).lower()
        if any(word in haystack for word in words):
            hits.append(finding)
    return hits


class _DefenderRule(SecurityRule):
    """Shared plumbing: read the assessments, or say why you cannot."""

    category = "posture"
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.SECURITY_ASSESSMENTS,
    )
    # The fix is in Defender or on the machine, not in a field CloudGuard reads.
    # An expectation naming one would describe a setting that does not exist.
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "az security assessment list --query "
            '"[?properties.status.code==\'Unhealthy\'].{name:properties.displayName,'
            'resource:properties.resourceDetails.Id}" --output table',
        ),
        notes=(
            "No expected state and no policy. What has to change is on the machine "
            "-- a patch applied, an agent installed -- and CloudGuard reads neither "
            "directly: it reads what Defender concluded. The command lists the open "
            "assessments so the finding can be followed back to Defender, which is "
            "where the remediation actually happens."
        ),
    )

    def _guard(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | None:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(
                f"Microsoft Defender for Cloud assessments unavailable: {failure}"
            )
        if _findings(resource) is None:
            return RuleResult.unknown(
                "No Defender for Cloud assessment covers this resource. Either the "
                "relevant Defender plan is off for this subscription, or the "
                "deployed scanner role predates the permission that reads them."
            )
        return None


class AzureExposedVulnerableMachineRule(_DefenderRule):
    rule_id = "AZ-VULN-001"
    name = "Internet-facing machine has unpatched vulnerabilities"
    description = (
        "Microsoft Defender for Cloud reports unremediated vulnerabilities on a "
        "machine that also answers the internet. Either fact is ordinary on its "
        "own; together they are a host an attacker can reach and a way in once "
        "they have."
    )
    severity = Severity.CRITICAL
    # Nothing but the internet and a published exploit. This is the highest
    # number in the catalogue and it is earned: the vulnerability is known, the
    # host is reachable, and no credential stands between the two.
    exploitability = 5
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.VIRTUAL_MACHINE]
    estimated_effort_minutes = 120
    rationale = (
        "This is the pairing that turns a patch backlog into an incident. A "
        "vulnerable machine behind a private network is work to schedule; the same "
        "machine with a public address is work that was already due. Defender "
        "reports the vulnerability and CloudGuard supplies the half Defender does "
        "not weigh -- whether anything outside can reach it."
    )
    remediation = (
        "Take the exposure away first, then the vulnerability.\n\n"
        "Removing the public IP or closing the port is minutes of work and ends "
        "the reachability today; patching is scheduled work that ends the "
        "vulnerability. Doing them in that order means the window closes now "
        "rather than at the next maintenance slot.\n\n"
        "Azure Portal: Defender for Cloud > Recommendations, filtered to this "
        "machine, lists what to apply. Reach the host through Azure Bastion or "
        "just-in-time access rather than a standing public address."
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["2"],
        "ISO_27001": ["A.8.8"],
        "NIST_CSF": ["PR.AC-5", "DE.CM-1"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["RA-5", "SI-2"],
        "SOC2": ["CC7.1"],
        "PCI_DSS_4": ["6.3.3", "11.3.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        guard = self._guard(resource, context)
        if guard is not None:
            return guard
        assert resource is not None

        findings = _findings(resource) or []
        # Serious ones only, on Microsoft's scale. A low-severity finding on a
        # reachable host is worth knowing and is not worth a CRITICAL, and
        # raising every one of them here would bury the pairing this rule
        # exists to surface.
        vulnerabilities = [
            finding
            for finding in _matching(findings, "vulnerab", "patch", "update")
            if str(finding.get("provider_severity") or "").lower() in SERIOUS
        ]

        exposed = resource.public_exposure in (Level.HIGH, Level.CRITICAL)
        evidence = {
            "public_exposure": resource.public_exposure.value,
            "has_public_ip": resource.get("has_public_ip"),
            "vulnerability_findings": vulnerabilities,
            "assessment_count": len(findings),
        }

        if not vulnerabilities:
            return RuleResult.passed(evidence)

        if not exposed:
            # Real, and a different finding. Defender already raises the
            # vulnerability; what this rule adds is the reachability, and
            # without it there is nothing here CloudGuard knows that Defender
            # did not say better.
            return RuleResult.not_applicable(
                "Vulnerabilities are reported here, and this machine is not "
                "reachable from the internet. Defender for Cloud raises them on "
                "their own terms."
            )

        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"{resource.name} answers the internet and has "
                f"{len(vulnerabilities)} unremediated "
                f"{'vulnerability' if len(vulnerabilities) == 1 else 'vulnerabilities'} "
                "reported by Defender for Cloud"
            ),
        )


class AzureMissingEndpointProtectionRule(_DefenderRule):
    rule_id = "AZ-MAL-001"
    name = "Machine has no working endpoint protection"
    description = (
        "Microsoft Defender for Cloud reports that this machine has no endpoint "
        "protection installed, or that what is installed is not reporting "
        "healthy."
    )
    severity = Severity.MEDIUM
    # Needs something to have arrived on the host already. What is missing is
    # the layer that would have caught it, which is defence in depth rather
    # than a way in.
    exploitability = 2
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.VIRTUAL_MACHINE]
    estimated_effort_minutes = 60
    rationale = (
        "Every framework that mentions malware wants this and CloudGuard could "
        "not answer it: nothing in an ARM configuration says whether an agent is "
        "installed and healthy, and only the machine knows. Defender does, so "
        "this is the check that turns four uncoverable controls -- NIST SI-2, "
        "SOC 2 CC6.8, PCI 5.2.1 among them -- into ones with evidence behind "
        "them."
    )
    remediation = (
        "Install endpoint protection, or fix the agent that is already there.\n\n"
        "Azure Portal: Defender for Cloud > Recommendations > 'Endpoint protection "
        "should be installed on machines' lists the affected hosts and offers a "
        "Fix action for most of them. A machine reporting unhealthy rather than "
        "missing usually has an agent that has stopped checking in, which is a "
        "different problem with the same consequence."
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.8.8"],
        "NIST_CSF": ["DE.CM-1"],
        "NIST_800_53": ["SI-2"],
        "SOC2": ["CC6.8"],
        "PCI_DSS_4": ["5.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        guard = self._guard(resource, context)
        if guard is not None:
            return guard
        assert resource is not None

        findings = _findings(resource) or []
        protection = _matching(findings, "endpoint protection", "antimalware", "malware")

        evidence = {
            "endpoint_protection_findings": protection,
            "assessment_count": len(findings),
        }
        if not protection:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"Defender for Cloud reports no working endpoint protection on "
                f"{resource.name}"
            ),
        )
