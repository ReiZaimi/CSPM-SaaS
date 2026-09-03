"""Reading somebody else's verdicts without re-reporting them.

Defender for Cloud has already reached a conclusion about every asset it
assesses. Mirroring those as CloudGuard rules would turn two hundred
assessments into two hundred findings, none of which a customer could not
already see in the Azure portal.

What CloudGuard has that Defender does not is the graph. So an assessment is
read as *evidence*: Defender supplies the vulnerability, CloudGuard supplies
whether anything outside can reach the machine, and the finding is the pairing
-- which neither says alone.

The UNKNOWN case is the one to get right and the easiest to get wrong. A
subscription with no Defender plan returns no assessments, and reading that as
"no vulnerabilities" would be an absence of evidence reported as evidence of
absence, on the class of finding a customer is most likely to believe.
"""

from typing import Any

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import Level, Provider, ResourceType, RuleState
from app.domain.resource import CloudResource
from app.rules.azure.posture.defender import (
    AzureExposedVulnerableMachineRule,
    AzureMissingEndpointProtectionRule,
)
from app.rules.base import RuleContext

VULN = AzureExposedVulnerableMachineRule()
MALWARE = AzureMissingEndpointProtectionRule()


def finding(
    title: str,
    *,
    severity: str = "High",
    categories: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "assessment_id": "1195afff-c881-495e-9bc5-1486211ae03f",
        "title": title,
        "provider_severity": severity,
        "categories": categories or ["Compute"],
        "cause": None,
        "description": None,
    }


def machine(
    assessments: list[dict[str, Any]] | None,
    *,
    exposure: Level = Level.HIGH,
) -> CloudResource:
    metadata: dict[str, Any] = {"has_public_ip": exposure in (Level.HIGH, Level.CRITICAL)}
    if assessments is not None:
        metadata["security_assessments"] = assessments
    return CloudResource(
        provider=Provider.AZURE,
        provider_resource_id="/subscriptions/s/vms/web-01",
        resource_type=ResourceType.VIRTUAL_MACHINE,
        name="web-01",
        criticality=Level.HIGH,
        data_sensitivity=Level.MEDIUM,
        public_exposure=exposure,
        metadata=metadata,
    )


def judge(rule: Any, resource: CloudResource) -> RuleState:
    return rule.evaluate(resource, RuleContext(resources=[resource])).state


VULNERABLE = finding("Machines should have vulnerability findings resolved")


class TestExposedVulnerableMachine:
    def test_reachable_and_vulnerable_fails(self) -> None:
        result = VULN.evaluate(
            machine([VULNERABLE]), RuleContext(resources=[machine([VULNERABLE])])
        )

        assert result.state == RuleState.FAIL
        assert result.evidence["vulnerability_findings"]

    def test_vulnerable_but_unreachable_is_not_applicable(self) -> None:
        """Real, and a different finding. Defender already raises the
        vulnerability on its own terms; without the reachability there is
        nothing here CloudGuard knows that Defender did not say better."""
        assert (
            judge(VULN, machine([VULNERABLE], exposure=Level.LOW))
            == RuleState.NOT_APPLICABLE
        )

    def test_reachable_and_assessed_clean_passes(self) -> None:
        """An empty list is Defender having looked at this subscription and
        found nothing wrong with this machine. That is a reading."""
        assert judge(VULN, machine([])) == RuleState.PASS

    def test_a_low_severity_finding_does_not_raise_a_critical(self) -> None:
        """Worth knowing and not worth this rule. Raising every one would bury
        the pairing the rule exists to surface."""
        assert judge(VULN, machine([finding("Something minor", severity="Low")])) == (
            RuleState.PASS
        )

    def test_no_assessment_reaching_the_machine_is_unknown(self) -> None:
        """Defender not enabled, the plan not covering this resource type, or a
        role that predates the permission. None of those is "no
        vulnerabilities"."""
        result = VULN.evaluate(machine(None), RuleContext(resources=[machine(None)]))

        assert result.state == RuleState.UNKNOWN
        assert "Defender plan is off" in (result.message or "")

    def test_a_failed_assessment_listing_is_unknown(self) -> None:
        target = machine([VULNERABLE])
        context = RuleContext(
            resources=[target],
            collection_errors={AzureEvidence.SECURITY_ASSESSMENTS.value: "403 denied"},
        )

        assert VULN.evaluate(target, context).state == RuleState.UNKNOWN

    def test_no_resource_is_not_applicable(self) -> None:
        assert VULN.evaluate(None, RuleContext()).state == RuleState.NOT_APPLICABLE


PROTECTION = finding(
    "Endpoint protection should be installed on machines",
    severity="Medium",
    categories=["Compute"],
)


class TestMissingEndpointProtection:
    def test_a_machine_defender_reports_unprotected_fails(self) -> None:
        assert judge(MALWARE, machine([PROTECTION])) == RuleState.FAIL

    def test_it_does_not_depend_on_being_reachable(self) -> None:
        """Unlike the vulnerability rule. Malware arrives by mail and by USB as
        readily as over a public address, so exposure is not the qualifier
        here."""
        assert judge(MALWARE, machine([PROTECTION], exposure=Level.LOW)) == (
            RuleState.FAIL
        )

    def test_a_machine_with_other_findings_passes_this_one(self) -> None:
        """Each rule reads the assessments it is about. A vulnerability finding
        is not an endpoint protection finding, and matching loosely would have
        one rule answer for another."""
        assert judge(MALWARE, machine([VULNERABLE])) == RuleState.PASS

    def test_no_assessment_reaching_the_machine_is_unknown(self) -> None:
        assert judge(MALWARE, machine(None)) == RuleState.UNKNOWN

    def test_no_resource_is_not_applicable(self) -> None:
        assert MALWARE.evaluate(None, RuleContext()).state == RuleState.NOT_APPLICABLE


class TestTheyReadRatherThanRepeat:
    def test_both_declare_the_assessments_they_read(self) -> None:
        for rule in (VULN, MALWARE):
            assert rule.requires_evidence == (AzureEvidence.SECURITY_ASSESSMENTS,)

    def test_neither_carries_an_expected_state(self) -> None:
        """What has to change is on the machine -- a patch applied, an agent
        installed -- and CloudGuard reads neither directly. A declaration
        naming a field would describe a setting that does not exist."""
        for rule in (VULN, MALWARE):
            spec = rule.remediation_spec
            assert spec is not None
            assert spec.expected == ()
            assert spec.cli
            assert spec.enforceable is False

    def test_they_close_the_controls_four_frameworks_could_not_reach(self) -> None:
        """The reason this was the highest-leverage collection left. One API
        surface, and the malware and patching requirements of NIST 800-53, SOC 2
        and PCI stop being permanently uncoverable."""
        assert "SI-2" in VULN.compliance_mappings["NIST_800_53"]
        assert "RA-5" in VULN.compliance_mappings["NIST_800_53"]
        assert "CC6.8" in MALWARE.compliance_mappings["SOC2"]
        assert "5.2.1" in MALWARE.compliance_mappings["PCI_DSS_4"]
        assert set(VULN.compliance_mappings["PCI_DSS_4"]) == {"6.3.3", "11.3.1"}
