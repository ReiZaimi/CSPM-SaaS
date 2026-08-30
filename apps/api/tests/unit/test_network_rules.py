"""AZ-NET-001 / 002 / 003."""

import pytest

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import RuleState
from app.rules.azure.network.exposure import (
    AzureOpenNsgRule,
    AzurePublicRdpRule,
    AzurePublicSshRule,
    _port_matches,
)
from tests.conftest import make_context, resource_from


class TestPublicRdp:
    rule = AzurePublicRdpRule()

    def test_public_rdp_detected(self) -> None:
        nsg = resource_from("vulnerable", "nsg_public_rdp")
        result = self.rule.evaluate(nsg, make_context(nsg))
        assert result.state == RuleState.FAIL
        assert result.evidence["port"] == 3389
        assert result.evidence["source"] == "*"
        assert result.evidence["nsg_rule_name"] == "AllowRDPFromAnywhere"

    def test_public_rdp_not_detected(self) -> None:
        nsg = resource_from("secure", "nsg_restricted")
        result = self.rule.evaluate(nsg, make_context(nsg))
        assert result.state == RuleState.PASS

    def test_unknown_when_rules_not_collected(self) -> None:
        """The NSG exists but its rule list never arrived. Never PASS."""
        nsg = resource_from("unknown", "nsg_no_rules_collected")
        result = self.rule.evaluate(nsg, make_context(nsg))
        assert result.state == RuleState.UNKNOWN

    def test_unknown_when_network_collection_failed(self) -> None:
        nsg = resource_from("vulnerable", "nsg_public_rdp")
        ctx = make_context(
            nsg,
            collection_errors={
                AzureEvidence.NETWORK_SECURITY_GROUPS: "Azure API timeout"
            },
        )
        result = self.rule.evaluate(nsg, ctx)
        assert result.state == RuleState.UNKNOWN
        assert "timeout" in result.message

    def test_not_applicable_to_other_resource_types(self) -> None:
        storage = resource_from("secure", "storage_locked_down")
        assert self.rule.matches(storage) is False

    def test_evidence_records_attachment(self) -> None:
        """An unattached NSG is still reported, but the evidence says so."""
        nsg = resource_from("vulnerable", "nsg_public_rdp")
        result = self.rule.evaluate(nsg, make_context(nsg))
        assert result.evidence["attached"] is False


class TestPublicSsh:
    rule = AzurePublicSshRule()

    def test_public_ssh_detected(self) -> None:
        nsg = resource_from("vulnerable", "nsg_public_ssh")
        result = self.rule.evaluate(nsg, make_context(nsg))
        assert result.state == RuleState.FAIL
        assert result.evidence["port"] == 22
        assert result.evidence["source"] == "0.0.0.0/0"

    def test_ssh_restricted_passes(self) -> None:
        nsg = resource_from("secure", "nsg_restricted")
        result = self.rule.evaluate(nsg, make_context(nsg))
        assert result.state == RuleState.PASS

    def test_rdp_fixture_does_not_trigger_ssh_rule(self) -> None:
        """Rules must not bleed into each other's territory."""
        nsg = resource_from("vulnerable", "nsg_public_rdp")
        result = self.rule.evaluate(nsg, make_context(nsg))
        assert result.state == RuleState.PASS


class TestOpenNsg:
    rule = AzureOpenNsgRule()

    def test_all_ports_open_detected(self) -> None:
        nsg = resource_from("vulnerable", "nsg_all_ports_open")
        result = self.rule.evaluate(nsg, make_context(nsg))
        assert result.state == RuleState.FAIL
        assert any(v["ports"] == "all" for v in result.evidence["violations"])

    def test_public_database_port_detected(self) -> None:
        nsg = resource_from("vulnerable", "nsg_public_database_port")
        result = self.rule.evaluate(nsg, make_context(nsg))
        assert result.state == RuleState.FAIL
        assert any(v.get("service") == "PostgreSQL" for v in result.evidence["violations"])

    def test_public_https_alone_is_not_a_violation(self) -> None:
        """A public web server is a design decision, not a misconfiguration."""
        nsg = resource_from("secure", "nsg_restricted")
        result = self.rule.evaluate(nsg, make_context(nsg))
        assert result.state == RuleState.PASS

    def test_internal_range_on_sensitive_port_passes(self) -> None:
        """The 10.0.0.0/8 rule in this fixture spans port 3389 but is private."""
        nsg = resource_from("vulnerable", "nsg_public_database_port")
        result = self.rule.evaluate(nsg, make_context(nsg))
        names = [v["nsg_rule_name"] for v in result.evidence["violations"]]
        assert "AllowRDPRange" not in names

    def test_unknown_when_not_collected(self) -> None:
        nsg = resource_from("unknown", "nsg_no_rules_collected")
        result = self.rule.evaluate(nsg, make_context(nsg))
        assert result.state == RuleState.UNKNOWN


@pytest.mark.parametrize(
    ("spec", "target", "expected"),
    [
        ("3389", 3389, True),
        ("3389", 22, False),
        ("*", 3389, True),
        ("3000-4000", 3389, True),
        ("3000-4000", 5000, False),
        ("22,3389,443", 3389, True),
        ("22,443", 3389, False),
        ("not-a-port", 3389, False),
    ],
)
def test_port_matching(spec: str, target: int, expected: bool) -> None:
    assert _port_matches(spec, target) is expected
