"""What the internet can reach, port by port and machine by machine."""

import pytest

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import Level, Provider, ResourceType, RuleState
from app.domain.resource import CloudResource
from app.rules.azure.network.exposure import (
    AzureOpenNsgRule,
    AzurePublicRdpRule,
    AzurePublicSmbRule,
    AzurePublicSqlPortRule,
    AzurePublicSshRule,
    AzureSensitivePublicAddressRule,
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

    def test_a_group_protecting_nothing_is_not_scored_as_reachable(self) -> None:
        """The same rule text, none of the reach. Nobody can connect to a
        machine this group does not protect, so what is left is a latent
        mistake -- worth fixing before it is attached to something, and not the
        thing being scanned for RDP this afternoon."""
        nsg = resource_from("vulnerable", "nsg_public_rdp")
        result = self.rule.evaluate(nsg, make_context(nsg))

        assert result.exploitability == 1
        assert self.rule.effective_exploitability(result) == 1
        assert "protects nothing" in result.message

    def test_a_group_that_guards_a_machine_keeps_the_rule_tag(self) -> None:
        vm = resource_from("vulnerable", "vm_public_rdp")
        nsg = resource_from("vulnerable", "nsg_public_rdp")
        context = make_context(
            nsg,
            vm,
            relationships={
                (nsg.provider_resource_id, "protects"): [vm.provider_resource_id]
            },
        )

        result = self.rule.evaluate(nsg, context)

        assert result.evidence["attached"] is True
        assert result.exploitability is None
        assert self.rule.effective_exploitability(result) == self.rule.exploitability


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


# --------------------------------------------- the two services with their own rule
def nsg_with(port: str, source: str = "*") -> CloudResource:
    return CloudResource(
        provider=Provider.AZURE,
        provider_resource_id="/subscriptions/1/nsg",
        resource_type=ResourceType.NETWORK_SECURITY_GROUP,
        name="nsg",
        metadata={
            "security_rules": [
                {
                    "name": "AllowIt",
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "source": source,
                    "destination_ports": [port],
                    "priority": 100,
                }
            ]
        },
    )


class TestPublicSqlPort:
    """AZ-NET-005. A database engine answering the open internet is attacked
    continuously, and the credentials it accepts are an application's."""

    rule = AzurePublicSqlPortRule()

    def test_open_1433_fails(self) -> None:
        nsg = nsg_with("1433")
        result = self.rule.evaluate(nsg, make_context(nsg))
        assert result.state == RuleState.FAIL
        assert result.evidence["port"] == 1433

    def test_a_port_range_covering_it_fails(self) -> None:
        """Azure spells a range as one string, and a rule reading only exact
        matches would miss the way most of these are actually written."""
        nsg = nsg_with("1400-1500")
        assert self.rule.evaluate(nsg, make_context(nsg)).state is RuleState.FAIL

    def test_a_restricted_source_passes(self) -> None:
        nsg = nsg_with("1433", source="10.0.0.0/8")
        assert self.rule.evaluate(nsg, make_context(nsg)).state is RuleState.PASS


class TestPublicSmb:
    """AZ-NET-008. WannaCry and NotPetya both spread over this port."""

    rule = AzurePublicSmbRule()

    def test_open_445_fails(self) -> None:
        nsg = nsg_with("445")
        result = self.rule.evaluate(nsg, make_context(nsg))
        assert result.state == RuleState.FAIL
        assert result.evidence["port"] == 445

    def test_a_restricted_source_passes(self) -> None:
        nsg = nsg_with("445", source="10.0.0.0/8")
        assert self.rule.evaluate(nsg, make_context(nsg)).state is RuleState.PASS


class TestTheCatchAllStopsWhereTheNamedRulesStart:
    """AZ-NET-003 keeps the ports that have no rule of their own.

    A port listed in both places raises two findings for one NSG rule and
    deducts from the security score twice for closing it, which is the same
    double-reporting the RDP, SSH and WinRM rules were already kept out of.
    """

    def test_sql_and_smb_are_not_in_the_catch_all(self) -> None:
        assert 1433 not in AzureOpenNsgRule.SENSITIVE_PORTS
        assert 445 not in AzureOpenNsgRule.SENSITIVE_PORTS

    def test_no_named_port_is_in_the_catch_all(self) -> None:
        named = {
            AzurePublicRdpRule.port,
            AzurePublicSshRule.port,
            AzurePublicSqlPortRule.port,
            AzurePublicSmbRule.port,
        }
        assert not named & set(AzureOpenNsgRule.SENSITIVE_PORTS)

    def test_a_port_with_no_rule_of_its_own_is_still_reported(self) -> None:
        """The catch-all still earns its place: Redis on the internet has no
        rule of its own and is not a design."""
        nsg = nsg_with("6379")
        assert (
            AzureOpenNsgRule().evaluate(nsg, make_context(nsg)).state is RuleState.FAIL
        )


# ------------------------------------------------ an address on a machine that matters
def machine(
    *,
    public: bool | None,
    sensitivity: Level = Level.HIGH,
    criticality: Level = Level.MEDIUM,
) -> CloudResource:
    metadata: dict = {"guarding_nsgs": []}
    if public is not None:
        metadata["has_public_ip"] = public
        metadata["public_ips"] = ["203.0.113.10"] if public else []
    return CloudResource(
        provider=Provider.AZURE,
        provider_resource_id="/subscriptions/1/vm",
        resource_type=ResourceType.VIRTUAL_MACHINE,
        name="vm",
        criticality=criticality,
        data_sensitivity=sensitivity,
        metadata=metadata,
    )


class TestSensitiveMachineWithAnAddress:
    """AZ-NET-015. The exposure of a machine with its own public address is
    whatever its NSG allows today and after every future change to it."""

    rule = AzureSensitivePublicAddressRule()

    def test_a_sensitive_machine_with_a_public_address_fails(self) -> None:
        vm = machine(public=True, sensitivity=Level.HIGH)
        result = self.rule.evaluate(vm, make_context(vm))
        assert result.state == RuleState.FAIL
        assert result.evidence["public_ips"] == ["203.0.113.10"]

    def test_business_criticality_counts_as_well_as_data(self) -> None:
        """Either half of what the estate says about an asset. A machine
        nothing runs without is worth keeping off the internet even if it
        stores nothing regulated."""
        vm = machine(public=True, sensitivity=Level.LOW, criticality=Level.CRITICAL)
        assert self.rule.evaluate(vm, make_context(vm)).state is RuleState.FAIL

    def test_an_unclassified_machine_is_out_of_scope(self) -> None:
        """Not a pass. AZ-CMP-001 already reports what the internet can reach;
        this rule is about the data on the machine."""
        vm = machine(public=True, sensitivity=Level.MEDIUM, criticality=Level.MEDIUM)
        assert (
            self.rule.evaluate(vm, make_context(vm)).state is RuleState.NOT_APPLICABLE
        )

    def test_a_sensitive_machine_with_no_address_passes(self) -> None:
        vm = machine(public=False, sensitivity=Level.CRITICAL)
        assert self.rule.evaluate(vm, make_context(vm)).state is RuleState.PASS

    def test_a_machine_whose_interfaces_never_arrived_is_unknown(self) -> None:
        vm = machine(public=None, sensitivity=Level.HIGH)
        assert self.rule.evaluate(vm, make_context(vm)).state is RuleState.UNKNOWN
