"""Normalization: real ARM/Graph payload shapes -> cloud-neutral resources.

This is the seam where a silent mistake would be most expensive: if the
normalizer drops a field, every rule downstream reports UNKNOWN or PASS on data
that was actually collected.
"""

import json
from pathlib import Path

import pytest

from app.connectors.azure.evidence import AzureEvidence
from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.base import RawSnapshot
from app.core.enums import Level, Provider, RelationshipType, ResourceType
from app.rules.base import RuleContext
from app.rules.engine import RuleEngine

RAW = Path(__file__).parent.parent / "fixtures" / "azure_raw"


def load_snapshot(name: str) -> RawSnapshot:
    raw = json.loads((RAW / f"{name}.json").read_text())
    return RawSnapshot(
        provider=Provider(raw["provider"]),
        tenant_id=raw["tenant_id"],
        subscription_id=raw["subscription_id"],
        version=raw["version"],
        data=raw["data"],
        errors=raw["errors"],
    )


@pytest.fixture
def state():
    return AzureNormalizer().normalize(load_snapshot("snapshot_mixed"))


def by_type(state, resource_type: ResourceType):
    return [r for r in state.resources if r.resource_type == resource_type]


class TestNsgNormalization:
    def test_singular_and_plural_port_fields_both_normalize(self, state) -> None:
        """ARM writes destinationPortRange OR destinationPortRanges."""
        nsg = by_type(state, ResourceType.NETWORK_SECURITY_GROUP)[0]
        rules = {r["name"]: r for r in nsg.metadata["security_rules"]}
        assert rules["AllowRDP"]["destination_ports"] == ["3389"]
        assert rules["AllowHTTPS"]["destination_ports"] == ["443"]

    def test_source_prefix_is_flattened(self, state) -> None:
        nsg = by_type(state, ResourceType.NETWORK_SECURITY_GROUP)[0]
        rules = {r["name"]: r for r in nsg.metadata["security_rules"]}
        assert rules["AllowRDP"]["source"] == "*"
        assert rules["AllowHTTPS"]["source"] == "Internet"

    def test_open_rdp_drives_critical_exposure(self, state) -> None:
        nsg = by_type(state, ResourceType.NETWORK_SECURITY_GROUP)[0]
        assert nsg.public_exposure == Level.CRITICAL

    def test_environment_tag_is_read(self, state) -> None:
        nsg = by_type(state, ResourceType.NETWORK_SECURITY_GROUP)[0]
        assert nsg.environment == "production"
        assert nsg.criticality == Level.HIGH


class TestVmNormalization:
    def test_public_ip_resolved_through_the_nic(self, state) -> None:
        vm = by_type(state, ResourceType.VIRTUAL_MACHINE)[0]
        assert vm.metadata["has_public_ip"] is True
        assert vm.metadata["public_ips"] == ["20.50.10.10"]

    def test_nsg_edge_points_from_nsg_to_vm(self, state) -> None:
        edges = [e for e in state.relationships if e[1] == RelationshipType.PROTECTS]
        assert len(edges) == 1
        source, _, target = edges[0]
        assert source.endswith("networkSecurityGroups/nsg-jumpbox")
        assert target.endswith("virtualMachines/vm-jumpbox")

    def test_explicit_criticality_tag_wins(self, state) -> None:
        vm = by_type(state, ResourceType.VIRTUAL_MACHINE)[0]
        assert vm.criticality == Level.HIGH


class TestStorageNormalization:
    def test_public_access_flags_carried_across(self, state) -> None:
        storage = by_type(state, ResourceType.STORAGE_ACCOUNT)[0]
        assert storage.metadata["allow_blob_public_access"] is True
        assert storage.metadata["network_default_action"] == "Allow"
        assert storage.metadata["min_tls_version"] == "TLS1_2"

    def test_untagged_storage_is_not_assumed_low_criticality(self, state) -> None:
        """No tag and no naming hint must yield UNKNOWN, never LOW."""
        storage = by_type(state, ResourceType.STORAGE_ACCOUNT)[0]
        assert storage.criticality == Level.UNKNOWN

    def test_storage_holds_data_so_sensitivity_has_a_floor(self, state) -> None:
        storage = by_type(state, ResourceType.STORAGE_ACCOUNT)[0]
        assert storage.data_sensitivity == Level.HIGH

    def test_empty_diagnostics_list_is_not_none(self, state) -> None:
        """Collected-and-empty must stay distinguishable from never-collected."""
        storage = by_type(state, ResourceType.STORAGE_ACCOUNT)[0]
        assert storage.metadata["diagnostic_settings"] == []


class TestDatabaseNormalization:
    def test_firewall_rules_are_flattened(self, state) -> None:
        server = by_type(state, ResourceType.SQL_SERVER)[0]
        rules = server.metadata["firewall_rules"]
        assert rules[0]["start_ip_address"] == "0.0.0.0"
        assert rules[0]["end_ip_address"] == "255.255.255.255"

    def test_open_firewall_drives_critical_exposure(self, state) -> None:
        server = by_type(state, ResourceType.SQL_SERVER)[0]
        assert server.public_exposure == Level.CRITICAL

    def test_env_prod_shorthand_recognised(self, state) -> None:
        server = by_type(state, ResourceType.SQL_SERVER)[0]
        assert server.criticality == Level.HIGH


class TestIdentityNormalization:
    def test_directory_roles_attached_to_user(self, state) -> None:
        users = {u.name: u for u in by_type(state, ResourceType.USER)}
        assert users["Arben K"].metadata["directory_roles"] == ["Global Administrator"]

    def test_graph_odata_type_becomes_a_readable_method_name(self, state) -> None:
        users = {u.name: u for u in by_type(state, ResourceType.USER)}
        assert users["Arben K"].metadata["mfa_methods"] == ["password"]

    def test_unqueried_user_has_no_mfa_key_at_all(self, state) -> None:
        """Absent, not empty: the rule must say UNKNOWN, not "no MFA"."""
        users = {u.name: u for u in by_type(state, ResourceType.USER)}
        assert "mfa_methods" not in users["Normal User"].metadata


class TestCollectionErrorPropagation:
    def test_gaps_reach_the_rule_context(self) -> None:
        """The rules degrade on ``gaps``, keyed per evidence key.

        ``errors`` is the sibling category summary the scan banner reads. The
        two are derived from one coverage report and must not be confused: a
        rule that read the category view would go UNKNOWN over listings it never
        touched.
        """
        snapshot = load_snapshot("snapshot_mixed")
        snapshot.gaps[AzureEvidence.STORAGE_ACCOUNTS] = "Azure API timeout"
        state = AzureNormalizer().normalize(snapshot)
        assert (
            state.collection_errors[AzureEvidence.STORAGE_ACCOUNTS]
            == "Azure API timeout"
        )

    def test_the_category_summary_does_not_degrade_a_rule_on_its_own(self) -> None:
        """A category is a permission, not a listing.

        Degrading on it would cost AZ-DB-001 its verdict whenever the
        PostgreSQL listing failed, over SQL servers it had read perfectly well.
        """
        snapshot = load_snapshot("snapshot_mixed")
        snapshot.errors["storage"] = "Azure API timeout"
        state = AzureNormalizer().normalize(snapshot)
        assert state.collection_errors == {}


class TestEndToEndEvaluation:
    """The whole point: raw Azure JSON in, findings out."""

    def test_normalized_snapshot_produces_expected_findings(self, state) -> None:
        context = RuleContext(
            resources=state.resources,
            relationships=_edges(state),
            collection_errors=state.collection_errors,
        )
        report = RuleEngine().evaluate(context)
        failed = {e.rule.rule_id for e in report.failures}

        assert "AZ-NET-001" in failed   # RDP open to the world
        assert "AZ-STO-001" in failed   # public blob access
        assert "AZ-DB-001" in failed    # SQL firewall allows all
        assert "AZ-ID-001" in failed    # admin with password only
        assert "AZ-CMP-001" in failed   # public VM with RDP open
        assert "AZ-LOG-001" in failed   # storage has no diagnostics

    def test_ssh_rule_does_not_fire_on_an_rdp_only_environment(self, state) -> None:
        context = RuleContext(
            resources=state.resources,
            relationships=_edges(state),
            collection_errors=state.collection_errors,
        )
        report = RuleEngine().evaluate(context)
        assert "AZ-NET-002" not in {e.rule.rule_id for e in report.failures}

    def test_storage_collection_failure_degrades_to_unknown_not_pass(self) -> None:
        snapshot = load_snapshot("snapshot_mixed")
        snapshot.gaps[AzureEvidence.STORAGE_ACCOUNTS] = "Azure API timeout"
        state = AzureNormalizer().normalize(snapshot)
        context = RuleContext(
            resources=state.resources,
            relationships=_edges(state),
            collection_errors=state.collection_errors,
        )
        report = RuleEngine().evaluate(context)

        assert "AZ-STO-001" not in {e.rule.rule_id for e in report.failures}
        assert "AZ-STO-001" in {e.rule.rule_id for e in report.gaps}
        assert report.coverage["AZ-STO-001"].passed_count == 0
        # And coverage honestly reflects that we know less than before.
        assert report.coverage_ratio < 1.0


def _edges(state) -> dict:
    grouped: dict = {}
    for source, rel_type, target in state.relationships:
        grouped.setdefault((source, rel_type.value), []).append(target)
    return grouped
