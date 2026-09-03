"""The Phase A additions, each pinned in all four states.

Four rules over evidence CloudGuard already collected and did not judge:
WinRM reachable from the internet, a machine no security group governs, a
storage account that will still speak plain HTTP, and a sensitive database
reachable only over its public endpoint.

UNKNOWN is checked on every one of them, and each time it stands for a
different absence -- a failed listing, an unresolved network interface, a
configuration key the snapshot never carried. All four must stay distinct from
PASS.
"""

from typing import Any

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import Level, Provider, ResourceType, RuleState
from app.domain.resource import CloudResource
from app.rules.azure.compute.exposure import AzureUnguardedVmRule
from app.rules.azure.database.public_access import (
    AzureDatabasePrivateConnectivityRule,
)
from app.rules.azure.network.exposure import AzurePublicWinRmRule
from app.rules.azure.storage.public_access import AzureStorageTransportRule
from app.rules.base import RuleContext

WINRM = AzurePublicWinRmRule()
UNGUARDED = AzureUnguardedVmRule()
TRANSPORT = AzureStorageTransportRule()
PRIVATE_DB = AzureDatabasePrivateConnectivityRule()


def asset(
    resource_type: ResourceType,
    *,
    resource_id: str = "/x/asset",
    name: str = "asset",
    sensitivity: Level = Level.MEDIUM,
    **metadata: Any,
) -> CloudResource:
    return CloudResource(
        provider=Provider.AZURE,
        provider_resource_id=resource_id,
        resource_type=resource_type,
        name=name,
        criticality=Level.MEDIUM,
        data_sensitivity=sensitivity,
        public_exposure=Level.UNKNOWN,
        metadata=metadata,
    )


def nsg_rule(port: str, source: str = "0.0.0.0/0", protocol: str = "Tcp") -> dict:
    return {
        "name": f"allow-{port}",
        "direction": "Inbound",
        "access": "Allow",
        "protocol": protocol,
        "source": source,
        "destination_ports": [port],
    }


# --------------------------------------------------------------------- WinRM
class TestPublicWinRm:
    def test_the_http_listener_open_to_the_internet_fails(self) -> None:
        nsg = asset(
            ResourceType.NETWORK_SECURITY_GROUP, security_rules=[nsg_rule("5985")]
        )

        result = WINRM.evaluate(nsg, RuleContext(resources=[nsg]))

        assert result.state == RuleState.FAIL
        assert result.evidence["port"] == 5985

    def test_the_https_listener_is_the_same_finding(self) -> None:
        """One door, two frames. Reporting 5985 and 5986 separately would ask a
        customer to close the same thing twice."""
        nsg = asset(
            ResourceType.NETWORK_SECURITY_GROUP, security_rules=[nsg_rule("5986")]
        )

        result = WINRM.evaluate(nsg, RuleContext(resources=[nsg]))

        assert result.state == RuleState.FAIL
        assert result.evidence["port"] == 5986

    def test_a_restricted_source_passes(self) -> None:
        nsg = asset(
            ResourceType.NETWORK_SECURITY_GROUP,
            security_rules=[nsg_rule("5985", source="10.0.0.0/8")],
        )

        assert WINRM.evaluate(nsg, RuleContext(resources=[nsg])).state == RuleState.PASS

    def test_a_missing_rule_list_is_unknown(self) -> None:
        nsg = asset(ResourceType.NETWORK_SECURITY_GROUP)

        assert (
            WINRM.evaluate(nsg, RuleContext(resources=[nsg])).state == RuleState.UNKNOWN
        )

    def test_no_resource_is_not_applicable(self) -> None:
        assert WINRM.evaluate(None, RuleContext()).state == RuleState.NOT_APPLICABLE


# ------------------------------------------------------------ unguarded machine
class TestUnguardedVm:
    def test_a_machine_with_no_security_group_fails(self) -> None:
        vm = asset(ResourceType.VIRTUAL_MACHINE, has_public_ip=False, name="db-01")

        result = UNGUARDED.evaluate(vm, RuleContext(resources=[vm]))

        assert result.state == RuleState.FAIL
        assert result.evidence["guarding_nsgs"] == []

    def test_a_guarded_machine_passes(self) -> None:
        vm = asset(
            ResourceType.VIRTUAL_MACHINE, resource_id="/vms/web", has_public_ip=False
        )
        nsg = asset(
            ResourceType.NETWORK_SECURITY_GROUP, resource_id="/nsgs/web", name="web-nsg"
        )
        context = RuleContext(
            resources=[vm, nsg],
            relationships={("/nsgs/web", "protects"): ["/vms/web"]},
        )

        result = UNGUARDED.evaluate(vm, context)

        assert result.state == RuleState.PASS
        assert result.evidence["guarding_nsgs"] == ["web-nsg"]

    def test_an_internet_facing_machine_scores_higher(self) -> None:
        """Nothing filters it and it is already reachable, so the missing
        segmentation is not a second-order problem."""
        vm = asset(ResourceType.VIRTUAL_MACHINE, has_public_ip=True)

        result = UNGUARDED.evaluate(vm, RuleContext(resources=[vm]))

        assert result.state == RuleState.FAIL
        assert result.exploitability == 4

    def test_unresolved_interfaces_are_unknown_not_a_finding(self) -> None:
        """Security groups hang off the interfaces. If those never arrived,
        "no group found" and "we could not look" are the same observation, and
        only one of them is a finding."""
        vm = asset(ResourceType.VIRTUAL_MACHINE, has_public_ip=None)

        result = UNGUARDED.evaluate(vm, RuleContext(resources=[vm]))

        assert result.state == RuleState.UNKNOWN

    def test_a_failed_listing_is_unknown(self) -> None:
        vm = asset(ResourceType.VIRTUAL_MACHINE, has_public_ip=False)
        context = RuleContext(
            resources=[vm],
            collection_errors={AzureEvidence.NETWORK_INTERFACES.value: "timeout"},
        )

        assert UNGUARDED.evaluate(vm, context).state == RuleState.UNKNOWN

    def test_no_resource_is_not_applicable(self) -> None:
        assert UNGUARDED.evaluate(None, RuleContext()).state == RuleState.NOT_APPLICABLE


# ------------------------------------------------------------ storage transport
class TestStorageTransport:
    def test_plain_http_fails(self) -> None:
        account = asset(
            ResourceType.STORAGE_ACCOUNT,
            https_traffic_only=False,
            min_tls_version="TLS1_2",
        )

        result = TRANSPORT.evaluate(account, RuleContext(resources=[account]))

        assert result.state == RuleState.FAIL
        assert "HTTP" in result.evidence["problems"][0]

    def test_old_tls_fails(self) -> None:
        account = asset(
            ResourceType.STORAGE_ACCOUNT,
            https_traffic_only=True,
            min_tls_version="TLS1_0",
        )

        assert (
            TRANSPORT.evaluate(account, RuleContext(resources=[account])).state
            == RuleState.FAIL
        )

    def test_https_only_on_modern_tls_passes(self) -> None:
        account = asset(
            ResourceType.STORAGE_ACCOUNT,
            https_traffic_only=True,
            min_tls_version="TLS1_2",
        )

        assert (
            TRANSPORT.evaluate(account, RuleContext(resources=[account])).state
            == RuleState.PASS
        )

    def test_an_absent_tls_version_is_not_read_as_an_old_one(self) -> None:
        """Azure's own default has moved over time. Guessing it would be
        inventing the evidence this rule exists to report."""
        account = asset(ResourceType.STORAGE_ACCOUNT, https_traffic_only=True)

        assert (
            TRANSPORT.evaluate(account, RuleContext(resources=[account])).state
            == RuleState.PASS
        )

    def test_an_account_that_refuses_shared_keys_scores_lower(self) -> None:
        """What travels on the wire is the point. A key is the whole account
        and never expires; a token is neither."""
        account = asset(
            ResourceType.STORAGE_ACCOUNT,
            https_traffic_only=False,
            allow_shared_key_access=False,
        )

        result = TRANSPORT.evaluate(account, RuleContext(resources=[account]))

        assert result.state == RuleState.FAIL
        assert result.exploitability == 1

    def test_no_transport_configuration_is_unknown(self) -> None:
        account = asset(ResourceType.STORAGE_ACCOUNT)

        assert (
            TRANSPORT.evaluate(account, RuleContext(resources=[account])).state
            == RuleState.UNKNOWN
        )

    def test_no_resource_is_not_applicable(self) -> None:
        assert TRANSPORT.evaluate(None, RuleContext()).state == RuleState.NOT_APPLICABLE


# --------------------------------------------------------- database private path
class TestDatabasePrivateConnectivity:
    def test_a_sensitive_public_database_with_no_private_endpoint_fails(self) -> None:
        server = asset(
            ResourceType.SQL_SERVER,
            sensitivity=Level.HIGH,
            public_network_access="Enabled",
            private_endpoints=[],
        )

        result = PRIVATE_DB.evaluate(server, RuleContext(resources=[server]))

        assert result.state == RuleState.FAIL

    def test_a_private_endpoint_passes(self) -> None:
        server = asset(
            ResourceType.SQL_SERVER,
            sensitivity=Level.CRITICAL,
            public_network_access="Enabled",
            private_endpoints=["/pe/one"],
        )

        assert (
            PRIVATE_DB.evaluate(server, RuleContext(resources=[server])).state
            == RuleState.PASS
        )

    def test_a_disabled_public_endpoint_passes_however_it_was_reached(self) -> None:
        """A server nothing can dial is not waiting on a private endpoint to
        be safe."""
        server = asset(
            ResourceType.SQL_SERVER,
            sensitivity=Level.HIGH,
            public_network_access="Disabled",
            private_endpoints=[],
        )

        assert (
            PRIVATE_DB.evaluate(server, RuleContext(resources=[server])).state
            == RuleState.PASS
        )

    def test_an_ordinary_database_is_not_applicable(self) -> None:
        """Scoped deliberately. Raising this on every development server is how
        the real one gets lost among findings nobody was going to act on."""
        server = asset(
            ResourceType.SQL_SERVER,
            sensitivity=Level.MEDIUM,
            public_network_access="Enabled",
            private_endpoints=[],
        )

        assert (
            PRIVATE_DB.evaluate(server, RuleContext(resources=[server])).state
            == RuleState.NOT_APPLICABLE
        )

    def test_missing_connectivity_configuration_is_unknown(self) -> None:
        server = asset(ResourceType.SQL_SERVER, sensitivity=Level.HIGH)

        assert (
            PRIVATE_DB.evaluate(server, RuleContext(resources=[server])).state
            == RuleState.UNKNOWN
        )

    def test_a_failed_listing_is_unknown(self) -> None:
        server = asset(
            ResourceType.SQL_SERVER,
            sensitivity=Level.HIGH,
            public_network_access="Enabled",
        )
        context = RuleContext(
            resources=[server],
            collection_errors={AzureEvidence.SQL_SERVERS.value: "timeout"},
        )

        assert PRIVATE_DB.evaluate(server, context).state == RuleState.UNKNOWN
