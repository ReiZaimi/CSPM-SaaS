"""AZ-CMP-001 -- the rule that combines exposure with an open admin port."""

from app.core.enums import RuleState
from app.rules.azure.compute.exposure import AzureExposedComputeRule
from tests.conftest import make_context, resource_from


class TestExposedCompute:
    rule = AzureExposedComputeRule()

    def test_public_vm_with_open_rdp_fails(self) -> None:
        vm = resource_from("vulnerable", "vm_public_rdp")
        nsg = resource_from("vulnerable", "nsg_public_rdp")
        ctx = make_context(
            vm,
            nsg,
            relationships={
                (nsg.provider_resource_id, "protects"): [vm.provider_resource_id]
            },
        )
        result = self.rule.evaluate(vm, ctx)
        assert result.state == RuleState.FAIL
        assert result.evidence["exposed_services"][0]["service"] == "RDP"

    def test_public_vm_with_restricted_nsg_passes(self) -> None:
        vm = resource_from("vulnerable", "vm_public_rdp")
        nsg = resource_from("secure", "nsg_restricted")
        ctx = make_context(
            vm,
            nsg,
            relationships={
                (nsg.provider_resource_id, "protects"): [vm.provider_resource_id]
            },
        )
        assert self.rule.evaluate(vm, ctx).state == RuleState.PASS

    def test_private_vm_passes_without_consulting_nsgs(self) -> None:
        """No public IP means no internet-facing exposure, whatever the NSG says."""
        vm = resource_from("secure", "vm_private")
        result = self.rule.evaluate(vm, make_context(vm))
        assert result.state == RuleState.PASS
        assert result.evidence["has_public_ip"] is False

    def test_unknown_when_attachment_unresolved(self) -> None:
        vm = resource_from("unknown", "vm_network_unresolved")
        assert self.rule.evaluate(vm, make_context(vm)).state == RuleState.UNKNOWN

    def test_unknown_when_public_ip_but_no_nsg_resolved(self) -> None:
        """We know it is exposed but cannot see what guards it -- not a PASS."""
        vm = resource_from("vulnerable", "vm_public_rdp")
        assert self.rule.evaluate(vm, make_context(vm)).state == RuleState.UNKNOWN

    def test_unknown_when_collection_failed(self) -> None:
        vm = resource_from("vulnerable", "vm_public_rdp")
        ctx = make_context(vm, collection_errors={"compute": "throttled"})
        assert self.rule.evaluate(vm, ctx).state == RuleState.UNKNOWN
