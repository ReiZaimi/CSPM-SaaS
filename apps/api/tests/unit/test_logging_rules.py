"""What keeps a record of what happened, and what does not."""

from dataclasses import replace

from app.core.enums import Level, Provider, ResourceType, RuleState
from app.domain.resource import CloudResource
from app.rules.azure.logging.diagnostics import (
    AzureCriticalResourceLoggingRule,
    AzureLoggingRule,
)
from tests.conftest import make_context, resource_from


class TestLoggingRule:
    rule = AzureLoggingRule()

    def test_no_diagnostic_settings_fails(self) -> None:
        storage = resource_from("vulnerable", "storage_public")
        result = self.rule.evaluate(storage, make_context(storage))
        assert result.state == RuleState.FAIL
        assert result.evidence["diagnostic_setting_count"] == 0

    def test_workspace_destination_passes(self) -> None:
        storage = resource_from("secure", "storage_locked_down")
        assert self.rule.evaluate(storage, make_context(storage)).state == RuleState.PASS

    def test_setting_with_no_destination_fails(self) -> None:
        """A diagnostic setting that forwards nowhere logs nothing."""
        storage = resource_from("secure", "storage_locked_down")
        hollow = replace(
            storage,
            metadata={**storage.metadata, "diagnostic_settings": [{"name": "empty"}]},
        )
        assert self.rule.evaluate(hollow, make_context(hollow)).state == RuleState.FAIL

    def test_unknown_when_not_collected(self) -> None:
        storage = resource_from("unknown", "storage_config_missing")
        assert self.rule.evaluate(storage, make_context(storage)).state == RuleState.UNKNOWN

    def test_does_not_apply_to_virtual_machines(self) -> None:
        vm = resource_from("secure", "vm_private")
        assert self.rule.matches(vm) is False


# ------------------------------------- the assets AZ-LOG-001 does not cover
def critical_resource(
    resource_type: ResourceType,
    *,
    settings: list | None,
    criticality: Level = Level.CRITICAL,
) -> CloudResource:
    metadata: dict = {}
    if settings is not None:
        metadata["diagnostic_settings"] = settings
    return CloudResource(
        provider=Provider.AZURE,
        provider_resource_id="/subscriptions/1/resource",
        resource_type=resource_type,
        name="asset",
        criticality=criticality,
        data_sensitivity=Level.MEDIUM,
        metadata=metadata,
    )


class TestCriticalResourceLogging:
    """AZ-LOG-004, over key vaults and machines -- the security-relevant types
    AZ-LOG-001 does not judge. Disjoint on purpose: one missing diagnostic
    setting must not become two findings and two deductions."""

    rule = AzureCriticalResourceLoggingRule()

    def test_a_vault_with_no_diagnostic_setting_fails(self) -> None:
        vault = critical_resource(ResourceType.KEY_VAULT, settings=[])
        result = self.rule.evaluate(vault, make_context(vault))
        assert result.state == RuleState.FAIL
        assert result.evidence["diagnostic_setting_count"] == 0

    def test_a_vault_is_judged_whatever_anybody_declared(self) -> None:
        """A vault holds the credentials to everything else. Waiting for a tag
        before asking whether anybody would see it being read is the wrong way
        round."""
        vault = critical_resource(
            ResourceType.KEY_VAULT, settings=[], criticality=Level.LOW
        )
        assert self.rule.evaluate(vault, make_context(vault)).state is RuleState.FAIL

    def test_a_critical_machine_with_no_setting_fails(self) -> None:
        vm = critical_resource(ResourceType.VIRTUAL_MACHINE, settings=[])
        assert self.rule.evaluate(vm, make_context(vm)).state is RuleState.FAIL

    def test_an_ordinary_machine_is_out_of_scope(self) -> None:
        """MEDIUM is where an untagged, undeclared machine lands, and logging
        every one of those is a catalogue-wide requirement rather than a
        statement about what a customer said matters."""
        vm = critical_resource(
            ResourceType.VIRTUAL_MACHINE, settings=[], criticality=Level.MEDIUM
        )
        assert (
            self.rule.evaluate(vm, make_context(vm)).state is RuleState.NOT_APPLICABLE
        )

    def test_a_configured_destination_passes(self) -> None:
        vm = critical_resource(
            ResourceType.VIRTUAL_MACHINE,
            settings=[{"name": "security-logs", "workspace_id": "/w"}],
        )
        assert self.rule.evaluate(vm, make_context(vm)).state is RuleState.PASS

    def test_a_reading_that_never_arrived_is_unknown(self) -> None:
        vault = critical_resource(ResourceType.KEY_VAULT, settings=None)
        assert self.rule.evaluate(vault, make_context(vault)).state is RuleState.UNKNOWN

    def test_the_two_logging_rules_judge_different_assets(self) -> None:
        """The guard on the split. If these ever overlap, one missing setting
        becomes two findings."""
        assert not set(AzureLoggingRule.applies_to) & set(
            AzureCriticalResourceLoggingRule.applies_to
        )
