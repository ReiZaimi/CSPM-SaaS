"""AZ-LOG-001."""

from dataclasses import replace

from app.core.enums import RuleState
from app.rules.azure.logging.diagnostics import AzureLoggingRule
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
