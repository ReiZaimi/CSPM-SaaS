"""The log an investigation starts from.

AZ-LOG-001 asks whether a resource records what happens *to* it. This asks
whether the subscription records who did it -- across every resource, including
the ones that no longer exist, which are the ones an incident is usually about.

It costs no customer a new permission, which is the interesting part of how it
was built: a subscription is a scope diagnostic settings apply to like any
other, so the existing ``Microsoft.Insights/diagnosticSettings/read`` reaches
it. The collector simply asks about one more id.
"""

from typing import Any

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import Level, Provider, ResourceType, RuleState
from app.domain.resource import CloudResource
from app.rules.azure.logging.diagnostics import AzureActivityLogExportRule
from app.rules.base import RuleContext

RULE = AzureActivityLogExportRule()

WORKSPACE = (
    "/subscriptions/s/resourceGroups/rg/providers"
    "/Microsoft.OperationalInsights/workspaces/central"
)


def subscription(settings: Any) -> CloudResource:
    metadata: dict[str, Any] = {"subscription_id": "s"}
    metadata["diagnostic_settings"] = settings
    return CloudResource(
        provider=Provider.AZURE,
        provider_resource_id="/subscriptions/s",
        resource_type=ResourceType.SUBSCRIPTION,
        name="s",
        criticality=Level.UNKNOWN,
        data_sensitivity=Level.UNKNOWN,
        public_exposure=Level.UNKNOWN,
        metadata=metadata,
    )


def setting(**destinations: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "name": "export",
        "workspace_id": None,
        "storage_account_id": None,
        "event_hub_id": None,
    }
    base.update(destinations)
    return base


def judge(resource: CloudResource) -> RuleState:
    return RULE.evaluate(resource, RuleContext(resources=[resource])).state


class TestActivityLogExport:
    def test_an_export_to_a_workspace_passes(self) -> None:
        assert judge(subscription([setting(workspace_id=WORKSPACE)])) == RuleState.PASS

    def test_an_export_to_storage_passes(self) -> None:
        """Where the logs go is the customer's choice. That they go somewhere
        is the finding."""
        assert (
            judge(subscription([setting(storage_account_id="/sa/logs")]))
            == RuleState.PASS
        )

    def test_no_setting_at_all_fails(self) -> None:
        result = RULE.evaluate(
            subscription([]), RuleContext(resources=[subscription([])])
        )

        assert result.state == RuleState.FAIL
        assert "90 days" in (result.message or "")

    def test_a_setting_with_no_destination_does_not_count(self) -> None:
        """An empty shell of a setting exports nothing. Counting it would let
        the presence of a row answer a question about where logs go."""
        assert judge(subscription([setting()])) == RuleState.FAIL

    def test_settings_that_could_not_be_read_are_unknown(self) -> None:
        """The collector records a per-resource error and the normalizer turns
        it into None. A subscription whose settings could not be read is not a
        subscription without them."""
        assert judge(subscription(None)) == RuleState.UNKNOWN

    def test_a_failed_collection_is_unknown(self) -> None:
        sub = subscription([])
        context = RuleContext(
            resources=[sub],
            collection_errors={AzureEvidence.DIAGNOSTIC_SETTINGS.value: "timeout"},
        )

        assert RULE.evaluate(sub, context).state == RuleState.UNKNOWN

    def test_no_resource_is_not_applicable(self) -> None:
        assert RULE.evaluate(None, RuleContext()).state == RuleState.NOT_APPLICABLE

    def test_it_judges_subscriptions_and_nothing_else(self) -> None:
        """AZ-LOG-001 covers the resources. If both rules claimed the same
        asset, one finding would be raised twice with two different fixes."""
        assert RULE.applies_to == [ResourceType.SUBSCRIPTION]


class TestItCostsNoNewPermission:
    def test_the_rule_reads_evidence_the_role_already_grants(self) -> None:
        """The reason this shipped ahead of the SQL and disk checks: a
        subscription is a scope diagnostic settings apply to like any other, so
        no customer redeploys anything to get it."""
        from app.connectors.azure import rbac

        assert RULE.requires_evidence == (AzureEvidence.DIAGNOSTIC_SETTINGS,)
        assert (
            "Microsoft.Insights/diagnosticSettings/read"
            in rbac.ROLE_HISTORY["v1"]
        )
