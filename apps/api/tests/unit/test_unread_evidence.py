"""A listing that failed must cost a verdict, even when it listed nothing.

A rule reports UNKNOWN from inside ``evaluate``, and ``evaluate`` runs once per
matching resource. So a rule whose evidence failed to collect had nothing to
iterate and produced nothing at all: no verdict, no gap, and a coverage ratio
computed over the rules that happened to have something to look at.

The two facts behind "no resources came back" are not the same. Either the
customer has none of them, and the check genuinely does not apply; or the
listing that would have shown them failed. Reading the second as the first
makes failing to look cheaper than looking and finding a problem, which is the
same overclaim as a PASS nobody earned, arrived at through silence.
"""

from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import Level, Provider, ResourceType, RuleState
from app.domain.resource import CloudResource
from app.rules.base import RuleContext, RuleResult, SecurityRule
from app.rules.engine import RuleEngine


class StorageRule(SecurityRule):
    rule_id = "AZ-TEST-010"
    name = "Storage accounts refuse public access"
    description = "test"
    category = "storage"
    severity = "HIGH"  # type: ignore[assignment]
    provider = Provider.AZURE
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.STORAGE_ACCOUNT]
    requires_evidence: ClassVar[tuple] = (AzureEvidence.STORAGE_ACCOUNTS,)
    remediation = "az storage account update ..."

    def evaluate(self, resource, context):  # type: ignore[no-untyped-def]
        return RuleResult.passed()


def storage_account() -> CloudResource:
    return CloudResource(
        provider=Provider.AZURE,
        provider_resource_id="/subscriptions/s/storage/one",
        resource_type=ResourceType.STORAGE_ACCOUNT,
        name="one",
        region="westeurope",
        criticality=Level.UNKNOWN,
        data_sensitivity=Level.UNKNOWN,
        public_exposure=Level.UNKNOWN,
    )


def test_a_failed_listing_that_returned_nothing_is_recorded_as_unknown() -> None:
    """The hole this closes. Storage collection failed, so no storage account
    came back -- and the rule that reads them must say it could not tell, not
    fall silent."""
    context = RuleContext(
        resources=[],
        collection_errors={AzureEvidence.STORAGE_ACCOUNTS.value: "Azure timed out"},
    )

    report = RuleEngine([StorageRule()]).evaluate(context)

    assert len(report.gaps) == 1
    assert report.gaps[0].rule.rule_id == "AZ-TEST-010"
    # The verdict is about the scan, not about any one asset: there is no asset
    # to attribute it to, which is the whole point.
    assert report.gaps[0].resource is None
    assert "Azure timed out" in report.gaps[0].result.message
    assert report.coverage["AZ-TEST-010"].unknown_count == 1


def test_an_empty_listing_that_succeeded_stays_silent() -> None:
    """A customer with no storage accounts is not a gap in what we know.

    NOT_APPLICABLE is excluded from the coverage ratio for exactly this reason,
    and turning it into UNKNOWN would report a gap CloudGuard had invented --
    the same overclaim pointed the other way.
    """
    report = RuleEngine([StorageRule()]).evaluate(RuleContext(resources=[]))

    assert report.gaps == []
    assert report.coverage["AZ-TEST-010"].unknown_count == 0


def test_a_listing_that_returned_something_is_judged_as_before() -> None:
    """The added path is reached only when nothing matched. A rule with
    resources to look at reports on them, and reports its own UNKNOWN from
    inside ``evaluate`` if it decides the evidence is unusable."""
    context = RuleContext(
        resources=[storage_account()],
        collection_errors={AzureEvidence.STORAGE_ACCOUNTS.value: "Azure timed out"},
    )

    report = RuleEngine([StorageRule()]).evaluate(context)

    assert report.gaps == []
    assert report.coverage["AZ-TEST-010"].passed_count == 1


def test_a_rule_declaring_no_evidence_cannot_degrade_this_way() -> None:
    """``requires_evidence`` is the declaration that makes the dependency
    exact. A rule that declares nothing has named no listing that could have
    failed, so an unrelated error must not take its verdict."""

    class Undeclared(StorageRule):
        rule_id = "AZ-TEST-011"
        requires_evidence: ClassVar[tuple] = ()

    context = RuleContext(
        resources=[],
        collection_errors={AzureEvidence.STORAGE_ACCOUNTS.value: "Azure timed out"},
    )

    report = RuleEngine([Undeclared()]).evaluate(context)

    assert report.gaps == []
    assert RuleState.UNKNOWN not in {g.result.state for g in report.gaps}
