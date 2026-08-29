"""A rule may only judge its own cloud.

Resource types are cloud-neutral by design -- an S3 bucket and an Azure storage
account both normalize to ``STORAGE_ACCOUNT`` -- so matching on type alone let
an Azure rule evaluate an AWS bucket and raise a finding carrying
``az storage account update`` as the fix for it. ``SecurityRule.provider`` was
declared from the start and never read.

Harmless while Azure is the only connector, which is why it is pinned here:
these tests fail loudly today if the check is removed, rather than months from
now as findings nobody can explain.
"""

from typing import ClassVar

from app.core.enums import Level, Provider, ResourceType, RuleScope
from app.domain.resource import CloudResource
from app.rules.base import RuleContext, RuleResult, SecurityRule
from app.rules.engine import RuleEngine


def resource(provider: Provider, name: str) -> CloudResource:
    return CloudResource(
        provider=provider,
        provider_resource_id=f"/{provider.value}/{name}",
        resource_type=ResourceType.STORAGE_ACCOUNT,
        name=name,
        region="somewhere",
        criticality=Level.UNKNOWN,
        data_sensitivity=Level.UNKNOWN,
        public_exposure=Level.UNKNOWN,
    )


class AzureStorageRule(SecurityRule):
    rule_id = "AZ-TEST-001"
    name = "Azure storage is private"
    description = "test"
    category = "storage"
    severity = "HIGH"  # type: ignore[assignment]
    provider = Provider.AZURE
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.STORAGE_ACCOUNT]
    remediation = "az storage account update ..."

    def evaluate(self, resource, context):  # type: ignore[no-untyped-def]
        return RuleResult.failed()


class AzureInventoryRule(SecurityRule):
    """AGGREGATE rules never reach ``matches`` -- they read the context."""

    rule_id = "AZ-TEST-002"
    name = "Azure inventory"
    description = "test"
    category = "storage"
    severity = "LOW"  # type: ignore[assignment]
    provider = Provider.AZURE
    scope = RuleScope.AGGREGATE
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.STORAGE_ACCOUNT]

    def evaluate(self, resource, context):  # type: ignore[no-untyped-def]
        return [
            RuleResult.failed(resource_id=r.provider_resource_id)
            for r in context.get_resources_by_type(ResourceType.STORAGE_ACCOUNT)
        ]


# ------------------------------------------------------------------ matches
def test_a_rule_matches_a_resource_from_its_own_cloud() -> None:
    assert AzureStorageRule().matches(resource(Provider.AZURE, "sa"))


def test_a_rule_does_not_match_another_cloud_s_resource_of_the_same_type() -> None:
    """The defect. Both normalize to STORAGE_ACCOUNT, and only the provider
    tells them apart."""
    assert not AzureStorageRule().matches(resource(Provider.AWS, "bucket"))


# ------------------------------------------------------- the aggregate path
def test_an_aggregate_rule_sees_only_its_own_cloud() -> None:
    """``matches`` cannot help here: an AGGREGATE rule reads the context
    directly, so the context is what has to be narrowed."""
    context = RuleContext(
        resources=[resource(Provider.AZURE, "sa"), resource(Provider.AWS, "bucket")]
    )
    report = RuleEngine([AzureInventoryRule()]).evaluate(context)

    named = {f.result.resource_id for f in report.failures}
    assert named == {"/azure/sa"}, "an AWS bucket was judged by an Azure rule"


def test_a_per_resource_rule_skips_the_other_cloud_end_to_end() -> None:
    context = RuleContext(
        resources=[resource(Provider.AZURE, "sa"), resource(Provider.AWS, "bucket")]
    )
    report = RuleEngine([AzureStorageRule()]).evaluate(context)

    assert len(report.failures) == 1
    assert report.failures[0].resource is not None
    assert report.failures[0].resource.provider == Provider.AZURE


# ---------------------------------------------------------------- narrowing
def test_a_single_cloud_context_is_not_copied() -> None:
    """Every scan today is one provider, and narrowing rebuilds the id and
    relationship indexes. Returning the original keeps that free."""
    context = RuleContext(resources=[resource(Provider.AZURE, "sa")])
    assert context.for_provider(Provider.AZURE) is context


def test_narrowing_drops_edges_that_leave_the_cloud() -> None:
    context = RuleContext(
        resources=[resource(Provider.AZURE, "sa"), resource(Provider.AWS, "bucket")],
        relationships={
            ("/azure/sa", "contains"): ["/azure/sa", "/aws/bucket"],
            ("/aws/bucket", "contains"): ["/aws/bucket"],
        },
    )
    narrowed = context.for_provider(Provider.AZURE)

    assert narrowed.relationships == {("/azure/sa", "contains"): ["/azure/sa"]}


def test_narrowing_keeps_the_collection_gaps() -> None:
    """A gap is why a rule reports UNKNOWN rather than PASS, and losing it in
    the narrowing would turn "could not look" back into "looked and it was
    fine" -- through the fix for a different bug."""
    context = RuleContext(
        resources=[resource(Provider.AZURE, "sa"), resource(Provider.AWS, "bucket")],
        collection_errors={"storage": "timeout"},
    )
    assert context.for_provider(Provider.AZURE).collection_errors == {
        "storage": "timeout"
    }
