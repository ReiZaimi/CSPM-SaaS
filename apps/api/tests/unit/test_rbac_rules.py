"""Who holds subscription-wide control, and who can grant themselves more.

Three rules over evidence CloudGuard already collected for the graph and could
not previously state. The graph draws an edge from a principal to a scope; an
edge says a principal reaches a scope and cannot say *as what*, so "this named
person holds Owner over your subscription" was a fact the product had and could
not report.

The four states are pinned per rule on purpose. UNKNOWN is the one that matters
most here: an identity with no recorded assignments is not an identity with no
privilege, and answering PASS for it would be the overclaim this engine refuses
everywhere else.
"""

from typing import Any, ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import Level, Provider, ResourceType, RuleState
from app.domain.resource import CloudResource
from app.rules.azure.rbac.privilege import (
    AzurePersonWithSubscriptionControlRule,
    AzureRoleGrantingIdentityRule,
    AzureWorkloadWithSubscriptionControlRule,
)
from app.rules.base import RuleContext

SUBSCRIPTION = "/subscriptions/1111"
RESOURCE_GROUP = f"{SUBSCRIPTION}/resourceGroups/prod"

PERSON = AzurePersonWithSubscriptionControlRule()
WORKLOAD = AzureWorkloadWithSubscriptionControlRule()
GRANTER = AzureRoleGrantingIdentityRule()


def identity(
    resource_type: ResourceType,
    *,
    roles: list[dict[str, Any]] | None = None,
    principal_type: str | None = None,
    name: str = "identity",
    resource_id: str = "/users/u1",
) -> CloudResource:
    metadata: dict[str, Any] = {}
    if roles is not None:
        metadata["roles"] = roles
    if principal_type is not None:
        metadata["principal_type"] = principal_type
    return CloudResource(
        provider=Provider.AZURE,
        provider_resource_id=resource_id,
        resource_type=resource_type,
        name=name,
        criticality=Level.UNKNOWN,
        data_sensitivity=Level.UNKNOWN,
        public_exposure=Level.UNKNOWN,
        metadata=metadata,
    )


def role(name: str, scope: str = SUBSCRIPTION, *, grants: bool = False) -> dict[str, Any]:
    return {"role": name, "scope": scope, "grants_role_assignment": grants}


def context(*resources: CloudResource, **kwargs: Any) -> RuleContext:
    return RuleContext(resources=list(resources), **kwargs)


BLIND = {
    "collection_errors": {AzureEvidence.ROLE_ASSIGNMENTS.value: "Azure timed out"}
}


# ------------------------------------------------- a person with the whole thing
class TestPersonWithSubscriptionControl:
    def test_a_user_holding_owner_over_the_subscription_fails(self) -> None:
        who = identity(ResourceType.USER, roles=[role("Owner")], name="ana")

        result = PERSON.evaluate(who, context(who))

        assert result.state == RuleState.FAIL
        assert result.evidence["subscription_wide_roles"] == [
            {"role": "Owner", "scope": SUBSCRIPTION}
        ]

    def test_the_same_role_one_scope_down_passes(self) -> None:
        """Scope is half the finding. Owner of one resource group is a normal
        way to run a team; Owner of the subscription is not the same claim."""
        who = identity(ResourceType.USER, roles=[role("Owner", RESOURCE_GROUP)])

        assert PERSON.evaluate(who, context(who)).state == RuleState.PASS

    def test_a_user_holding_nothing_passes(self) -> None:
        who = identity(ResourceType.USER, roles=[])

        assert PERSON.evaluate(who, context(who)).state == RuleState.PASS

    def test_a_workload_identity_is_not_applicable(self) -> None:
        """It is over-privileged in the same way and it is a different finding,
        with a different fix and a different owner."""
        who = identity(
            ResourceType.SERVICE_PRINCIPAL,
            roles=[role("Owner")],
            principal_type="ServicePrincipal",
            resource_id="/principals/p1",
        )

        assert PERSON.evaluate(who, context(who)).state == RuleState.NOT_APPLICABLE

    def test_an_identity_with_no_recorded_assignments_is_unknown(self) -> None:
        """Absent is not empty. A managed identity that reached the graph
        through the VM that runs as it has no assignment list of its own, and
        answering PASS would say we looked."""
        who = identity(ResourceType.USER)

        result = PERSON.evaluate(who, context(who))

        assert result.state == RuleState.UNKNOWN

    def test_a_failed_role_listing_is_unknown(self) -> None:
        who = identity(ResourceType.USER, roles=[role("Owner")])

        result = PERSON.evaluate(who, context(who, **BLIND))

        assert result.state == RuleState.UNKNOWN
        assert "Azure timed out" in (result.message or "")

    def test_a_principal_azure_typed_as_a_user_is_judged_as_a_person(self) -> None:
        """The directory pass and the role assignment name the same human two
        ways; either is enough to know a person holds this."""
        who = identity(
            ResourceType.SERVICE_PRINCIPAL,
            roles=[role("User Access Administrator")],
            principal_type="User",
            resource_id="/principals/p2",
        )

        assert PERSON.evaluate(who, context(who)).state == RuleState.FAIL


# ------------------------------------------------ a workload with the whole thing
class TestWorkloadWithSubscriptionControl:
    def test_a_service_principal_with_contributor_fails(self) -> None:
        who = identity(
            ResourceType.SERVICE_PRINCIPAL,
            roles=[role("Contributor")],
            principal_type="ServicePrincipal",
            resource_id="/principals/p1",
        )

        result = WORKLOAD.evaluate(who, context(who))

        assert result.state == RuleState.FAIL

    def test_a_person_is_not_applicable(self) -> None:
        who = identity(ResourceType.USER, roles=[role("Contributor")])

        assert WORKLOAD.evaluate(who, context(who)).state == RuleState.NOT_APPLICABLE

    def test_an_identity_nothing_runs_as_scores_lower(self) -> None:
        """The over-privilege is real; the route to it is not. Stepping
        exploitability down is the same move an unattached NSG rule gets."""
        who = identity(
            ResourceType.SERVICE_PRINCIPAL,
            roles=[role("Owner")],
            principal_type="ServicePrincipal",
            resource_id="/principals/p1",
        )

        result = WORKLOAD.evaluate(who, context(who))

        assert result.exploitability == 2
        assert result.evidence["attached_to"] == []

    def test_an_identity_a_machine_runs_as_keeps_the_class_score(self) -> None:
        """This is the second half of nearly every attack path: reach the
        workload, inherit the identity, act everywhere it can act."""
        who = identity(
            ResourceType.SERVICE_PRINCIPAL,
            roles=[role("Owner")],
            principal_type="ManagedIdentity",
            resource_id="/principals/p1",
        )
        vm = identity(
            ResourceType.VIRTUAL_MACHINE, name="web-01", resource_id="/vms/web-01"
        )

        result = WORKLOAD.evaluate(
            who,
            context(
                who,
                vm,
                relationships={("/vms/web-01", "has_identity"): ["/principals/p1"]},
            ),
        )

        assert result.state == RuleState.FAIL
        assert result.exploitability is None
        assert result.evidence["attached_to"] == ["web-01"]
        assert "web-01" in (result.message or "")

    def test_a_failed_role_listing_is_unknown(self) -> None:
        who = identity(
            ResourceType.SERVICE_PRINCIPAL,
            roles=[role("Owner")],
            principal_type="ServicePrincipal",
            resource_id="/principals/p1",
        )

        assert WORKLOAD.evaluate(who, context(who, **BLIND)).state == RuleState.UNKNOWN


# ------------------------------------------------------ escalation, by permission
class TestRoleGrantingIdentity:
    def test_an_identity_that_can_write_role_assignments_fails(self) -> None:
        who = identity(
            ResourceType.SERVICE_PRINCIPAL,
            roles=[role("Access Manager", grants=True)],
            principal_type="ServicePrincipal",
            resource_id="/principals/p1",
        )

        result = GRANTER.evaluate(who, context(who))

        assert result.state == RuleState.FAIL
        assert result.evidence["can_grant_roles"] is True

    def test_contributor_alone_does_not_fail(self) -> None:
        """The reason this reads the permission rather than the role name.
        Owner and Contributor both carry ``actions: ["*"]``; only Contributor
        excludes the assignment write. A name-based check would flag every
        Contributor on nearly every subscription in existence."""
        who = identity(
            ResourceType.SERVICE_PRINCIPAL,
            roles=[role("Contributor", grants=False)],
            principal_type="ServicePrincipal",
            resource_id="/principals/p1",
        )

        assert GRANTER.evaluate(who, context(who)).state == RuleState.PASS

    def test_it_judges_people_and_workloads_alike(self) -> None:
        """Escalation is escalation. Who holds it changes the remediation, not
        whether it is a finding."""
        who = identity(
            ResourceType.USER, roles=[role("Owner", RESOURCE_GROUP, grants=True)]
        )

        result = GRANTER.evaluate(who, context(who))

        assert result.state == RuleState.FAIL
        assert result.evidence["is_person"] is True

    def test_an_identity_with_no_recorded_assignments_is_unknown(self) -> None:
        who = identity(ResourceType.SERVICE_PRINCIPAL, resource_id="/principals/p1")

        assert GRANTER.evaluate(who, context(who)).state == RuleState.UNKNOWN


# ------------------------------------------------------------------- the contract
class TestRuleContract:
    RULES: ClassVar[list] = [PERSON, WORKLOAD, GRANTER]

    def test_each_rule_declares_the_evidence_it_reads(self) -> None:
        for rule in self.RULES:
            assert AzureEvidence.ROLE_ASSIGNMENTS in rule.requires_evidence
            assert AzureEvidence.ROLE_DEFINITIONS in rule.requires_evidence

    def test_each_rule_is_not_applicable_without_a_resource(self) -> None:
        for rule in self.RULES:
            result = rule.evaluate(None, context())
            assert result.state == RuleState.NOT_APPLICABLE
