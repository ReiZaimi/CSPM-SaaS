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
    AzureBroadScopeAssignmentRule,
    AzureDangerousCustomRoleRule,
    AzureExcessiveOwnersRule,
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


# ---------------------------------------------- privilege above the subscription
BROAD = AzureBroadScopeAssignmentRule()
MANAGEMENT_GROUP = "/providers/Microsoft.Management/managementGroups/platform"


class TestPrivilegeAboveTheSubscription:
    """AZ-IAM-008. A subscription-scoped mistake is bounded by the subscription;
    a management-group one grows on its own, because the subscriptions created
    next inherit it and nobody granted them anything."""

    def test_owner_at_a_management_group_fails(self) -> None:
        holder = identity(
            ResourceType.USER,
            roles=[{"role": "Owner", "scope": MANAGEMENT_GROUP}],
        )
        result = BROAD.evaluate(holder, RuleContext(resources=[holder]))
        assert result.state == RuleState.FAIL
        assert result.evidence["inherited_full_control"][0]["scope"] == MANAGEMENT_GROUP

    def test_owner_at_the_tenant_root_fails(self) -> None:
        """The broadest scope Azure has, and the one an assignment reaches by
        accident when somebody grants at the root to unblock themselves."""
        holder = identity(ResourceType.USER, roles=[{"role": "Owner", "scope": "/"}])
        result = BROAD.evaluate(holder, RuleContext(resources=[holder]))
        assert result.state == RuleState.FAIL

    def test_the_same_role_on_the_subscription_is_not_this_finding(self) -> None:
        """AZ-IAM-001 reports that one. Failing both would raise two findings
        for one assignment and charge the score twice for removing it."""
        holder = identity(
            ResourceType.USER, roles=[{"role": "Owner", "scope": SUBSCRIPTION}]
        )
        assert (
            BROAD.evaluate(holder, RuleContext(resources=[holder])).state
            is RuleState.PASS
        )

    def test_a_narrow_role_above_the_subscription_passes(self) -> None:
        """Reader inherited by every subscription is a design, not a defect."""
        holder = identity(
            ResourceType.USER, roles=[{"role": "Reader", "scope": MANAGEMENT_GROUP}]
        )
        assert (
            BROAD.evaluate(holder, RuleContext(resources=[holder])).state
            is RuleState.PASS
        )

    def test_an_identity_with_no_recorded_assignments_is_unknown(self) -> None:
        holder = identity(ResourceType.USER, roles=None)
        assert (
            BROAD.evaluate(holder, RuleContext(resources=[holder])).state
            is RuleState.UNKNOWN
        )


# ------------------------------------------------------ how many hold Owner
OWNERS = AzureExcessiveOwnersRule()


def owners(count: int) -> list[CloudResource]:
    return [
        identity(
            ResourceType.USER,
            roles=[{"role": "Owner", "scope": SUBSCRIPTION}],
            resource_id=f"/users/owner-{index}",
            name=f"owner-{index}",
        )
        for index in range(count)
    ]


class TestHowManyHoldOwner:
    """AZ-IAM-005. Not the same question as AZ-IAM-001, which reports each
    holder: no single Owner is the one too many, so this cannot be asked per
    identity."""

    def test_a_small_number_of_owners_passes(self) -> None:
        context = RuleContext(resources=owners(2))
        assert OWNERS.evaluate(None, context).state is RuleState.PASS

    def test_more_owners_than_a_team_needs_fails(self) -> None:
        context = RuleContext(resources=owners(OWNERS.MAX_OWNERS + 1))
        result = OWNERS.evaluate(None, context)
        assert result.state == RuleState.FAIL
        assert result.evidence["owner_count"] == OWNERS.MAX_OWNERS + 1

    def test_owners_above_the_subscription_are_not_counted_here(self) -> None:
        """AZ-IAM-008's answer. Counting them would make one assignment two
        findings, and the fix for each is a different operation."""
        inherited = [
            identity(
                ResourceType.USER,
                roles=[{"role": "Owner", "scope": MANAGEMENT_GROUP}],
                resource_id=f"/users/mg-{index}",
            )
            for index in range(OWNERS.MAX_OWNERS + 3)
        ]
        result = OWNERS.evaluate(None, RuleContext(resources=inherited))
        assert result.state == RuleState.PASS

    def test_a_tenant_whose_assignments_never_arrived_is_unknown(self) -> None:
        """Nobody holding Owner is not a clean tenant if nothing was read."""
        blind = [identity(ResourceType.USER, roles=None)]
        assert (
            OWNERS.evaluate(None, RuleContext(resources=blind)).state
            is RuleState.UNKNOWN
        )

    def test_a_failed_role_listing_is_unknown_not_a_pass(self) -> None:
        context = RuleContext(
            resources=owners(1),
            collection_errors={AzureEvidence.ROLE_ASSIGNMENTS.value: "403"},
        )
        assert OWNERS.evaluate(None, context).state is RuleState.UNKNOWN


# ------------------------------------------------------ roles a tenant wrote
CUSTOM = AzureDangerousCustomRoleRule()


def subscription_with(*roles: dict[str, Any]) -> CloudResource:
    return CloudResource(
        provider=Provider.AZURE,
        provider_resource_id=SUBSCRIPTION,
        resource_type=ResourceType.SUBSCRIPTION,
        name="subscription",
        criticality=Level.HIGH,
        data_sensitivity=Level.HIGH,
        public_exposure=Level.LOW,
        metadata={"custom_roles": list(roles)},
    )


class TestRolesATenantWroteItself:
    """AZ-IAM-010. Whoever reviews privilege looks at who holds Owner; a custom
    role granting the same actions passes that review under another name."""

    def test_a_wildcard_role_fails(self) -> None:
        subscription = subscription_with({"name": "Platform Support", "actions": ["*"]})
        result = CUSTOM.evaluate(subscription, RuleContext(resources=[subscription]))
        assert result.state == RuleState.FAIL
        assert result.evidence["dangerous_roles"][0]["role"] == "Platform Support"

    def test_a_role_that_can_hand_out_roles_fails(self) -> None:
        subscription = subscription_with(
            {
                "name": "Access Manager",
                "actions": ["Microsoft.Authorization/roleAssignments/write"],
            }
        )
        assert (
            CUSTOM.evaluate(subscription, RuleContext(resources=[subscription])).state
            is RuleState.FAIL
        )

    def test_an_exclusion_is_read_the_way_arm_reads_it(self) -> None:
        """What separates Contributor from Owner. A wildcard that takes the
        authorization writes back in notActions has not granted them, and
        calling it dangerous would report every Contributor-shaped custom role
        on nearly every subscription in existence."""
        subscription = subscription_with(
            {
                "name": "Almost Contributor",
                "actions": ["Microsoft.Compute/*"],
                "not_actions": ["Microsoft.Authorization/*/write"],
            }
        )
        assert (
            CUSTOM.evaluate(subscription, RuleContext(resources=[subscription])).state
            is RuleState.PASS
        )

    def test_a_narrow_custom_role_passes(self) -> None:
        subscription = subscription_with(
            {"name": "Log Reader", "actions": ["Microsoft.Insights/*/read"]}
        )
        assert (
            CUSTOM.evaluate(subscription, RuleContext(resources=[subscription])).state
            is RuleState.PASS
        )

    def test_a_subscription_whose_definitions_never_arrived_is_unknown(self) -> None:
        subscription = CloudResource(
            provider=Provider.AZURE,
            provider_resource_id=SUBSCRIPTION,
            resource_type=ResourceType.SUBSCRIPTION,
            name="subscription",
            metadata={},
        )
        assert (
            CUSTOM.evaluate(subscription, RuleContext(resources=[subscription])).state
            is RuleState.UNKNOWN
        )
