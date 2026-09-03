"""Who may act over a whole subscription, and who may hand that out.

Three rules over one piece of evidence: the role assignments already collected
for the graph. They are deliberately *per identity* rather than per assignment
-- an account holding Owner twice is one problem, and a finding per assignment
would charge the security score twice for it.

``roles`` on an identity is a list of ``{"role", "scope",
"grants_role_assignment"}``, written by the normalizer's authorization pass.
The scope string is an ARM path, so its shape says what the assignment covers:
``/subscriptions/<id>`` and nothing after it is the whole subscription, while
anything with ``/resourceGroups/`` beneath it is narrower.
"""

import re
from typing import Any, ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.connectors.azure.rbac import action_matches
from app.core.enums import ResourceType, RuleScope, Severity
from app.domain.resource import CloudResource
from app.remediation import Comparison, ExpectedState, RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule

# Roles whose holder can change anything in the scope they hold it over.
# Matched on the resolved role *name* rather than on the definition GUID,
# because a tenant's own role called "Platform Owner" carrying the same
# permissions is exactly what a GUID list would miss -- and because the
# definition's permissions are already read for the escalation question below,
# where they answer it exactly.
FULL_CONTROL_ROLES = {"owner", "contributor", "user access administrator"}

# ``/subscriptions/<guid>`` with nothing beneath it.
_SUBSCRIPTION_SCOPE = re.compile(r"^/subscriptions/[^/]+/?$", re.IGNORECASE)


def _is_subscription_scope(scope: str | None) -> bool:
    return bool(_SUBSCRIPTION_SCOPE.match((scope or "").strip()))


def _roles(resource: CloudResource) -> list[dict[str, Any]] | None:
    """This identity's role assignments, or None if none were recorded.

    None and ``[]`` are different answers and the difference decides the
    verdict. An identity the authorization pass never saw an assignment for has
    no key at all; one that was seen and holds nothing has an empty list. The
    first is silence, the second is a PASS somebody earned.
    """
    roles = resource.get("roles")
    if roles is None:
        return None
    return [r for r in roles if isinstance(r, dict)]


def _is_person(resource: CloudResource) -> bool:
    """Whether this identity belongs to a human.

    A directory user node, or a principal Azure itself typed as ``User``. The
    two arise from different collections -- the directory pass and the role
    assignment's own ``principalType`` -- and either one is enough.
    """
    if resource.resource_type == ResourceType.USER:
        return True
    return str(resource.get("principal_type") or "").lower() == "user"


class _RoleAssignmentRule(SecurityRule):
    """Shared plumbing: read the assignments, or say why you cannot."""

    category = "identity"
    provider_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.ROLE_ASSIGNMENTS,
        AzureEvidence.ROLE_DEFINITIONS,
    )
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = provider_evidence
    applies_to: ClassVar[list[ResourceType]] = [
        ResourceType.USER,
        ResourceType.SERVICE_PRINCIPAL,
    ]
    # Empty expectations, and the reason is the same for all three: what has to
    # change is a role *assignment*, which is not a field on the asset being
    # judged. There is nothing to compare afterwards and nothing an Azure Policy
    # can deny at creation -- a policy that refused role assignments would refuse
    # the legitimate ones too. So the declaration says so and still hands over
    # the command, which is the contract
    # ``test_an_expectation_nobody_can_state_has_to_say_why`` enforces.
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "az role assignment list --assignee <object-id> --all "
            "--query \"[].{role:roleDefinitionName,scope:scope}\" --output table",
            "az role assignment delete --assignee <object-id> --role <role> "
            "--scope <scope>",
        ),
        notes=(
            "No expected state and no policy. The fix is removing or narrowing a "
            "role assignment, which is a decision about who should hold what -- "
            "not a setting on the identity, and not something a preventive policy "
            "can refuse without refusing every legitimate assignment alongside it. "
            "List what the identity holds first: the scope matters as much as the "
            "role, and an assignment inherited from a management group is removed "
            "at the management group, not here."
        ),
    )

    def _guard(self, resource: CloudResource | None, context: RuleContext) -> RuleResult | None:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Role assignments unavailable: {failure}")
        if _roles(resource) is None:
            # The identity is in the graph because something else named it --
            # a managed identity attached to a VM, say -- and no assignment was
            # ever read for it. Silence, not a clean bill of health.
            return RuleResult.unknown(
                "No role assignments were recorded for this identity"
            )
        return None


class AzurePersonWithSubscriptionControlRule(_RoleAssignmentRule):
    rule_id = "AZ-IAM-001"
    name = "Person holds full control of a subscription"
    description = (
        "A named user account holds Owner, Contributor or User Access Administrator "
        "directly over an entire subscription. Standing subscription-wide control on a "
        "person's day-to-day account means one phished session is one phished "
        "subscription."
    )
    severity = Severity.HIGH
    exploitability = 3
    estimated_effort_minutes = 45
    rationale = (
        "The account a person reads mail with is the account an attacker gets. Direct, "
        "permanent, subscription-wide control on that account removes every step between "
        "a stolen session and total control of the environment -- there is no further "
        "privilege to escalate to."
    )
    remediation = (
        "Move standing subscription-wide control off individual accounts.\n\n"
        "Assign the role to a group whose membership is reviewed, and make the "
        "assignment eligible rather than active through Privileged Identity Management "
        "so it must be activated, with approval and a time limit, for the work that "
        "needs it. Where the person genuinely administers this subscription day to day, "
        "assign the narrowest role that covers the work, at the resource group rather "
        "than the subscription.\n\n"
        "Azure Portal: Subscription > Access control (IAM) > Role assignments > select "
        "the assignment > Remove, then re-grant at a narrower scope.\n\n"
        "Azure CLI:\n"
        "  az role assignment delete --assignee <upn> --role Owner \\\n"
        "    --scope /subscriptions/<subscription-id>"
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["1.21"],
        "ISO_27001": ["A.5.15", "A.5.18", "A.8.2"],
        "NIST_CSF": ["PR.AC-1", "PR.AC-4"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
        "NIST_800_53": ["AC-6", "AC-2"],
        "SOC2": ["CC6.3"],
        "PCI_DSS_4": ["7.2.1", "7.2.2"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        guard = self._guard(resource, context)
        if guard is not None:
            return guard
        assert resource is not None

        if not _is_person(resource):
            return RuleResult.not_applicable("Not a user account")

        held = [
            role
            for role in _roles(resource) or []
            if str(role.get("role", "")).lower() in FULL_CONTROL_ROLES
            and _is_subscription_scope(role.get("scope"))
        ]
        if not held:
            return RuleResult.passed({"subscription_wide_roles": []})

        return RuleResult.failed(
            evidence={
                "subscription_wide_roles": [
                    {"role": r.get("role"), "scope": r.get("scope")} for r in held
                ],
                "account_enabled": resource.get("account_enabled"),
                "user_principal_name": resource.get("user_principal_name"),
            },
            message=(
                f"{resource.name} holds "
                + ", ".join(sorted({str(r.get("role")) for r in held}))
                + " directly over the whole subscription"
            ),
        )


class AzureWorkloadWithSubscriptionControlRule(_RoleAssignmentRule):
    rule_id = "AZ-IAM-002"
    name = "Workload identity holds full control of a subscription"
    description = (
        "A service principal or managed identity holds Owner or Contributor over an "
        "entire subscription. A workload identity has no session to expire and no person "
        "to notice it being used, so its permissions are exactly what an attacker "
        "inherits by compromising whatever runs as it."
    )
    severity = Severity.HIGH
    exploitability = 3
    estimated_effort_minutes = 60
    rationale = (
        "This is the second half of nearly every cloud attack path CloudGuard finds: "
        "reach a workload, inherit its identity, act everywhere that identity can act. A "
        "deployment pipeline that needs to write to three resource groups does not need "
        "the subscription, and the difference is the entire blast radius."
    )
    remediation = (
        "Narrow the assignment to the scopes the workload actually writes to.\n\n"
        "Look at what this identity has done -- the activity log filtered by its object "
        "id shows which resources it touches -- and re-grant at those resource groups, "
        "or with a built-in role narrower than Contributor.\n\n"
        "Azure CLI:\n"
        "  az role assignment delete --assignee <object-id> --role Contributor \\\n"
        "    --scope /subscriptions/<subscription-id>\n"
        "  az role assignment create --assignee <object-id> --role <narrower-role> \\\n"
        "    --scope /subscriptions/<subscription-id>/resourceGroups/<rg>"
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["1.21"],
        "ISO_27001": ["A.5.15", "A.5.16", "A.8.2"],
        "NIST_CSF": ["PR.AC-1", "PR.AC-4"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
        "NIST_800_53": ["AC-6", "AC-3"],
        "SOC2": ["CC6.3"],
        "PCI_DSS_4": ["7.2.1", "7.2.2"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        guard = self._guard(resource, context)
        if guard is not None:
            return guard
        assert resource is not None

        if _is_person(resource):
            return RuleResult.not_applicable("Not a workload identity")

        held = [
            role
            for role in _roles(resource) or []
            if str(role.get("role", "")).lower() in FULL_CONTROL_ROLES
            and _is_subscription_scope(role.get("scope"))
        ]
        if not held:
            return RuleResult.passed({"subscription_wide_roles": []})

        # What runs as this identity. An identity nothing is attached to is
        # still over-privileged, but an identity a reachable workload runs as
        # is the path -- so the evidence names them and the graph carries on
        # from here.
        runs = context.get_related_inverse(resource, "has_identity")
        return RuleResult.failed(
            evidence={
                "subscription_wide_roles": [
                    {"role": r.get("role"), "scope": r.get("scope")} for r in held
                ],
                "principal_type": resource.get("principal_type"),
                "attached_to": [r.name for r in runs],
                "attached_resource_ids": [r.provider_resource_id for r in runs],
            },
            # Nothing runs as it, so there is no workload to compromise on the
            # way in. The over-privilege is real and the route to it is not.
            exploitability=None if runs else 2,
            message=(
                f"{resource.name} holds "
                + ", ".join(sorted({str(r.get("role")) for r in held}))
                + " over the whole subscription"
                + (
                    f", and is the identity of {runs[0].name}"
                    if len(runs) == 1
                    else f", and is the identity of {len(runs)} resources"
                    if runs
                    else ", though nothing currently runs as it"
                )
            ),
        )


class AzureRoleGrantingIdentityRule(_RoleAssignmentRule):
    rule_id = "AZ-IAM-003"
    name = "Identity can grant itself any role"
    description = (
        "An identity holds a role that permits writing role assignments. Whatever it "
        "currently holds is not its effective permission: it can grant itself anything "
        "at that scope, so its reach has no ceiling below the scope itself."
    )
    severity = Severity.CRITICAL
    exploitability = 3
    estimated_effort_minutes = 60
    rationale = (
        "Privilege escalation is the step that turns a foothold into an incident. An "
        "identity that can write role assignments does not need to be Owner -- it can "
        "become Owner, at any moment, without exploiting anything. This is why the "
        "check reads the role's permissions rather than its name: Owner and Contributor "
        "both carry `actions: [\"*\"]`, and only Contributor excludes the assignment "
        "write, so a name-based check would flag every Contributor in existence."
    )
    remediation = (
        "Remove the assignment-writing role, or narrow its scope.\n\n"
        "User Access Administrator and Owner both carry "
        "`Microsoft.Authorization/roleAssignments/write`, as can a custom role. Where "
        "something genuinely must manage access -- an access-review automation, a "
        "landing-zone pipeline -- scope it to the resource groups it administers rather "
        "than to the subscription, and make it eligible through Privileged Identity "
        "Management rather than permanently active.\n\n"
        "Azure CLI, to see what a custom role actually permits:\n"
        "  az role definition list --name <role> \\\n"
        "    --query \"[].{actions:permissions[0].actions,notActions:permissions[0].notActions}\""
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["1.21"],
        "ISO_27001": ["A.5.15", "A.5.18", "A.8.2"],
        "NIST_CSF": ["PR.AC-4"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
        "NIST_800_53": ["AC-6", "AC-3"],
        "SOC2": ["CC6.3"],
        "PCI_DSS_4": ["7.2.2"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        guard = self._guard(resource, context)
        if guard is not None:
            return guard
        assert resource is not None

        escalating = [
            role
            for role in _roles(resource) or []
            if role.get("grants_role_assignment") is True
        ]
        if not escalating:
            return RuleResult.passed({"can_grant_roles": False})

        runs = context.get_related_inverse(resource, "has_identity")
        return RuleResult.failed(
            evidence={
                "can_grant_roles": True,
                "granting_roles": [
                    {"role": r.get("role"), "scope": r.get("scope")} for r in escalating
                ],
                "is_person": _is_person(resource),
                "attached_to": [r.name for r in runs],
            },
            message=(
                f"{resource.name} holds "
                + ", ".join(sorted({str(r.get("role")) for r in escalating}))
                + ", which permits writing role assignments -- it can grant itself any "
                "role at that scope"
            ),
        )


# ``/providers/Microsoft.Management/managementGroups/<name>``, and the tenant
# root ``/``. Either one is above the subscription: an assignment made there is
# inherited by every subscription beneath it, including ones created afterwards.
_MANAGEMENT_GROUP_SCOPE = re.compile(
    r"^/providers/Microsoft\.Management/managementGroups/[^/]+/?$", re.IGNORECASE
)


def _is_broad_scope(scope: str | None) -> bool:
    text = (scope or "").strip()
    return text == "/" or bool(_MANAGEMENT_GROUP_SCOPE.match(text))


class AzureExcessiveOwnersRule(SecurityRule):
    """How many people hold Owner, asked of the subscription rather than of them.

    AZ-IAM-001 reports each person holding subscription-wide control, which is
    the right shape for the fix: that assignment is removed from that account.
    This is the different question underneath -- whether the *number* of them is
    a policy nobody set -- and it cannot be asked per identity, because no single
    Owner is the one too many.
    """

    rule_id = "AZ-IAM-005"
    name = "Too many Owners on the subscription"
    description = (
        "More identities hold Owner over this subscription than a small administrative "
        "team needs. Owner carries the right to change anything in the subscription and to "
        "grant that right to others, so every additional holder is another account whose "
        "compromise ends the same way."
    )
    category = "identity"
    severity = Severity.MEDIUM
    exploitability = 2
    scope = RuleScope.AGGREGATE
    applies_to: ClassVar[list[ResourceType]] = []
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.ROLE_ASSIGNMENTS,
        AzureEvidence.ROLE_DEFINITIONS,
    )
    estimated_effort_minutes = 60
    rationale = (
        "Owner is the role that cannot be constrained: it can undo any restriction placed "
        "on it, including the one you would add to contain an incident. Keeping the number "
        "small is the only control over it that survives contact with an attacker who has "
        "taken one of them."
    )
    remediation = (
        "Reduce the number of standing Owners.\n\n"
        "Azure Portal: Subscription > Access control (IAM) > Role assignments > filter to "
        "Owner. Move people who need to manage resources but not access to Contributor, "
        "and people who need to grant access occasionally to eligible assignments in "
        "Privileged Identity Management.\n\n"
        "Azure CLI:\n"
        "  az role assignment list --role Owner --scope /subscriptions/<id> -o table\n\n"
        "Microsoft's own guidance is fewer than three permanent Owners per subscription, "
        "plus a break-glass account whose credentials are held offline."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        # Nothing on any one asset satisfies this: the finding is the size of a
        # set, not a setting. Declared empty rather than left absent, so "no
        # declaration written" and "no declaration possible" stay apart.
        expected=(),
        cli=("az role assignment list --role Owner --scope /subscriptions/<id> -o table",),
        notes=(
            "Fixed by removing standing assignments rather than by changing a "
            "setting. No Azure Policy can express a count of role holders."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["1.21", "1.1.3"],
        "ISO_27001": ["A.5.15", "A.5.18", "A.8.2"],
        "NIST_CSF": ["PR.AC-4"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["AC-2", "AC-6"],
        "SOC2": ["CC6.2", "CC6.3"],
        "PCI_DSS_4": ["7.2.1", "7.2.2"],
    }

    # Three, matching Microsoft's own guidance, plus the break-glass account
    # that guidance also assumes -- so the threshold is what a compliant tenant
    # holds rather than what a careful one aims for.
    MAX_OWNERS: ClassVar[int] = 4

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Role assignments unavailable: {failure}")

        holders = [
            identity
            for identity in context.resources
            if any(
                str(role.get("role", "")).lower() == "owner"
                and _is_subscription_scope(role.get("scope"))
                for role in _roles(identity) or []
            )
        ]

        # Nobody at all is not a clean tenant; it is a tenant whose assignments
        # never arrived, or one where every Owner sits above the subscription.
        # Either way there is nothing here to pass.
        if not any(_roles(identity) is not None for identity in context.resources):
            return RuleResult.unknown("No role assignments were collected")

        evidence = {
            "owner_count": len(holders),
            "threshold": self.MAX_OWNERS,
            "owners": sorted(
                str(identity.get("user_principal_name") or identity.name)
                for identity in holders
            )[:50],
        }
        if len(holders) <= self.MAX_OWNERS:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"{len(holders)} identities hold Owner over the subscription, "
                f"more than the {self.MAX_OWNERS} a small administrative team needs"
            ),
        )


class AzureBroadScopeAssignmentRule(_RoleAssignmentRule):
    rule_id = "AZ-IAM-008"
    name = "Full control granted above the subscription"
    description = (
        "An identity holds Owner, Contributor or User Access Administrator at a management "
        "group or at the tenant root rather than at a subscription. The grant is inherited "
        "by every subscription beneath that scope — including subscriptions created after "
        "the assignment was made, which nobody reviews because nobody granted them "
        "anything."
    )
    category = "identity"
    severity = Severity.HIGH
    exploitability = 3
    estimated_effort_minutes = 45
    rationale = (
        "A subscription-scoped mistake is bounded by the subscription. A management-group "
        "one grows on its own: the blast radius is whatever the organization creates next, "
        "and the assignment that produced it was made once, years ago, by somebody who was "
        "solving a problem in one environment."
    )
    remediation = (
        "Move the assignment down to the scope that actually needs it.\n\n"
        "Azure Portal: Management groups > select the group > Access control (IAM) > Role "
        "assignments > remove the assignment, then add it on the subscription or resource "
        "group where the work happens.\n\n"
        "Azure CLI:\n"
        "  az role assignment list --scope \\\n"
        "    /providers/Microsoft.Management/managementGroups/<name> -o table\n"
        "  az role assignment delete --assignee <object-id> --scope <management-group-scope>\n\n"
        "Where a platform team genuinely operates across every subscription, prefer an "
        "eligible assignment in Privileged Identity Management over a standing one, so the "
        "inherited reach exists only while somebody is using it."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="roles",
                comparison=Comparison.NONE_MATCHING,
                equals=None,
                describes=(
                    "No Owner, Contributor or User Access Administrator "
                    "assignment sits above the subscription"
                ),
                example={
                    "role": "Owner",
                    "scope": "/providers/Microsoft.Management/managementGroups/<name>",
                },
            ),
        ),
        cli=(
            "az role assignment delete --assignee <object-id> "
            "--scope /providers/Microsoft.Management/managementGroups/<name>",
        ),
        notes=(
            "No policy is generated. Azure Policy cannot deny a role "
            "assignment at a scope above the one it is assigned at, and the "
            "fix is an organizational decision about where a team's authority "
            "belongs rather than a setting to enforce."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["1.21", "1.1.3"],
        "ISO_27001": ["A.5.15", "A.8.2"],
        "NIST_CSF": ["PR.AC-4"],
        "GDPR": ["32(1)(b)", "5(1)(f)"],
        "NIST_800_53": ["AC-6", "AC-3"],
        "SOC2": ["CC6.3"],
        "PCI_DSS_4": ["7.2.1", "7.2.2"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        guard = self._guard(resource, context)
        if guard is not None:
            return guard
        assert resource is not None

        held = [
            role
            for role in _roles(resource) or []
            if str(role.get("role", "")).lower() in FULL_CONTROL_ROLES
            and _is_broad_scope(role.get("scope"))
        ]
        if not held:
            return RuleResult.passed({"inherited_full_control": []})

        return RuleResult.failed(
            evidence={
                "inherited_full_control": [
                    {"role": r.get("role"), "scope": r.get("scope")} for r in held
                ],
                "principal_type": resource.get("principal_type"),
                "user_principal_name": resource.get("user_principal_name"),
            },
            message=(
                f"{resource.name} holds "
                + ", ".join(sorted({str(r.get("role")) for r in held}))
                + " above the subscription, so every subscription beneath that "
                "scope inherits it"
            ),
        )


# Actions that make a custom role a way around the role model rather than a
# narrowing of it. Wildcards are read as patterns, exactly as ARM reads them:
# ``*`` grants everything, and ``Microsoft.Authorization/*`` grants the right to
# rewrite who may do what.
_DANGEROUS_ACTIONS = (
    "*",
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleDefinitions/write",
    "Microsoft.Authorization/elevateAccess/action",
)


def _granted(actions: list[str], not_actions: list[str], target: str) -> bool:
    """Whether these permissions grant ``target`` after exclusions.

    ``notActions`` is what separates Contributor from Owner, and a custom role
    written the same way deserves the same reading: an action granted by a
    wildcard and taken back by an exclusion is not granted.
    """
    if not any(action_matches(pattern, target) for pattern in actions):
        return False
    return not any(action_matches(pattern, target) for pattern in not_actions)


class AzureDangerousCustomRoleRule(SecurityRule):
    rule_id = "AZ-IAM-010"
    name = "Custom role grants unrestricted or self-granting permissions"
    description = (
        "A role this tenant wrote itself grants every action, or grants the right to write "
        "role assignments and definitions. A custom role is normally how an organization "
        "narrows what a job needs; one written this way is Owner under another name, and it "
        "is invisible to any review that looks for the built-in roles."
    )
    category = "identity"
    severity = Severity.HIGH
    exploitability = 3
    scope = RuleScope.PER_RESOURCE
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.SUBSCRIPTION]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.ROLE_DEFINITIONS,
    )
    estimated_effort_minutes = 90
    rationale = (
        "Whoever reviews privilege looks at who holds Owner. A custom role called "
        "\"Platform Support\" that grants the same actions passes that review, and the "
        "right to write role assignments turns whatever its holder has into whatever they "
        "want."
    )
    remediation = (
        "Narrow the role to the actions the job needs.\n\n"
        "Azure Portal: Subscription > Access control (IAM) > Roles > filter to CustomRole > "
        "select the role > Permissions > replace the wildcard with the specific operations, "
        "or exclude the authorization writes under NotActions.\n\n"
        "Azure CLI:\n"
        "  az role definition list --custom-role-only true -o json\n"
        "  az role definition update --role-definition <file.json>\n\n"
        "Where the role genuinely needs to manage access, say so explicitly by assigning "
        "User Access Administrator to the few identities that need it, rather than folding "
        "the right into a role whose name does not mention it."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="custom_roles",
                comparison=Comparison.NONE_MATCHING,
                equals=None,
                describes=(
                    "No custom role grants every action, or the right to write "
                    "role assignments or definitions"
                ),
                example={"name": "<role>", "actions": ["*"]},
            ),
        ),
        cli=("az role definition list --custom-role-only true -o json",),
        notes=(
            "No policy is generated. A role definition is not a resource with "
            "settings to audit; the fix is to rewrite the definition."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["1.21", "1.1.3"],
        "ISO_27001": ["A.5.15", "A.8.2"],
        "NIST_CSF": ["PR.AC-4"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["AC-6", "AC-3"],
        "SOC2": ["CC6.3"],
        "PCI_DSS_4": ["7.2.1", "7.2.2"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Role definitions unavailable: {failure}")

        roles = resource.get("custom_roles")
        if roles is None:
            return RuleResult.unknown("Role definitions missing from snapshot")

        dangerous: list[dict[str, Any]] = []
        for role in roles:
            actions = [str(a) for a in (role.get("actions") or [])]
            not_actions = [str(a) for a in (role.get("not_actions") or [])]
            granted = [
                target
                for target in _DANGEROUS_ACTIONS
                if _granted(actions, not_actions, target)
            ]
            if granted:
                dangerous.append(
                    {
                        "role": role.get("name"),
                        "grants": granted,
                        "assignable_scopes": role.get("assignable_scopes"),
                    }
                )

        if not dangerous:
            return RuleResult.passed({"custom_role_count": len(roles)})

        return RuleResult.failed(
            evidence={
                "custom_role_count": len(roles),
                "dangerous_roles": dangerous,
            },
            message=(
                f"{len(dangerous)} custom role(s) grant unrestricted or "
                "self-granting permissions: "
                + ", ".join(sorted(str(r["role"]) for r in dangerous))
            ),
        )
