from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, RuleScope, Severity
from app.domain.resource import CloudResource
from app.remediation import RemediationSpec
from app.rules.azure.identity.mfa import _is_privileged
from app.rules.base import RuleContext, RuleResult, SecurityRule


class AzurePrivilegedUserRule(SecurityRule):
    """The one genuinely aggregate rule in the initial set.

    "Too many admins" is not a statement about any single user -- asking it
    per-user would be meaningless. The engine calls this once per scan with
    ``resource=None`` (RULE_ENGINE.md section 1).
    """

    rule_id = "AZ-ID-002"
    name = "Excessive number of privileged users"
    description = (
        "More accounts hold privileged directory roles than a tenant of this size needs. "
        "Every additional administrator is another account whose compromise is a full "
        "tenant compromise."
    )
    category = "identity"
    severity = Severity.HIGH
    exploitability = 3
    scope = RuleScope.AGGREGATE
    applies_to: ClassVar[list[ResourceType]] = []
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.USERS,
        AzureEvidence.DIRECTORY_ROLES,
        AzureEvidence.USER_ROLE_MAP,
    )
    estimated_effort_minutes = 60
    rationale = (
        "Standing administrative access widens the blast radius of any single credential "
        "theft. Most people who hold an admin role need it occasionally, not permanently."
    )
    remediation = (
        "Review who holds privileged roles and remove standing access that is not needed.\n\n"
        "Entra admin centre > Roles and administrators > select the role > Assignments.\n\n"
        "Azure CLI:\n"
        "  az role assignment list --all --include-inherited -o table\n\n"
        "Where Entra ID P2 is available, convert standing assignments to eligible ones with "
        "Privileged Identity Management so administrators activate the role only when they "
        "need it. Aim for a small number of permanent Global Administrators (Microsoft "
        "recommends fewer than five) plus one break-glass account."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        # Empty on purpose, and the emptiness is the statement. This rule judges
        # a *ratio across the tenant* -- how many enabled accounts hold
        # privileged roles -- so there is no asset whose settings can be made to
        # satisfy it. Inventing a per-asset expectation would tell a customer to
        # change something about one account when the finding is about the shape
        # of their directory.
        #
        # Declared rather than left absent so the two answers stay apart: an
        # absent declaration is work not done, and this is a fact about the
        # check.
        expected=(),
        cli=(
            "az ad directory-role member list --role <role> -o table",
            "az role assignment list --all --assignee <upn> -o table",
        ),
        notes=(
            "Fixed by removing standing access rather than by changing a "
            "setting: move the accounts that need privilege occasionally onto "
            "eligible assignments in Privileged Identity Management, so the "
            "role is held for the length of a task rather than permanently. No "
            "policy can express a ratio, and no expected state can either."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["1.21"],
        "ISO_27001": ["A.5.15", "A.5.18"],
        "NIST_CSF": ["PR.AC-4"],
        "GDPR": ["25", "32(1)(b)"],
        "NIST_800_53": ["AC-2", "AC-6"],
        "SOC2": ["CC6.2", "CC6.3"],
        "PCI_DSS_4": ["7.2.1", "8.2.1"],
    }

    # Below this, "too many admins" is not a meaningful claim -- a two-person
    # company legitimately has two admins.
    ABSOLUTE_FLOOR = 5
    # Above this share of enabled accounts, privilege is not being rationed.
    MAX_PRIVILEGED_RATIO = 0.20

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Identity data unavailable: {failure}")

        users = context.get_resources_by_type(ResourceType.USER)
        if not users:
            return RuleResult.unknown("No directory users were collected")

        enabled = [u for u in users if u.get("account_enabled") is not False]
        privileged = [u for u in enabled if _is_privileged(u)]

        if not enabled:
            return RuleResult.unknown("No enabled directory users were collected")

        ratio = len(privileged) / len(enabled)
        over_ratio = ratio > self.MAX_PRIVILEGED_RATIO
        over_floor = len(privileged) > self.ABSOLUTE_FLOOR

        evidence = {
            "privileged_user_count": len(privileged),
            "enabled_user_count": len(enabled),
            "privileged_ratio": round(ratio, 3),
            "threshold_ratio": self.MAX_PRIVILEGED_RATIO,
            "threshold_floor": self.ABSOLUTE_FLOOR,
            "privileged_users": sorted(
                u.get("user_principal_name") or u.name for u in privileged
            )[:50],
        }

        if over_floor and over_ratio:
            return RuleResult.failed(
                evidence=evidence,
                message=(
                    f"{len(privileged)} of {len(enabled)} enabled accounts hold privileged "
                    f"roles ({ratio:.0%}) — above the {self.MAX_PRIVILEGED_RATIO:.0%} guideline"
                ),
            )
        return RuleResult.passed(evidence)


class AzureGuestPrivilegedUserRule(SecurityRule):
    rule_id = "AZ-ID-011"
    name = "Guest account holds a privileged role"
    description = (
        "An account invited into this directory from outside it holds a privileged role. "
        "Its password, its second factor and its lifecycle belong to another organization's "
        "administrator: this tenant cannot reset it, cannot enforce how it is protected, and "
        "does not learn when the person leaves the company that owns it."
    )
    category = "identity"
    severity = Severity.HIGH
    exploitability = 3
    scope = RuleScope.PER_RESOURCE
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.USER]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.USERS,
        AzureEvidence.DIRECTORY_ROLES,
        AzureEvidence.USER_ROLE_MAP,
    )
    estimated_effort_minutes = 30
    rationale = (
        "Privilege granted to an identity you do not control is privilege you cannot "
        "withdraw at the speed of an incident. A partner's compromised account arrives here "
        "already holding the role, and the joiner-mover-leaver process that would have "
        "removed it runs in a directory that is not yours."
    )
    remediation = (
        "Move the privilege onto an account this tenant controls.\n\n"
        "Entra admin centre > Roles and administrators > select the role > Assignments > "
        "remove the guest, then assign a member account belonging to this directory.\n\n"
        "Azure CLI:\n"
        "  az ad user list --filter \"userType eq 'Guest'\" -o table\n\n"
        "Where a partner genuinely needs administrative access, prefer Entra ID Governance "
        "access packages with an expiry date, or Privileged Identity Management with "
        "time-bound eligible assignment, so the grant ends on its own rather than when "
        "somebody remembers it."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        # Empty, because the fix is not a setting on this account: a guest
        # cannot be turned into a member, and the thing that changes is which
        # account holds the role. Declared rather than left absent so "no
        # declaration written" and "no declaration possible" stay apart.
        expected=(),
        cli=("az ad user list --filter \"userType eq 'Guest'\" -o table",),
        notes=(
            "Fixed by moving the role onto an account this directory owns. No "
            "policy is generated: role assignment is a directory operation "
            "rather than a resource property, so no policyRule can express it."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["1.1.3", "1.21"],
        "ISO_27001": ["A.5.15", "A.5.16", "A.5.18"],
        "NIST_CSF": ["PR.AC-1", "PR.AC-4"],
        "GDPR": ["32(1)(b)", "5(1)(f)"],
        "NIST_800_53": ["AC-2", "AC-6"],
        "SOC2": ["CC6.1", "CC6.2", "CC6.3"],
        "PCI_DSS_4": ["7.2.1", "8.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Identity data unavailable: {failure}")

        roles = resource.get("directory_roles")
        if roles is None:
            return RuleResult.unknown("Role membership missing from snapshot")
        if not _is_privileged(resource):
            return RuleResult.not_applicable("User holds no privileged role")

        user_type = resource.get("user_type")
        if user_type is None:
            # The account was read and its type was not. Guessing "Member"
            # because most accounts are one would be a pass nobody earned.
            return RuleResult.unknown(
                "The directory did not report whether this account is a guest"
            )
        if str(user_type).lower() != "guest":
            return RuleResult.passed({"user_type": user_type, "privileged_roles": roles})

        return RuleResult.failed(
            evidence={
                "user_type": user_type,
                "privileged_roles": roles,
                "user_principal_name": resource.get("user_principal_name"),
                "account_enabled": resource.get("account_enabled"),
            },
            message=(
                f"{resource.name} is a guest in this directory and holds "
                + ", ".join(sorted(str(r) for r in roles))
            ),
        )


class AzureDisabledPrivilegedUserRule(SecurityRule):
    rule_id = "AZ-ID-012"
    name = "Disabled account still holds a privileged role"
    description = (
        "An account that has been disabled still carries its privileged role assignment. "
        "Disabling stops sign-in; it does not remove privilege, so re-enabling the account "
        "— by a helpdesk request, a sync from an on-premises directory, or an attacker who "
        "reaches the directory — restores administrative access in one step."
    )
    category = "identity"
    severity = Severity.MEDIUM
    exploitability = 2
    scope = RuleScope.PER_RESOURCE
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.USER]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.USERS,
        AzureEvidence.DIRECTORY_ROLES,
        AzureEvidence.USER_ROLE_MAP,
    )
    estimated_effort_minutes = 15
    rationale = (
        "A disabled account with a live role is a leaver whose offboarding stopped halfway. "
        "It is invisible to every review that looks at who can sign in, and it is one "
        "checkbox away from being an administrator again."
    )
    remediation = (
        "Remove the role assignment, then delete the account if nobody needs its history.\n\n"
        "Entra admin centre > Roles and administrators > select the role > Assignments > "
        "remove the disabled account.\n\n"
        "Azure CLI:\n"
        "  az role assignment delete --assignee <object-id> --scope <scope>\n\n"
        "Disabling is the right first step during offboarding, because it is reversible "
        "while questions are still being asked. Removing the privilege is the step that "
        "makes it stick."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        # Empty for the same reason as the rule above: the fix is removing a
        # role assignment, which is an operation on the directory rather than a
        # value on the account. Re-enabling the account would satisfy any
        # expectation written about ``account_enabled`` and is the opposite of
        # the fix.
        expected=(),
        cli=("az role assignment delete --assignee <object-id> --scope <scope>",),
        notes=(
            "No policy is generated: directory role membership is not a "
            "resource property, so no policyRule can express it."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["1.1.3"],
        "ISO_27001": ["A.5.16", "A.5.18"],
        "NIST_CSF": ["PR.AC-1", "PR.AC-4"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["AC-2", "PS-4"],
        "SOC2": ["CC6.2", "CC6.3"],
        "PCI_DSS_4": ["7.2.1", "8.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Identity data unavailable: {failure}")

        roles = resource.get("directory_roles")
        if roles is None:
            return RuleResult.unknown("Role membership missing from snapshot")
        if not _is_privileged(resource):
            return RuleResult.not_applicable("User holds no privileged role")

        enabled = resource.get("account_enabled")
        if enabled is None:
            return RuleResult.unknown(
                "The directory did not report whether this account is enabled"
            )
        if enabled is not False:
            return RuleResult.passed({"account_enabled": True, "privileged_roles": roles})

        return RuleResult.failed(
            evidence={
                "account_enabled": False,
                "privileged_roles": roles,
                "user_principal_name": resource.get("user_principal_name"),
            },
            message=(
                f"{resource.name} is disabled and still holds "
                + ", ".join(sorted(str(r) for r in roles))
            ),
        )
