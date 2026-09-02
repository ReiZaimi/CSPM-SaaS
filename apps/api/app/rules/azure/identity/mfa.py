"""Identity rules. These read Microsoft Graph data, not ARM data."""

from typing import Any, ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, RuleScope, Severity
from app.domain.resource import CloudResource
from app.remediation import Comparison, ExpectedState, RemediationSpec
from app.risk.grouping import RiskGrouping
from app.rules.base import RuleContext, RuleResult, SecurityRule
from app.rules.controls import Control

# Entra directory roles that carry enough power that a missing second factor is
# a critical problem rather than a hygiene note.
PRIVILEGED_ROLES = {
    "global administrator",
    "privileged role administrator",
    "privileged authentication administrator",
    "security administrator",
    "application administrator",
    "cloud application administrator",
    "exchange administrator",
    "sharepoint administrator",
    "user administrator",
    "billing administrator",
    "conditional access administrator",
    "hybrid identity administrator",
    "intune administrator",
    "owner",
    "contributor",
    "user access administrator",
}


def _is_privileged(resource: CloudResource) -> bool:
    roles = resource.get("directory_roles", []) or []
    return any(str(r).strip().lower() in PRIVILEGED_ROLES for r in roles)


# What an attacker still needs once a second factor is demanded at sign-in: not
# the password, which they have, but the phone. Three on the scale in
# RULE_ENGINE.md section 5 -- a valid credential is no longer enough, and this
# is not a fix, so it does not fall further.
_MFA_ENFORCED = 3


def _enforced_on(
    resource: CloudResource, roles: list[Any], controls: dict[str, Any]
) -> tuple[Control, ...]:
    """Whether something already demands a second factor of this account.

    Security defaults first, because they are unconditional: switched on, every
    account in the tenant is challenged, with no scope to reason about.

    Then Conditional Access, matched on what the normalizer could establish --
    a policy is only offered here if it is enabled, grants multi-factor
    unambiguously, covers every application, and had every group it names read
    back. Anything less was dropped before it reached this function, because the
    single use of these is lowering a score.
    """
    found: list[Control] = []

    if controls.get("security_defaults_enabled") is True:
        found.append(
            Control(
                id="entra.security_defaults",
                name="Security defaults",
                detail=(
                    "Entra security defaults are enabled for this tenant, so every "
                    "account is challenged for a second factor at sign-in."
                ),
                exploitability=_MFA_ENFORCED,
            )
        )

    user_id = str(resource.provider_resource_id).rsplit("/", 1)[-1]
    held = {str(r).strip().lower() for r in roles}

    for policy in controls.get("mfa_policies", []) or []:
        if user_id in set(policy.get("excluded_user_ids") or []):
            continue
        if held & {str(r).strip().lower() for r in policy.get("excluded_role_names") or []}:
            continue

        covered = (
            policy.get("all_users")
            or user_id in set(policy.get("user_ids") or [])
            or bool(
                held & {str(r).strip().lower() for r in policy.get("role_names") or []}
            )
        )
        if not covered:
            continue

        found.append(
            Control(
                id=f"entra.conditional_access.{policy.get('id')}",
                name=str(policy.get("name")),
                detail=(
                    "This Conditional Access policy is enabled, applies to this "
                    "account and requires multi-factor authentication for every "
                    "application."
                ),
                exploitability=_MFA_ENFORCED,
            )
        )

    return tuple(found)


class AzureMfaRule(SecurityRule):
    rule_id = "AZ-ID-001"
    name = "Privileged user without multi-factor authentication"
    description = (
        "A user holding a privileged directory or subscription role has no multi-factor "
        "authentication method registered. A single stolen password is then enough to take "
        "over the account, and with it the role's privileges."
    )
    category = "identity"
    severity = Severity.CRITICAL
    exploitability = 4
    scope = RuleScope.PER_RESOURCE
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.USER]
    # Every one of them: a user without their role map cannot be judged
    # privileged, and one without authentication methods cannot be judged
    # at all. ``user_role_map`` is the task that reads both.
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.USERS,
        AzureEvidence.DIRECTORY_ROLES,
        AzureEvidence.USER_ROLE_MAP,
    )
    estimated_effort_minutes = 30
    # One risk, however many accounts. The fix named in ``remediation`` below is
    # a single Conditional Access policy covering every privileged role at once,
    # so a tenant with forty exposed administrators has one thing to do and not
    # forty -- and forty Critical risks would take the org security score to
    # zero over one policy that was never written.
    risk_grouping: ClassVar[RiskGrouping | None] = RiskGrouping(
        singular="A privileged account has no multi-factor authentication",
        plural="{count} privileged accounts have no multi-factor authentication",
    )
    rationale = (
        "Privileged accounts are the highest-value target in any tenant. Without a second "
        "factor, credential phishing or password reuse converts directly into administrative "
        "access to your whole environment."
    )
    remediation = (
        "Require multi-factor authentication for this account.\n\n"
        "Preferred: enforce it for all privileged roles at once with a Conditional Access "
        "policy — Entra admin centre > Protection > Conditional Access > Create new policy > "
        "assign to directory roles > Grant > Require multifactor authentication.\n\n"
        "Entra ID Free tenants: enable security defaults instead — Entra admin centre > "
        "Properties > Manage security defaults > Enabled.\n\n"
        "Then have the user register a method at https://aka.ms/mfasetup. Prefer an "
        "authenticator app or FIDO2 key over SMS."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="mfa_methods",
                comparison=Comparison.NOT_EMPTY,
                equals=None,
                describes=(
                    "The account has a second factor registered that is not a "
                    "password"
                ),
                example="microsoftAuthenticator",
            ),
        ),
        # Who the expectation is about. A rule that returns NOT_APPLICABLE for
        # every ordinary account is not passing them -- it is out of scope --
        # and saying so is the difference between "your users are fine" and
        # "this is about your administrators".
        applies_when={"directory_roles": ["Global Administrator"]},
        cli=(
            "az ad user get-member-groups --id <upn>",
        ),
        notes=(
            "No policy is generated and none can be. This is a directory "
            "setting rather than a resource property, so no policyRule can "
            "express it: it is enforced with a Conditional Access policy "
            "requiring multifactor authentication for directory roles, which "
            "is configured in Entra ID rather than deployed to a subscription."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["1.1.1", "1.1.2"],
        "ISO_27001": ["A.5.15", "A.5.17"],
        "NIST_CSF": ["PR.AC-1", "PR.AC-7"],
        "GDPR": ["25", "32(1)(b)"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Identity data unavailable: {failure}")

        if not _is_privileged(resource):
            # Non-privileged users are out of scope for this rule -- that is a
            # scope statement, not a clean bill of health.
            return RuleResult.not_applicable("User holds no privileged role")

        if resource.get("account_enabled") is False:
            return RuleResult.not_applicable("Account is disabled")

        methods = resource.get("mfa_methods")
        if methods is None:
            # Reading authentication methods needs a Graph permission that may
            # not have been consented. That is a coverage gap, not a pass.
            return RuleResult.unknown(
                "Authentication method data unavailable — "
                "UserAuthenticationMethod.Read.All may not be consented"
            )

        strong = [m for m in methods if str(m).lower() not in {"password", "none"}]
        roles = resource.get("directory_roles", []) or []

        if strong:
            return RuleResult.passed(
                {"mfa_registered": True, "methods": strong, "privileged_roles": roles}
            )

        enforced = _enforced_on(resource, roles, context.controls)
        return RuleResult.failed(
            evidence={
                "mfa_registered": False,
                "registered_methods": list(methods),
                "privileged_roles": roles,
                "user_principal_name": resource.get("user_principal_name"),
            },
            # Still a failure, and deliberately. A policy demanding a second
            # factor of an account that has never registered one locks that
            # account out of its own tenant the first time it is challenged --
            # which is a real operational problem, not a fixed one -- and the
            # policy can be disabled, rescoped or have this account excluded in
            # a change nobody reviews. What it does change is what an attacker
            # holding the password can do with it today.
            controls=enforced,
            message=(
                f"{resource.name} holds privileged role(s) "
                f"{', '.join(str(r) for r in roles)} with no MFA method registered"
                + (
                    f", though {enforced[0].name} still requires one at sign-in"
                    if enforced
                    else ""
                )
            ),
        )
