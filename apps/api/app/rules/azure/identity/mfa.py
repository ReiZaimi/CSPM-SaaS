"""Identity rules. These read Microsoft Graph data, not ARM data."""

from typing import ClassVar

from app.core.enums import ResourceType, RuleScope, Severity
from app.domain.resource import CloudResource
from app.rules.base import RuleContext, RuleResult, SecurityRule

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
    requires_collection: ClassVar[list[str]] = ["identity"]
    estimated_effort_minutes = 30
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

        failure = context.has_collection_error("identity", "mfa")
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

        return RuleResult.failed(
            evidence={
                "mfa_registered": False,
                "registered_methods": list(methods),
                "privileged_roles": roles,
                "user_principal_name": resource.get("user_principal_name"),
            },
            message=(
                f"{resource.name} holds privileged role(s) "
                f"{', '.join(str(r) for r in roles)} with no MFA method registered"
            ),
        )
