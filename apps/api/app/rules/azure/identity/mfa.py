"""Identity rules. These read Microsoft Graph data, not ARM data."""

from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, RuleScope, Severity
from app.domain.resource import CloudResource
from app.remediation import Comparison, ExpectedState, RemediationSpec
from app.risk.grouping import RiskGrouping
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
