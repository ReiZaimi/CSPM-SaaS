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
        "NIST_800_53": ["IA-2", "AC-2"],
        "SOC2": ["CC6.1", "CC6.2"],
        "PCI_DSS_4": ["8.3.1", "8.4.2"],
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


class AzureUserWithoutMfaRule(SecurityRule):
    rule_id = "AZ-ID-004"
    name = "User without multi-factor authentication"
    description = (
        "An ordinary user account has no multi-factor authentication method registered. "
        "A stolen or reused password is then the whole of the account's defence, and every "
        "account is a way into the tenant even when it holds no administrative role."
    )
    category = "identity"
    # Not CRITICAL, which is AZ-ID-001's answer for the same gap on an account
    # that administers the tenant. The distinction is the blast radius rather
    # than the exposure: both are one password away from being taken, and only
    # one of them takes the directory with it.
    severity = Severity.MEDIUM
    exploitability = 4
    scope = RuleScope.PER_RESOURCE
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.USER]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.USERS,
        AzureEvidence.DIRECTORY_ROLES,
        AzureEvidence.USER_ROLE_MAP,
    )
    estimated_effort_minutes = 20
    # One policy covers the tenant, so a tenant with two hundred exposed
    # accounts has one thing to do. Reported per account because each one is
    # separately fixed by the person who owns it, and grouped at the risk layer
    # so the score is charged once for the policy nobody wrote.
    risk_grouping: ClassVar[RiskGrouping | None] = RiskGrouping(
        singular="An account has no multi-factor authentication",
        plural="{count} accounts have no multi-factor authentication",
    )
    rationale = (
        "Password-only accounts are where most tenant compromises start, and they rarely "
        "stay ordinary: an attacker inside the directory can read it, phish colleagues from "
        "a trusted address, and wait for an administrator to grant the account something."
    )
    remediation = (
        "Require multi-factor authentication for every account, not only privileged ones.\n\n"
        "Preferred: a Conditional Access policy covering all users — Entra admin centre > "
        "Protection > Conditional Access > Create new policy > Users: All users > Grant > "
        "Require multifactor authentication. Exclude only a break-glass account.\n\n"
        "Entra ID Free tenants: enable security defaults instead — Entra admin centre > "
        "Properties > Manage security defaults > Enabled.\n\n"
        "Then have each user register a method at https://aka.ms/mfasetup. Prefer an "
        "authenticator app or FIDO2 key over SMS."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="mfa_methods",
                comparison=Comparison.NOT_EMPTY,
                equals=None,
                describes="The account has a second factor registered",
                example="microsoftAuthenticator",
            ),
        ),
        cli=("az ad user list --query \"[].{upn:userPrincipalName}\" -o table",),
        notes=(
            "No policy is generated and none can be: this is a directory "
            "setting rather than a resource property, enforced with a "
            "Conditional Access policy or security defaults in Entra ID."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["1.1.2", "1.1.3"],
        "ISO_27001": ["A.5.15", "A.5.17"],
        "NIST_CSF": ["PR.AC-1", "PR.AC-7"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["IA-2", "IA-5"],
        "SOC2": ["CC6.1"],
        "PCI_DSS_4": ["8.3.1", "8.4.2"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Identity data unavailable: {failure}")

        # Privileged accounts belong to AZ-ID-001, which says the same thing
        # about them at Critical. Reporting both would raise two findings for
        # one missing second factor and charge the score twice for it.
        if _is_privileged(resource):
            return RuleResult.not_applicable(
                "Privileged accounts are judged by AZ-ID-001"
            )

        if resource.get("account_enabled") is False:
            return RuleResult.not_applicable("Account is disabled")

        methods = resource.get("mfa_methods")
        if methods is None:
            return RuleResult.unknown(
                "Authentication method data unavailable — "
                "UserAuthenticationMethod.Read.All may not be consented"
            )

        strong = [m for m in methods if str(m).lower() not in {"password", "none"}]
        if strong:
            return RuleResult.passed({"mfa_registered": True, "methods": strong})

        enforced = _enforced_on(resource, [], context.controls)
        return RuleResult.failed(
            evidence={
                "mfa_registered": False,
                "registered_methods": list(methods),
                "user_principal_name": resource.get("user_principal_name"),
            },
            controls=enforced,
            message=(
                f"{resource.name} signs in with a password and nothing else"
            ),
        )


class AzureTenantMfaEnforcementRule(SecurityRule):
    rule_id = "AZ-ID-005"
    name = "Nothing enforces multi-factor authentication tenant-wide"
    description = (
        "Neither security defaults nor an enabled Conditional Access policy requires a "
        "second factor of every account for every application. Whether any given user has "
        "one is then up to that user, and an account that registers nothing is protected by "
        "its password alone."
    )
    category = "identity"
    severity = Severity.HIGH
    exploitability = 4
    scope = RuleScope.AGGREGATE
    applies_to: ClassVar[list[ResourceType]] = []
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.SECURITY_DEFAULTS,
        AzureEvidence.CONDITIONAL_ACCESS_POLICIES,
    )
    estimated_effort_minutes = 45
    rationale = (
        "Per-account registration is a policy nobody enforces: it covers whoever happened "
        "to opt in, and the accounts that did not are exactly the ones an attacker will "
        "find. A tenant-wide requirement is one setting and it is the setting that turns a "
        "stolen password into a failed sign-in."
    )
    remediation = (
        "Require a second factor of everybody, in one place.\n\n"
        "Entra ID P1 or P2: Entra admin centre > Protection > Conditional Access > Create "
        "new policy > Users: All users (exclude one break-glass account) > Target "
        "resources: All cloud apps > Grant > Require multifactor authentication > enable "
        "the policy.\n\n"
        "Entra ID Free: Entra admin centre > Properties > Manage security defaults > "
        "Enabled. This challenges every account and blocks legacy authentication, at the "
        "cost of the per-policy control the licensed option gives you.\n\n"
        "Keep one break-glass account excluded, with a long unique password and its "
        "credentials held offline, so a broken policy cannot lock everybody out."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        # Empty, and the emptiness is the statement. This is a fact about the
        # tenant's directory rather than about any asset, so there is nothing
        # whose settings can be made to satisfy it -- inventing a per-asset
        # expectation would tell a customer to change one account when the
        # finding is that nothing covers all of them.
        expected=(),
        cli=("az ad signed-in-user show",),
        notes=(
            "No policy is generated and none can be: Conditional Access and "
            "security defaults are directory settings in Entra ID rather than "
            "resource properties, so no policyRule can express them."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["1.1.1", "1.1.2", "1.1.3"],
        "ISO_27001": ["A.5.15", "A.5.17"],
        "NIST_CSF": ["PR.AC-1", "PR.AC-7"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["IA-2", "AC-2"],
        "SOC2": ["CC6.1", "CC6.2"],
        "PCI_DSS_4": ["8.3.1", "8.4.2"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Tenant policy unavailable: {failure}")

        controls = context.controls
        defaults = controls.get("security_defaults_enabled")
        policies = controls.get("mfa_policies")

        # Neither reading arrived. Absent is not "off": a tenant whose policies
        # were never read is one CloudGuard cannot speak for, and saying so is
        # the difference between a gap and an accusation.
        if defaults is None and policies is None:
            return RuleResult.unknown(
                "Neither security defaults nor Conditional Access policies were read"
            )

        if defaults is True:
            return RuleResult.passed(
                {"security_defaults_enabled": True, "tenant_wide_mfa": True}
            )

        # Only a policy the normalizer could establish covers everybody: enabled,
        # unambiguously multi-factor, every application, every user, with every
        # group it excludes read back. Anything less was dropped before here.
        covering = [p for p in (policies or []) if p.get("all_users")]
        if covering:
            return RuleResult.passed(
                {
                    "security_defaults_enabled": False,
                    "tenant_wide_mfa": True,
                    "policies": [str(p.get("name")) for p in covering],
                }
            )

        return RuleResult.failed(
            evidence={
                "security_defaults_enabled": defaults,
                "tenant_wide_mfa": False,
                "enforced_policy_count": len(policies or []),
                # Named rather than counted: a tenant with three policies that
                # each cover one group is a tenant whose administrator believes
                # they have this, and the list is what shows they do not.
                "policies_covering_some_users": [
                    str(p.get("name")) for p in (policies or [])
                ][:20],
            },
            message=(
                "No security default and no Conditional Access policy requires "
                "multi-factor authentication of every account"
            ),
        )


class AzureLegacyAuthenticationRule(SecurityRule):
    rule_id = "AZ-ID-006"
    name = "Legacy authentication is not blocked"
    description = (
        "Nothing blocks the older authentication protocols — IMAP, POP, SMTP AUTH, "
        "Exchange ActiveSync and the pre-modern Office clients. They cannot present a "
        "second factor, so they bypass Conditional Access entirely: a password alone is "
        "accepted on those endpoints however strictly the tenant enforces MFA elsewhere."
    )
    category = "identity"
    severity = Severity.HIGH
    exploitability = 4
    scope = RuleScope.AGGREGATE
    applies_to: ClassVar[list[ResourceType]] = []
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.CONDITIONAL_ACCESS_POLICIES,
        AzureEvidence.SECURITY_DEFAULTS,
    )
    estimated_effort_minutes = 45
    rationale = (
        "Legacy protocols are the standing workaround for every multi-factor requirement a "
        "tenant has. Microsoft's own telemetry put the overwhelming majority of password "
        "spray and credential stuffing against them, precisely because a second factor "
        "cannot be asked for over a protocol that has no way to present one."
    )
    remediation = (
        "Block the protocols that cannot carry a second factor.\n\n"
        "Entra ID P1 or P2: Entra admin centre > Protection > Conditional Access > Create "
        "new policy > Users: All users > Target resources: All cloud apps > Conditions > "
        "Client apps > tick 'Exchange ActiveSync clients' and 'Other clients' > Grant > "
        "Block access > enable the policy.\n\n"
        "Entra ID Free: enabling security defaults blocks legacy authentication as part of "
        "the same switch.\n\n"
        "Check what would break first: Entra admin centre > Monitoring > Sign-in logs, "
        "filter Client app to the legacy values, and look at which accounts and services "
        "appear. Most are mail clients that support modern authentication and simply have "
        "not been reconfigured."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        # Empty, and the emptiness is the statement. This is a fact about the
        # tenant's directory rather than about any asset, so there is nothing
        # whose settings can be made to satisfy it -- inventing a per-asset
        # expectation would tell a customer to change one account when the
        # finding is that nothing covers all of them.
        expected=(),
        cli=("az ad signed-in-user show",),
        notes=(
            "No policy is generated and none can be: Conditional Access and "
            "security defaults are directory settings in Entra ID rather than "
            "resource properties, so no policyRule can express them."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["1.1.3", "1.21"],
        "ISO_27001": ["A.5.15", "A.5.17", "A.8.2"],
        "NIST_CSF": ["PR.AC-1", "PR.AC-7"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["IA-2", "AC-17"],
        "SOC2": ["CC6.1", "CC6.6"],
        "PCI_DSS_4": ["8.3.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Tenant policy unavailable: {failure}")

        controls = context.controls
        blocked = controls.get("legacy_authentication_blocked")
        defaults = controls.get("security_defaults_enabled")

        if blocked is None and defaults is None:
            return RuleResult.unknown(
                "Neither Conditional Access policies nor security defaults were read"
            )

        # Security defaults block legacy authentication as part of the same
        # switch, so a tenant on them needs no policy of its own.
        if defaults is True:
            return RuleResult.passed(
                {"legacy_authentication_blocked": True, "via": "security_defaults"}
            )
        if blocked is True:
            return RuleResult.passed(
                {"legacy_authentication_blocked": True, "via": "conditional_access"}
            )

        return RuleResult.failed(
            evidence={
                "legacy_authentication_blocked": False,
                "security_defaults_enabled": defaults,
            },
            message=(
                "Legacy authentication protocols are still accepted, so a "
                "password alone signs in on those endpoints"
            ),
        )
