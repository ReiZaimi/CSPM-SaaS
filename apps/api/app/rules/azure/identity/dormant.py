"""Privileged accounts nobody uses.

``signInActivity`` comes from Microsoft Graph under ``AuditLog.Read.All`` with
``User.Read.All`` -- both consented since onboarding existed -- and additionally
requires the tenant to hold an Entra ID P1 or P2 licence. A tenant without one
is refused the reading and this rule reports UNKNOWN with that reason, because
a licence is not something admin consent can grant (``DECISIONS.md`` section
63).
"""

from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, RuleScope, Severity
from app.domain.resource import CloudResource
from app.remediation import RemediationSpec
from app.risk.grouping import RiskGrouping
from app.rules.azure.identity.mfa import _is_privileged
from app.rules.base import RuleContext, RuleResult, SecurityRule


class AzureDormantPrivilegedAccountRule(SecurityRule):
    """An administrator account that nobody has signed into for months.

    The account is not dangerous because it is idle. It is dangerous because
    nobody is watching it: a standing administrator credential whose owner has
    changed team, left, or forgotten it exists is one whose misuse produces no
    complaint from the person it belongs to.
    """

    rule_id = "AZ-ID-003"
    name = "Privileged account is dormant"
    description = (
        "An account holding a privileged directory role has not signed in for months, "
        "or has never signed in at all. Its privileges are standing, so a stolen "
        "password still works — and because nobody uses the account, nobody notices "
        "when somebody else does."
    )
    category = "identity"
    severity = Severity.HIGH
    # Standing privilege behind a credential nobody would miss. The attacker
    # still needs that credential, so this is the same rung as the MFA rule's
    # compensated case rather than an open door.
    exploitability = 3
    scope = RuleScope.PER_RESOURCE
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.USER]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.USERS,
        AzureEvidence.DIRECTORY_ROLES,
        AzureEvidence.USER_ROLE_MAP,
        AzureEvidence.USER_SIGN_IN_ACTIVITY,
    )
    estimated_effort_minutes = 20
    risk_grouping: ClassVar[RiskGrouping | None] = RiskGrouping(
        singular="A privileged account has gone unused",
        plural="{count} privileged accounts have gone unused",
    )
    rationale = (
        "Leftover administrative accounts are how a departure becomes a breach months "
        "later. Removing privilege nobody exercises costs the customer nothing they "
        "were using, and removes an account from the set an attacker can quietly try."
    )
    remediation = (
        "Decide whether the account is still needed, then act on the answer.\n\n"
        "If the person has left or no longer needs the role: remove the role assignment "
        "— Entra admin centre > Roles and administrators > select the role > "
        "Assignments > Remove. Disable or delete the account itself if nothing else "
        "uses it.\n\n"
        "If the account is a break-glass account, it is expected to be idle: exclude it "
        "from this review by keeping it documented, and confirm its credentials are "
        "stored where they can be reached in an incident.\n\n"
        "Where Entra ID P2 is available, make the role eligible rather than permanent "
        "with Privileged Identity Management, so an unused role grants nothing until "
        "somebody activates it:\n"
        "  az rest --method get --url "
        "'https://graph.microsoft.com/v1.0/users/<id>?$select=signInActivity'"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        # Empty for the same reason AZ-ID-002's is: what is wrong here is an
        # absence measured against the date of the scan, not a setting on the
        # account. There is no field a customer can set to "recently used".
        expected=(),
        cli=(
            "az ad user get-member-groups --id <upn>",
            "az role assignment list --all --assignee <upn> -o table",
        ),
        notes=(
            "No policy is generated and none can be. Dormancy is a fact about "
            "how an account has been used rather than how it is configured, so "
            "no policyRule and no expected state can express it. The fix is to "
            "remove privilege nobody exercises, or to convert it to an eligible "
            "assignment in Privileged Identity Management."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.5.18"],
        "NIST_CSF": ["PR.AC-1"],
        "NIST_800_53": ["AC-2", "PS-4"],
        "SOC2": ["CC6.2", "CC6.3"],
        "PCI_DSS_4": ["7.2.1"],
        "GDPR": ["32(1)(b)"],
    }

    # Long enough that quarterly duties, parental leave and a long holiday do
    # not read as abandonment; short enough that a departure shows up in the
    # same quarter it happened.
    DORMANT_AFTER_DAYS = 90

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Identity data unavailable: {failure}")

        if not _is_privileged(resource):
            return RuleResult.not_applicable("User holds no privileged role")

        if resource.get("account_enabled") is False:
            # A disabled account signs nobody in. Its role assignment is still
            # untidy, and that is AZ-ID-002's question rather than this one.
            return RuleResult.not_applicable("Account is disabled")

        if resource.get("sign_in_activity_read") is not True:
            return RuleResult.unknown(
                "Sign-in activity was not read for this account, so it cannot be "
                "told apart from one in daily use"
            )

        roles = resource.get("directory_roles", []) or []
        days = resource.get("days_since_sign_in")
        age = resource.get("account_age_days")

        if days is None:
            # Entra holds no sign-in for this account at all. For an account
            # that has existed long enough to be used, that is the strongest
            # form of the finding rather than a missing reading.
            if age is not None and int(age) < self.DORMANT_AFTER_DAYS:
                return RuleResult.passed(
                    {
                        "never_signed_in": True,
                        "account_age_days": int(age),
                        "threshold_days": self.DORMANT_AFTER_DAYS,
                        "privileged_roles": roles,
                    }
                )
            return RuleResult.failed(
                evidence={
                    "never_signed_in": True,
                    "account_age_days": age,
                    "threshold_days": self.DORMANT_AFTER_DAYS,
                    "privileged_roles": roles,
                    "user_principal_name": resource.get("user_principal_name"),
                },
                message=(
                    f"{resource.name} holds privileged role(s) "
                    f"{', '.join(str(r) for r in roles)} and has never signed in"
                ),
            )

        if int(days) > self.DORMANT_AFTER_DAYS:
            return RuleResult.failed(
                evidence={
                    "days_since_sign_in": int(days),
                    "last_sign_in": resource.get("last_sign_in"),
                    "threshold_days": self.DORMANT_AFTER_DAYS,
                    "privileged_roles": roles,
                    "user_principal_name": resource.get("user_principal_name"),
                },
                message=(
                    f"{resource.name} holds privileged role(s) "
                    f"{', '.join(str(r) for r in roles)} and last signed in "
                    f"{int(days)} days ago"
                ),
            )

        return RuleResult.passed(
            {
                "days_since_sign_in": int(days),
                "last_sign_in": resource.get("last_sign_in"),
                "threshold_days": self.DORMANT_AFTER_DAYS,
                "privileged_roles": roles,
            }
        )
