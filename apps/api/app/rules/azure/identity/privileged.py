from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, RuleScope, Severity
from app.domain.resource import CloudResource
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
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["1.21"],
        "ISO_27001": ["A.5.15", "A.5.18"],
        "NIST_CSF": ["PR.AC-4"],
        "GDPR": ["25", "32(1)(b)"],
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
