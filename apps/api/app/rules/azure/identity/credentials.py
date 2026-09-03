"""What an application registration's credentials are worth to a thief.

Read from Microsoft Graph under ``Application.Read.All``, which admin consent
has requested since onboarding existed (``DECISIONS.md`` section 63), so no
customer pays anything for this check.
"""

from typing import Any, ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, RuleScope, Severity
from app.domain.resource import CloudResource
from app.remediation import RemediationSpec
from app.risk.grouping import RiskGrouping
from app.rules.base import RuleContext, RuleResult, SecurityRule


class AzureLongLivedApplicationCredentialRule(SecurityRule):
    """How long a stolen client secret keeps working.

    Deliberately not "this credential has expired". An expired secret grants
    nobody anything -- it is an application that has stopped working, which is
    the customer's outage rather than their exposure, and a finding for it
    would fill a security tool with operational noise. What an attacker gets is
    the *remaining* life of a credential they steal today, which is the one
    thing about an expiry date that is a security fact.
    """

    rule_id = "AZ-APP-001"
    name = "Application credential valid for years"
    description = (
        "An application registration holds a client secret or certificate that stays "
        "valid far into the future. A secret is a password that no second factor "
        "protects and no person notices being used, so one copied out of a pipeline "
        "log or a developer's machine keeps working until the date it was issued for."
    )
    category = "identity"
    severity = Severity.MEDIUM
    # A valid credential is what an attacker must already hold -- this does not
    # hand out access, it decides how long stolen access lasts.
    exploitability = 3
    scope = RuleScope.PER_RESOURCE
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.APPLICATION]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.APPLICATION_CREDENTIALS,
    )
    estimated_effort_minutes = 45
    risk_grouping: ClassVar[RiskGrouping | None] = RiskGrouping(
        singular="An application credential stays valid for years",
        plural="{count} application credentials stay valid for years",
    )
    rationale = (
        "Client secrets are bearer credentials: whoever holds one is the application. "
        "Shortening how long they last is the only control that limits what a leaked "
        "secret is worth, because nothing else stands between the secret and a token."
    )
    remediation = (
        "Shorten the credential's lifetime, or stop using one.\n\n"
        "Preferred: use a managed identity or workload identity federation instead — "
        "neither has a secret to leak. Entra admin centre > App registrations > select "
        "the app > Certificates & secrets > Federated credentials.\n\n"
        "Where a secret is genuinely needed, issue it for months rather than years and "
        "rotate it on that schedule:\n"
        "  az ad app credential reset --id <appId> --years 1\n\n"
        "Then remove the long-lived credential:\n"
        "  az ad app credential delete --id <appId> --key-id <keyId>\n\n"
        "Deleting a credential an application still uses stops that application, so "
        "issue the replacement and cut over before removing the old one."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        # Empty, and for the reason AZ-ID-002's is: what this rule checks is a
        # duration measured from the moment of capture, not a value sitting on
        # the asset. "endDateTime is less than a year from the day you last
        # scanned" is not a state a policy can match or a customer can set.
        expected=(),
        cli=(
            "az ad app credential list --id <appId>",
            "az ad app credential reset --id <appId> --years 1",
        ),
        notes=(
            "No policy is generated and none can be. Azure Policy governs "
            "resources in a subscription, and an application registration is a "
            "directory object -- there is no policyRule that reaches it. The "
            "fix is to reissue the credential with a shorter lifetime, or to "
            "replace it with a federated credential that has no secret at all."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.5.17"],
        "NIST_CSF": ["PR.AC-1"],
        "NIST_800_53": ["IA-5"],
        "SOC2": ["CC6.1"],
        # The nearest control this catalogue holds. PCI's own requirement about
        # application and system account credentials is 8.6, which is not in
        # the catalogue; 8.3.1 is the authentication requirement a bearer
        # secret with years of life is the weak form of, and mapping it there
        # is a closer claim than mapping it nowhere.
        "PCI_DSS_4": ["8.3.1"],
        "GDPR": ["32(1)(b)"],
    }

    # Longer than this and the credential is not a rotating secret, it is a
    # standing one. Microsoft's own portal offers 6, 12 and 24 months and
    # recommends the shortest workable; a year of remaining life is generous
    # enough that a tenant rotating on any sensible schedule never sees this.
    MAX_REMAINING_DAYS = 365

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Application data unavailable: {failure}")

        credentials: list[dict[str, Any]] = resource.get("credentials") or []
        if not credentials:
            # An application authenticating through a federated credential or a
            # managed identity has none of these, which is the recommended
            # shape rather than an unchecked one.
            return RuleResult.not_applicable(
                "Application holds no client secret or certificate"
            )

        unreadable = [c for c in credentials if c.get("days_remaining") is None]
        long_lived = [
            c
            for c in credentials
            if c.get("days_remaining") is not None
            and int(c["days_remaining"]) > self.MAX_REMAINING_DAYS
        ]

        if long_lived:
            worst = max(long_lived, key=lambda c: int(c["days_remaining"]))
            return RuleResult.failed(
                evidence={
                    "long_lived_credentials": long_lived,
                    "threshold_days": self.MAX_REMAINING_DAYS,
                    "credential_count": len(credentials),
                    "app_id": resource.get("app_id"),
                },
                message=(
                    f"{resource.name} holds a {worst['kind']} valid for another "
                    f"{int(worst['days_remaining'])} days"
                ),
            )

        if unreadable:
            # A date this scan could not read is a credential it knows nothing
            # about. Reporting the rest as clean would be a pass covering
            # something nobody looked at.
            return RuleResult.unknown(
                f"{len(unreadable)} credential(s) carry an expiry date this scan "
                "could not read"
            )

        return RuleResult.passed(
            {
                "credentials": credentials,
                "threshold_days": self.MAX_REMAINING_DAYS,
                "app_id": resource.get("app_id"),
            }
        )
