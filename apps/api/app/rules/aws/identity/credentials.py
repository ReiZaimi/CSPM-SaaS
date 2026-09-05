"""IAM rules: who can sign in, with what, and how long ago they last did.

Everything here reads IAM's credential report rather than the user listing.
``ListUsers`` says a user exists; the report says whether MFA is on, which keys
are active and when each was last used -- and those are the only facts any of
these rules turn on.

Ages come off the resource, computed by the normalizer against the capture's own
``collected_at``. A rule that read the clock would answer differently on replay,
which would make "verified fixed" a statement about when somebody asked.
"""

from typing import ClassVar

from app.connectors.aws.evidence import AwsEvidence
from app.core.enums import Provider, ResourceType, RuleScope, Severity
from app.domain.resource import CloudResource
from app.remediation import ExpectedState, RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule

# How long an active key may sit unused before it is more liability than tool.
# Ninety days is the CIS threshold and the one most customers already audit
# against, so a finding here lines up with a number they recognise.
STALE_KEY_DAYS = 90

# The shortest password length that is not an argument. CIS asks for 14.
MINIMUM_PASSWORD_LENGTH = 14


class AwsUserWithoutMfaRule(SecurityRule):
    rule_id = "AWS-IAM-001"
    name = "IAM user can sign in without MFA"
    description = (
        "A user has a console password and no MFA device. A phished or reused password "
        "is then the only thing between an attacker and that user's permissions."
    )
    category = "identity"
    provider = Provider.AWS
    severity = Severity.HIGH
    exploitability = 4
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.USER]
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.IAM_USERS,
        AwsEvidence.IAM_CREDENTIAL_REPORT,
    )
    estimated_effort_minutes = 15
    rationale = (
        "Password reuse and phishing are the ordinary way accounts are taken. MFA is "
        "the single control that makes a stolen password insufficient on its own."
    )
    remediation = (
        "Enrol the user in MFA, or remove their console password if they only use the "
        "API.\n\n"
        "AWS CLI:\n"
        "  aws iam list-virtual-mfa-devices\n"
        "  aws iam enable-mfa-device --user-name <user> --serial-number <arn> \\\n"
        "    --authentication-code1 <code1> --authentication-code2 <code2>\n\n"
        "To remove console access instead:\n"
        "  aws iam delete-login-profile --user-name <user>\n\n"
        "Better still, move people to IAM Identity Center with an identity provider, "
        "so MFA is enforced once rather than per user."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="mfa_active",
                equals=True,
                describes="The user has an MFA device registered",
            ),
        ),
        # Only about users who can sign in at all. A user with no console
        # password has nothing MFA protects, and a rule that judged them anyway
        # would raise a finding nobody can act on.
        applies_when={"password_enabled": True},
        notes=(
            "Preventive enforcement on AWS would be an AWS Config rule or an "
            "SCP. Neither is generated yet."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["1.10"],
        "ISO_27001": ["A.5.17"],
        "NIST_CSF": ["PR.AC-1", "PR.AC-7"],
        "NIST_800_53": ["IA-2"],
        "SOC2": ["CC6.1"],
        "PCI_DSS_4": ["8.4.2"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Credential state unavailable: {failure}")

        has_password = resource.get("password_enabled")
        has_mfa = resource.get("mfa_active")
        if has_password is None or has_mfa is None:
            return RuleResult.unknown(
                "The credential report did not cover this user"
            )
        evidence = {
            "password_enabled": has_password,
            "mfa_active": has_mfa,
            "user": resource.name,
        }

        # A user with no console password cannot sign in at all, so MFA is not
        # the control that matters for them -- their access keys are, and
        # AWS-IAM-003 is about those.
        if not has_password:
            return RuleResult.not_applicable(
                f"{resource.name} has no console password"
            )
        if has_mfa:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} can sign in with a password and no MFA",
        )


class AwsStaleAccessKeyRule(SecurityRule):
    rule_id = "AWS-IAM-003"
    name = "An access key has gone unused"
    description = (
        f"A user holds an active access key that has not been used for "
        f"{STALE_KEY_DAYS} days or more. It grants everything the user can do and "
        "nobody is watching it."
    )
    category = "identity"
    provider = Provider.AWS
    severity = Severity.MEDIUM
    # A credential of the kind routinely found in a repository, a laptop backup
    # or a CI log. Not reachable from the internet on its own.
    exploitability = 3
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.USER]
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.IAM_USERS,
        AwsEvidence.IAM_CREDENTIAL_REPORT,
    )
    estimated_effort_minutes = 20
    rationale = (
        "An unused key is all cost and no benefit: it can still be found in a "
        "repository or a backup, and because nothing uses it, nothing notices when "
        "something does."
    )
    remediation = (
        "Deactivate the key, wait for anything to break, then delete it.\n\n"
        "AWS CLI:\n"
        "  aws iam list-access-keys --user-name <user>\n"
        "  aws iam update-access-key --user-name <user> --access-key-id <id> "
        "--status Inactive\n"
        "  aws iam delete-access-key --user-name <user> --access-key-id <id>\n\n"
        "Deactivating first is deliberate: it is instantly reversible, and it is how "
        "you find out whether a job nobody remembers was using it."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        # No expected state, and this is the one place that is honest rather
        # than lazy: the expectation is "no *active* key has been unused for
        # ninety days", which is a threshold over a collection and not a setting
        # on an asset. Half-declaring it would let a customer satisfy what they
        # were shown and still have the finding open.
        expected=(),
        cli=(
            "aws iam list-access-keys --user-name <user>",
            "aws iam update-access-key --user-name <user> "
            "--access-key-id <id> --status Inactive",
            "aws iam delete-access-key --user-name <user> --access-key-id <id>",
        ),
        notes=(
            "The expectation is a threshold over the user's keys rather than a "
            "value on the user, so no expected state can state it. Deactivate "
            "first: it is instantly reversible and is how you find out whether "
            "a job nobody remembers was using the key."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["1.12", "1.14"],
        "ISO_27001": ["A.5.16", "A.5.18"],
        "NIST_CSF": ["PR.AC-1"],
        "NIST_800_53": ["AC-2"],
        "SOC2": ["CC6.2", "CC6.3"],
        "PCI_DSS_4": ["8.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Credential state unavailable: {failure}")

        if not resource.get("CredentialReport"):
            return RuleResult.unknown("The credential report did not cover this user")

        idle = resource.get("key_idle_days")
        if idle is None:
            # No active key at all, which is not a stale one.
            return RuleResult.not_applicable(f"{resource.name} holds no active key")

        evidence = {"idle_days": idle, "threshold_days": STALE_KEY_DAYS}
        if int(idle) < STALE_KEY_DAYS:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"{resource.name} has an active access key unused for {idle} days"
            ),
        )


class AwsRootAccessKeyRule(SecurityRule):
    rule_id = "AWS-IAM-002"
    name = "The root user has an active access key"
    description = (
        "The account's root user holds an access key. Root can do anything in the "
        "account, cannot be restricted by any policy, and its actions cannot be "
        "denied by an SCP."
    )
    category = "identity"
    provider = Provider.AWS
    severity = Severity.CRITICAL
    exploitability = 3
    scope = RuleScope.AGGREGATE
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.ACCOUNT_SUMMARY,
    )
    estimated_effort_minutes = 15
    rationale = (
        "There is no legitimate day-to-day use for a root access key, and no way to "
        "limit what one can do. A leaked root key is an unrecoverable compromise of "
        "the account rather than of a role within it."
    )
    remediation = (
        "Delete the root access keys. Sign in as root, go to Security credentials, "
        "and remove them; there is no CLI path, because nothing but root can do it.\n\n"
        "Then confirm from any principal that can read the summary:\n"
        "  aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'\n\n"
        "Anything that was using the key should be a role or an IAM user with only "
        "the permissions it needs."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        # Aggregate: the expectation is about the account, not about an asset,
        # so there is no resource an expected state could be checked against.
        expected=(),
        cli=(
            "aws iam get-account-summary "
            "--query 'SummaryMap.AccountAccessKeysPresent'",
        ),
        notes=(
            "There is no CLI that deletes a root access key: only the root user "
            "can, from the console's Security credentials page. The command "
            "above confirms afterwards that it is gone."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["1.4"],
        "ISO_27001": ["A.5.15", "A.8.2"],
        "NIST_CSF": ["PR.AC-4"],
        "NIST_800_53": ["AC-6"],
        "SOC2": ["CC6.3"],
        "PCI_DSS_4": ["7.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Account summary unavailable: {failure}")

        summary = context.controls.get("account_summary")
        if not summary:
            return RuleResult.unknown("Account summary missing from snapshot")

        present = int(summary.get("AccountAccessKeysPresent", 0))
        evidence = {
            "root_access_keys_present": present,
            "root_mfa_enabled": int(summary.get("AccountMFAEnabled", 0)),
        }
        if not present:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message="The root user has an active access key",
        )


class AwsPasswordPolicyRule(SecurityRule):
    rule_id = "AWS-IAM-004"
    name = "The account password policy is weak or absent"
    description = (
        "The account has no IAM password policy, or one that permits passwords "
        f"shorter than {MINIMUM_PASSWORD_LENGTH} characters."
    )
    category = "identity"
    provider = Provider.AWS
    severity = Severity.MEDIUM
    exploitability = 2
    scope = RuleScope.AGGREGATE
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.ACCOUNT_PASSWORD_POLICY,
    )
    estimated_effort_minutes = 10
    rationale = (
        "The policy is what applies to every console user who is not covered by an "
        "identity provider. Without one, AWS's own minimum applies and nothing stops "
        "a short password."
    )
    remediation = (
        "Set a policy on the account.\n\n"
        "AWS CLI:\n"
        "  aws iam update-account-password-policy \\\n"
        f"    --minimum-password-length {MINIMUM_PASSWORD_LENGTH} \\\n"
        "    --require-symbols --require-numbers --require-uppercase-characters \\\n"
        "    --require-lowercase-characters --allow-users-to-change-password\n\n"
        "Rotation requirements are deliberately not recommended here: forced expiry "
        "produces weaker, more predictable passwords, and current NIST guidance advises "
        "against it. Length and MFA are what carry the weight."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        # Aggregate: a property of the account rather than of any asset.
        expected=(),
        cli=(
            "aws iam update-account-password-policy "
            f"--minimum-password-length {MINIMUM_PASSWORD_LENGTH} "
            "--require-symbols --require-numbers "
            "--require-uppercase-characters --require-lowercase-characters",
        ),
        notes=(
            "Rotation is deliberately not part of this. Forced expiry produces "
            "weaker, more predictable passwords, and current NIST guidance "
            "advises against it; length and MFA carry the weight."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["1.8"],
        "ISO_27001": ["A.5.17"],
        "NIST_CSF": ["PR.AC-1"],
        "NIST_800_53": ["IA-5"],
        "SOC2": ["CC6.1"],
        "PCI_DSS_4": ["8.3.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Password policy unavailable: {failure}")

        policy = context.controls.get("password_policy")
        if policy is None:
            # Distinguishable from "no policy is set", which the collector
            # records as an empty list and the normalizer as ``None``. Both
            # arrive here as None, so this is the honest reading only because
            # the evidence check above has already ruled out a failed read.
            return RuleResult.failed(
                evidence={"policy": None},
                message="The account has no IAM password policy",
            )

        length = int(policy.get("MinimumPasswordLength", 0))
        evidence = {"minimum_password_length": length, "policy": policy}
        if length >= MINIMUM_PASSWORD_LENGTH:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"The password policy permits {length}-character passwords "
                f"(fewer than {MINIMUM_PASSWORD_LENGTH})"
            ),
        )
