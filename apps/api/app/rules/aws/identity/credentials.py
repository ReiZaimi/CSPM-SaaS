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


class AwsRootMfaRule(SecurityRule):
    rule_id = "AWS-IAM-005"
    name = "The root user has no MFA"
    description = (
        "The account's root user can sign in with a password alone. Root can do "
        "anything in the account, cannot be restricted by any policy, and is the "
        "one identity whose compromise is unrecoverable."
    )
    category = "identity"
    provider = Provider.AWS
    severity = Severity.CRITICAL
    exploitability = 4
    scope = RuleScope.AGGREGATE
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.ACCOUNT_SUMMARY,
    )
    estimated_effort_minutes = 15
    rationale = (
        "The root user's email address is usually known and its password is "
        "usually old. It is the one account no SCP can restrict and no policy "
        "can scope, so a second factor is the only control there is."
    )
    remediation = (
        "Sign in as root, go to Security credentials, and register an MFA "
        "device. A hardware key is the right answer for the one identity that "
        "cannot be limited any other way.\n\n"
        "There is no CLI path — only root can do this. Confirm afterwards from "
        "any principal that can read the summary:\n"
        "  aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'\n\n"
        "Then stop using root. Everything routine should be a role."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        # Aggregate: a property of the account rather than of any asset.
        expected=(),
        cli=("aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'",),
        notes=(
            "No CLI enables this: only the root user can, from the console's "
            "Security credentials page. The command above confirms afterwards."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["1.5"],
        "ISO_27001": ["A.5.17", "A.8.2"],
        "NIST_CSF": ["PR.AC-1", "PR.AC-7"],
        "NIST_800_53": ["IA-2"],
        "SOC2": ["CC6.1"],
        "PCI_DSS_4": ["8.4.2"],
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

        enabled = int(summary.get("AccountMFAEnabled", 0))
        evidence = {"root_mfa_enabled": enabled}
        if enabled:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence, message="The root user has no MFA device"
        )


class AwsAdministratorPolicyRule(SecurityRule):
    rule_id = "AWS-IAM-006"
    name = "A customer policy grants full administrative access"
    description = (
        "A customer-managed policy allows every action on every resource. "
        "Whoever holds it can do anything in the account, including granting "
        "themselves more."
    )
    category = "authorization"
    provider = Provider.AWS
    severity = Severity.HIGH
    # It is not a way in. It is what a foothold becomes: an identity holding
    # this has no ceiling, and can grant itself permanence.
    exploitability = 3
    scope = RuleScope.AGGREGATE
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.IAM_POLICIES,
        AwsEvidence.IAM_POLICY_DOCUMENTS,
    )
    estimated_effort_minutes = 60
    rationale = (
        "A policy granting `*:*` removes the ceiling on whoever holds it. It is "
        "also self-perpetuating: it includes `iam:*`, so its holder can create "
        "further access that survives the policy being taken away."
    )
    remediation = (
        "Replace it with the permissions actually used. IAM Access Analyzer "
        "generates a policy from CloudTrail history, which is the honest way to "
        "find out:\n\n"
        "  aws accessanalyzer start-policy-generation \\\n"
        "    --policy-generation-details principalArn=<role-arn> \\\n"
        "    --cloud-trail-details <details>\n\n"
        "Detach before deleting, and check what is attached first:\n"
        "  aws iam list-entities-for-policy --policy-arn <arn>\n\n"
        "AWS's own `AdministratorAccess` is excluded from this check: it is "
        "AWS-managed, sometimes genuinely needed, and not something this "
        "account wrote."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        # Aggregate, and about a document rather than an asset: policies are not
        # modelled as resources, because nobody secures a policy -- it is what
        # secures everything else.
        expected=(),
        cli=("aws iam list-entities-for-policy --policy-arn <arn>",),
        notes=(
            "Check what is attached before detaching. A policy attached to "
            "nothing today is attached to something tomorrow, which is why an "
            "unattached one is still reported."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["1.16"],
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
            return RuleResult.unknown(f"Policy documents unavailable: {failure}")

        documents = context.controls.get("iam_policy_documents") or []
        if not documents:
            return RuleResult.not_applicable(
                "This account has no customer-managed policies"
            )

        offenders = [
            {
                "arn": row.get("Arn"),
                "name": row.get("PolicyName"),
                "attached_to": row.get("AttachmentCount"),
            }
            for row in documents
            if _grants_everything(row.get("Document"))
        ]
        evidence = {"policies_checked": len(documents), "administrator": offenders}
        if not offenders:
            return RuleResult.passed(evidence)

        named = ", ".join(str(p["name"]) for p in offenders)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{len(offenders)} policy/policies grant full access: {named}",
        )


def _grants_everything(document: object) -> bool:
    """Whether a policy document allows every action on every resource.

    Read structurally rather than by string match. ``"Action": "*"`` and
    ``"Action": ["*"]`` are the same policy, and so is ``"*:*"`` -- IAM accepts
    both spellings, and a check that knew only one would pass the other.

    A ``Deny`` elsewhere in the same document does not rescue it: deny is
    evaluated against the request, not against the grant, and the statement
    still hands out everything it does not specifically refuse.
    """
    if not isinstance(document, dict):
        return False
    statements = document.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if not isinstance(statement, dict):
            continue
        if str(statement.get("Effect")) != "Allow":
            continue
        # A condition is a real limit, and a statement carrying one is not the
        # unbounded grant this rule is about.
        if statement.get("Condition"):
            continue
        actions = statement.get("Action") or []
        actions = [actions] if isinstance(actions, str) else actions
        resources = statement.get("Resource") or []
        resources = [resources] if isinstance(resources, str) else resources
        if any(str(a) in ("*", "*:*") for a in actions) and any(
            str(r) == "*" for r in resources
        ):
            return True
    return False


class AwsExpiredCertificateRule(SecurityRule):
    rule_id = "AWS-IAM-007"
    name = "An expired certificate is still in IAM"
    description = (
        "A TLS certificate uploaded to IAM has passed its expiry date. Either "
        "something is still serving it, or it is a leftover nobody removed."
    )
    category = "identity"
    provider = Provider.AWS
    severity = Severity.MEDIUM
    exploitability = 1
    scope = RuleScope.AGGREGATE
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.IAM_SERVER_CERTIFICATES,
    )
    estimated_effort_minutes = 15
    rationale = (
        "An expired certificate in use breaks clients or teaches them to click "
        "through warnings; one not in use is a leftover that will eventually be "
        "attached to something by mistake. Neither is a state to leave alone."
    )
    remediation = (
        "Find what uses it, then remove it:\n\n"
        "  aws iam list-server-certificates\n"
        "  aws iam delete-server-certificate --server-certificate-name <name>\n\n"
        "New certificates belong in ACM rather than IAM — ACM renews them, and "
        "IAM does not. IAM certificates are almost always a leftover from before "
        "ACM covered the service in question."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "aws iam delete-server-certificate --server-certificate-name <name>",
        ),
        notes=(
            "Check what serves it first. Deleting one still attached to a load "
            "balancer breaks TLS on it."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["1.19"],
        "ISO_27001": ["A.8.24"],
        "NIST_CSF": ["PR.DS-2"],
        "NIST_800_53": ["SC-12"],
        "SOC2": ["CC6.7"],
        "PCI_DSS_4": ["4.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Certificates unavailable: {failure}")

        certificates = context.controls.get("server_certificates") or []
        if not certificates:
            return RuleResult.not_applicable(
                "This account has no certificates in IAM"
            )

        # Expiry is judged against the capture rather than the clock, the same
        # way a credential's age is: a replayed scan has to reach the verdict
        # the original one did.
        expired = [
            {
                "name": row.get("ServerCertificateName"),
                "expiration": str(row.get("Expiration")),
            }
            for row in certificates
            if row.get("Expired") is True
        ]
        evidence = {"certificates": len(certificates), "expired": expired}
        if not expired:
            return RuleResult.passed(evidence)

        named = ", ".join(str(c["name"]) for c in expired)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{len(expired)} expired certificate(s) remain in IAM: {named}",
        )


class AwsAccessAnalyzerRule(SecurityRule):
    rule_id = "AWS-IAM-008"
    name = "IAM Access Analyzer is not enabled in every region"
    description = (
        "One or more enabled regions have no IAM Access Analyzer, so nothing is "
        "watching for resources shared outside the account."
    )
    category = "authorization"
    provider = Provider.AWS
    severity = Severity.MEDIUM
    exploitability = 1
    scope = RuleScope.AGGREGATE
    requires_evidence: ClassVar[tuple[AwsEvidence, ...]] = (
        AwsEvidence.ACCESS_ANALYZERS,
        AwsEvidence.ENABLED_REGIONS,
    )
    estimated_effort_minutes = 15
    rationale = (
        "Access Analyzer is the only service that answers \"what in this account "
        "can be reached from outside it\" by reasoning about the policies rather "
        "than by pattern-matching them. It is free, and off by default."
    )
    remediation = (
        "Create an analyzer per region:\n\n"
        "  aws accessanalyzer create-analyzer --analyzer-name account "
        "--type ACCOUNT --region <region>\n\n"
        "At the organization level, ``--type ORGANIZATION`` from the delegated "
        "administrator covers every member account, which is the version that "
        "stays true as accounts are added."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "aws accessanalyzer create-analyzer --analyzer-name account "
            "--type ACCOUNT --region <region>",
        ),
        notes=(
            "An analyzer in a non-ACTIVE state finds nothing, so this reads the "
            "status rather than the existence of the analyzer."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AWS_3.0": ["1.20"],
        "ISO_27001": ["A.5.15"],
        "NIST_CSF": ["PR.AC-4", "DE.CM-1"],
        "NIST_800_53": ["AC-6"],
        "SOC2": ["CC6.3"],
        "PCI_DSS_4": ["7.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Analyzer coverage unavailable: {failure}")

        enabled = set(context.controls.get("enabled_regions") or [])
        if not enabled:
            return RuleResult.unknown("The account's enabled regions are not known")

        covered = set(context.controls.get("access_analyzer_regions") or [])
        uncovered = sorted(enabled - covered)
        evidence = {
            "enabled_regions": sorted(enabled),
            "regions_covered": sorted(covered),
            "regions_without": uncovered,
        }
        if not uncovered:
            return RuleResult.passed(evidence)

        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"Access Analyzer is not enabled in {len(uncovered)} of "
                f"{len(enabled)} enabled regions: {', '.join(uncovered)}"
            ),
        )
