"""AWS's answer to "how does a customer grant us access".

One grant where Azure has two, and the whole flow follows from that. There is no
consent screen, no directory permissions and no service principal to wait for --
the customer deploys one CloudFormation stack, and the role it creates is the
entire grant. A successful ``sts:AssumeRole`` proves everything there is to
prove, so it sets both ``consent_status`` and ``rbac_verified_at``
(``DECISIONS.md`` §70): leaving the first permanently PENDING would make
``is_verified`` false for a connection that verifies.

The **external id** is the security property this file exists to protect. It is
generated when the connection is created, written into the stack the customer
deploys, and required by the trust policy that stack installs. Without it,
anybody who learns CloudGuard's account id can create a role trusting CloudGuard
and have it scan an environment on their behalf.

.. warning::

   Nothing here has been run against a live AWS account. ``docs/AWS_INTEGRATION.md``
   §1 holds the checklist, and AWS is not offered in the UI until it has passed.
"""

from typing import Any

from app.connectors.aws.auth import cloudguard_principal_arn, new_external_id
from app.connectors.aws.client import AwsApiError, AwsClient
from app.connectors.aws.iam import (
    MANAGED_POLICY_ARNS,
    POLICY_VERSION,
    ROLE_NAME,
    STACK_NAME,
    TemplateContext,
    actions_granted_by,
    categories_behind,
    cloudformation_template,
    launch_stack_url,
    policy_is_current,
    version_of_granted,
)
from app.connectors.base import ConnectionCheck
from app.connectors.evidence import EvidenceCategory
from app.connectors.onboarding import (
    DeploymentArtifact,
    DiscoveredAccount,
    ProviderOnboarding,
)
from app.core.enums import ConnectionScope, Provider
from app.core.errors import NotConfigured, ValidationFailed
from app.core.logging import get_logger
from app.models.cloud_connection import CloudConnection

log = get_logger(__name__)

READY_TO_DEPLOY = "Deploy the CloudGuard stack to continue."

# Where the console link lands. An IAM role is global, so this only decides
# which console the customer sees; the stack creates the same role wherever it
# is run.
CONSOLE_REGION = "us-east-1"


class AwsOnboarding(ProviderOnboarding):
    provider = Provider.AWS
    root_scope = ConnectionScope.ORGANIZATION

    initial_status_detail = READY_TO_DEPLOY
    ready_to_deploy_detail = READY_TO_DEPLOY
    # Empty, and not an omission: an AWS grant either exists or does not.
    # There is no way to deploy the stack and have it grant less than it says,
    # which is exactly what Entra consent can do.
    grant_incomplete_prefix = ""
    has_separate_consent = False

    # ---------------------------------------------------------------- grants

    def grant_version(self) -> str:
        return POLICY_VERSION

    def scope_path(self, connection: CloudConnection) -> str | None:
        """What the customer sees this connection covering, in AWS's words.

        Not an ARN. The scope of an AWS grant is not one addressable thing the
        way an ARM scope is -- the same stack is deployed into every account
        beneath it -- so this is a label for the customer rather than something
        a call is made against.
        """
        if not connection.scope_id:
            return None
        if connection.scope_type == ConnectionScope.ACCOUNT:
            return f"account/{connection.scope_id}"
        if connection.scope_type == ConnectionScope.ORGANIZATIONAL_UNIT:
            return f"ou/{connection.scope_id}"
        return f"organization/{connection.scope_id}"

    def requires_scope_id(self, scope_type: ConnectionScope) -> bool:
        """Always, including at the widest scope.

        Azure's tenant root needs no id because consent reports the tenant.
        AWS has nothing equivalent: there is no call CloudGuard can make until
        it knows an account to assume a role in, so even an organization-wide
        connection names its management account.
        """
        return True

    def initial_provider_ref(self, connection: CloudConnection) -> dict[str, Any]:
        """The external id, generated now and never again.

        Generated server-side and never accepted from a request body, which is
        the whole point: an id the customer chooses is an id an attacker can
        choose. Written before any artefact names it, so the template and the
        trust policy cannot disagree about what it is.
        """
        account = connection.scope_id or ""
        return {
            "external_id": new_external_id(),
            "role_arn": f"arn:aws:iam::{account}:role/{ROLE_NAME}",
        }

    # ------------------------------------------------------------- artefacts

    def artifact_ready(self, connection: CloudConnection) -> bool:
        """Ready as soon as the connection exists.

        Azure's template waits for a service principal that consent has to
        publish; AWS's waits for nothing, because the identity the trust policy
        names is CloudGuard's own and was known before the customer arrived.
        """
        return bool(
            connection.provider_ref.get("external_id") and connection.scope_id
        )

    def artifact(self, connection: CloudConnection) -> DeploymentArtifact:
        external_id = str(connection.provider_ref.get("external_id") or "")
        if not external_id:
            raise ValidationFailed(
                "This connection has no external id yet, so there is nothing "
                "safe to deploy."
            )
        context = TemplateContext(
            principal_arn=cloudguard_principal_arn(), external_id=external_id
        )
        return DeploymentArtifact(
            body=cloudformation_template(context),
            filename="cloudguard-scanner.template.json",
        )

    def launch_url(self, connection: CloudConnection, artifact_url: str) -> str:
        return launch_stack_url(artifact_url, CONSOLE_REGION)

    # ------------------------------------------------------------- verifying

    def _client(self, connection: CloudConnection, service: str) -> AwsClient:
        from app.connectors.aws.auth import RoleAssumer

        reference = connection.provider_ref or {}
        assumer = RoleAssumer(
            str(reference.get("role_arn") or ""),
            str(reference.get("external_id") or ""),
        )
        return AwsClient(assumer, service, CONSOLE_REGION)

    async def probe(self, connection: CloudConnection) -> ConnectionCheck:
        """Assume the role and read one thing. Quiet on failure.

        Called on a loop while the customer is plausibly still deploying, so a
        refusal here is the normal state of a connection mid-setup.
        """
        check = ConnectionCheck(ok=False, tenant_id=connection.tenant_id or "")
        try:
            async with self._client(connection, "sts") as sts:
                identity = await sts.call("get_caller_identity")
            check.subscription_id = str(identity.get("Account") or "") or None
            check.permissions_verified.append(
                f"Assumed the scanner role as {identity.get('Arn')}"
            )
            async with self._client(connection, "ec2") as ec2:
                regions = await ec2.call("describe_regions", AllRegions=False)
            check.permissions_verified.append(
                f"{len(regions.get('Regions') or [])} region(s) readable"
            )
            # The trust boundary, reported by AWS rather than typed. There is no
            # consent callback here to carry it, so this call is where it comes
            # from -- and an account outside an organization answers with an
            # error, which is not a failure: a standalone account is a boundary
            # of one and says so by naming itself.
            check.tenant_id = await self._organization_id(connection) or str(
                identity.get("Account") or ""
            )
        except (AwsApiError, NotConfigured):
            return check
        except Exception:
            return check

        check.ok = True
        check.detail = "Connection verified"
        return check

    async def _organization_id(self, connection: CloudConnection) -> str | None:
        try:
            async with self._client(connection, "organizations") as organizations:
                described = await organizations.call("describe_organization")
        except Exception:
            return None
        return str((described.get("Organization") or {}).get("Id") or "") or None

    async def discover(self, connection: CloudConnection) -> list[DiscoveredAccount]:
        """Every account this connection covers, each with its own role to assume.

        An organization-wide connection assumes one role per member account. The
        same stack is deployed into each -- by StackSet, or one at a time -- so
        the ARNs differ only by account id and can be written here rather than
        collected. The external id is the connection's and is shared, which is
        correct: it identifies the *relationship*, not the account.

        A single-account connection discovers itself. That is not a special
        case so much as the honest answer for a boundary of one.
        """
        external_id = str((connection.provider_ref or {}).get("external_id") or "")
        if not external_id:
            return []

        if connection.scope_type == ConnectionScope.ACCOUNT:
            account_id = str(connection.scope_id or "")
            if not account_id:
                return []
            return [
                DiscoveredAccount(
                    account_id=account_id,
                    display_name=account_id,
                    provider_ref=self._account_ref(account_id, external_id),
                )
            ]

        try:
            async with self._client(connection, "organizations") as organizations:
                accounts = await organizations.paginate("list_accounts", "Accounts")
        except Exception as exc:
            log.warning(
                "aws.account_discovery_failed",
                connection_id=str(connection.id),
                error=str(exc),
            )
            return []

        found: list[DiscoveredAccount] = []
        for account in accounts:
            account_id = str(account.get("Id") or "")
            # A closed or suspended account cannot be read and is not a gap:
            # scanning one would fail every listing for a reason the customer
            # already knows about.
            if not account_id or str(account.get("Status")) != "ACTIVE":
                continue
            found.append(
                DiscoveredAccount(
                    account_id=account_id,
                    display_name=str(account.get("Name") or account_id),
                    provider_ref=self._account_ref(account_id, external_id),
                )
            )
        return found

    @staticmethod
    def _account_ref(account_id: str, external_id: str) -> dict[str, Any]:
        return {
            "role_arn": f"arn:aws:iam::{account_id}:role/{ROLE_NAME}",
            "external_id": external_id,
        }

    # ---------------------------------------------------------- grant drift

    def grant_is_behind(self, connection: CloudConnection) -> bool:
        return not policy_is_current(connection.role_version)

    def degraded_categories(
        self, connection: CloudConnection
    ) -> dict[EvidenceCategory, str]:
        if not self.grant_is_behind(connection):
            return {}
        explanation = (
            f"CloudGuard's scanner policy was updated to {POLICY_VERSION} and "
            f"this connection still has {connection.role_version}, which does "
            "not grant the permissions these checks need. Redeploy the stack "
            "from the connection page to enable them."
        )
        return {
            category: explanation
            for category in categories_behind(connection.role_version)
        }

    async def detect_grant_version(self, connection: CloudConnection) -> str | None:
        """What the deployed role actually allows, read from the role.

        From the policy document rather than from the stack's version tag,
        because a tag is a label and a label is not evidence -- the same reason
        the Azure equivalent resolves role definitions rather than trusting a
        name. It also gets the answer right for the customer who attached a
        broader policy of their own instead of deploying the stack.

        ``None`` means the question could not be answered, which is not the same
        as "behind": the caller leaves the recorded version alone rather than
        replacing a fact with a probe that did not land.
        """
        try:
            async with self._client(connection, "iam") as iam:
                inline = await iam.call("list_role_policies", RoleName=ROLE_NAME)
                statements: list[dict[str, Any]] = []
                for name in inline.get("PolicyNames") or []:
                    document = await iam.call(
                        "get_role_policy", RoleName=ROLE_NAME, PolicyName=str(name)
                    )
                    policy = document.get("PolicyDocument") or {}
                    statements.extend(policy.get("Statement") or [])
        except Exception as exc:
            log.warning(
                "aws.policy_version_probe_failed",
                connection_id=str(connection.id),
                error=str(exc),
            )
            return None

        if not statements:
            return None
        return version_of_granted(actions_granted_by(statements))

    # ------------------------------------------------------------ teardown

    def revocation_steps(self, connection: CloudConnection) -> dict:
        """Deleting the stack is the whole of it, and the customer runs it.

        CloudGuard cannot delete a role in someone else's account, and would not
        want the permission: ``iam:DeleteRole`` in a customer's account is a
        far more dangerous grant than the read access it would withdraw. So the
        command is generated and :func:`check_access_revoked` proves afterwards
        whether it worked, by the access failing.
        """
        account = connection.scope_id or ""
        external_id = str((connection.provider_ref or {}).get("external_id") or "")
        return {
            "principal_id": str((connection.provider_ref or {}).get("role_arn") or ""),
            "scope_path": self.scope_path(connection),
            "role_name": f"{ROLE_NAME} ({connection.role_version})",
            "tenant_id": connection.tenant_id,
            "external_id_note": (
                "The external id is not a secret you need to rotate after this. "
                "It only means anything to a role that requires it, and that "
                "role is what you are deleting."
                if external_id
                else ""
            ),
            "steps": [
                {
                    "title": "Delete the CloudGuard stack",
                    "detail": (
                        "Removes the scanner role. Run it in every account the "
                        "stack was deployed to, or delete the StackSet if you "
                        "used one."
                    ),
                    "command": (
                        f"aws cloudformation delete-stack --stack-name {STACK_NAME}"
                    ),
                },
                {
                    "title": "Confirm the role is gone",
                    "detail": "Optional. Answers NoSuchEntity once it is.",
                    "command": f"aws iam get-role --role-name {ROLE_NAME}",
                },
            ],
            "why_manual": (
                "CloudGuard holds read-only access and no write permission of "
                "any kind, so it cannot remove its own access. These run under "
                "your credentials, not CloudGuard's."
            ),
            "portal_url": (
                f"https://{CONSOLE_REGION}.console.aws.amazon.com/cloudformation/home"
                f"?region={CONSOLE_REGION}#/stacks"
            ),
            "account_id": account,
            "managed_policies": list(MANAGED_POLICY_ARNS),
        }
