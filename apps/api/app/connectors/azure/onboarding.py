"""Azure's answer to "how does a customer grant us access".

Everything here was in ``services/cloud_connections.py`` and is unchanged in
behaviour. It moved because a second provider now exists to move it *for*
(``MULTI_CLOUD.md`` §8 step 5): the service kept the database work, the polling
and the scope choices, and this holds the half that only means anything in
Azure -- consent links, Graph lookups, the ARM template, role versions read
back from role assignments.

The two-grant shape is the thing to keep in view. Entra admin consent covers
Microsoft Graph, an ARM role covers the subscriptions, and the two fail
independently -- a customer very often completes the first and forgets the
second. Both are proven by being used, never by the customer saying they did it.
"""

import json
import time
from urllib.parse import quote

# Imported as a module, not by name. Every entry point here is exercised by
# tests that replace ``TokenProvider`` with one that issues a prepared token,
# and a name bound at import time would not see that -- the service this code
# came from imported inside each function for exactly that reason, which read
# as an accident and was load-bearing.
from app.connectors.azure import auth
from app.connectors.azure.client import ArmClient, AzureApiError, GraphClient
from app.connectors.azure.rbac import (
    ROLE_NAME,
    ROLE_VERSION,
    TemplateContext,
    actions_granted_by,
    arm_template,
    categories_behind,
    role_is_current,
    version_of_granted,
)
from app.connectors.base import ConnectionCheck
from app.connectors.evidence import EvidenceCategory
from app.connectors.onboarding import (
    DeploymentArtifact,
    DiscoveredAccount,
    PrincipalLookup,
    ProviderOnboarding,
)
from app.core.config import settings
from app.core.enums import ConnectionScope, ConsentStatus, Provider
from app.core.errors import NotConfigured, ValidationFailed
from app.core.logging import get_logger
from app.core.signing import sign_state
from app.models.cloud_connection import CloudConnection

log = get_logger(__name__)

READY_TO_DEPLOY = "Admin consent granted. Deploy the scanner role next."

# Marks a status detail as being about the directory grant rather than the
# subscription one. Checked as a prefix so a later step can tell the two apart
# without a schema change: everything else on this connection may be healthy
# while this is not, and the message must not be replaced by a cheerful one.
GRANT_INCOMPLETE_PREFIX = "Admin consent did not grant"


class AzureOnboarding(ProviderOnboarding):
    provider = Provider.AZURE
    root_scope = ConnectionScope.TENANT_ROOT

    initial_status_detail = "Grant admin consent to continue."
    ready_to_deploy_detail = READY_TO_DEPLOY
    grant_incomplete_prefix = GRANT_INCOMPLETE_PREFIX

    # ---------------------------------------------------------------- grants

    def grant_version(self) -> str:
        return ROLE_VERSION

    def scope_path(self, connection: CloudConnection) -> str | None:
        """The ARM scope an assignment is created at.

        A tenant's root management group is named with the tenant id, so
        TENANT_ROOT resolves only once consent has told us what that is.
        """
        if connection.scope_type == ConnectionScope.SUBSCRIPTION:
            return f"/subscriptions/{connection.scope_id}" if connection.scope_id else None
        if connection.scope_type == ConnectionScope.MANAGEMENT_GROUP:
            group = connection.scope_id
        else:
            group = connection.tenant_id
        return (
            f"/providers/Microsoft.Management/managementGroups/{group}"
            if group
            else None
        )

    def start_url(self, connection: CloudConnection) -> tuple[str | None, str | None]:
        """A fresh consent link, or the reason there cannot be one.

        Regenerated on every read rather than stored, for two reasons. The
        state is signed with a 30-minute TTL, so a URL persisted at creation
        would be dead long before most customers get their administrator's
        attention. And it used to be returned *only* from the create response,
        which meant a page reload lost the consent button entirely and stranded
        the connection in PENDING with no way forward but deleting it.

        The failure reason is returned rather than swallowed. A deployment
        whose Entra credentials are wrong cannot produce this URL at all, and
        the customer needs to see that instead of a card with nothing on it.
        """
        try:
            state = sign_state(
                {
                    "cloud_connection_id": str(connection.id),
                    "organization_id": str(connection.organization_id),
                    "issued_at": time.time(),
                }
            )
            return auth.build_consent_url(state), None
        except NotConfigured as exc:
            return None, str(exc)
        except Exception as exc:  # pragma: no cover -- signing failure is unexpected
            log.warning(
                "azure.consent_url_failed",
                connection_id=str(connection.id),
                error=str(exc),
            )
            return None, f"Could not build a consent link: {exc}"

    async def grant_problem(self, connection: CloudConnection) -> str | None:
        """What consent failed to grant, named, or None when it granted
        everything.

        Consent resolves ``/.default`` to whatever CloudGuard's app
        registration declares at the moment it is clicked, so a registration
        whose permissions are missing -- or declared as delegated rather than
        application -- produces a consent screen that looks entirely successful
        and a token carrying no directory permissions at all. Nothing
        downstream could tell: the callback recorded GRANTED on Entra's
        redirect alone, and the first evidence anyone saw was the identity
        category failing mid-scan with "Insufficient privileges to complete the
        operation", a sentence naming neither the permission nor who can grant
        it.

        The token answers it before any call is made. Read for diagnosis only
        -- Microsoft stays the enforcer.
        """
        if not connection.tenant_id:
            return None

        try:
            tokens = auth.TokenProvider(connection.tenant_id)
            absent = auth.missing_permissions(tokens.graph_token())
        except Exception as exc:
            # Not evidence of a missing grant. A tenant that cannot issue a
            # token has a different problem, and the probes report that one.
            log.warning(
                "azure.grant_check_failed",
                connection_id=str(connection.id),
                error=str(exc),
            )
            return None

        if not absent:
            return None

        total = len(auth.REQUIRED_GRAPH_PERMISSIONS)
        if len(absent) == total:
            scale = f"any of the {total} directory permissions CloudGuard needs"
        else:
            scale = (
                f"{len(absent)} of the {total} directory permissions CloudGuard needs"
            )
        return (
            f"{GRANT_INCOMPLETE_PREFIX} {scale}: {', '.join(absent)}. Subscription "
            "scanning is unaffected; the identity checks cannot run until this is "
            "granted. Add these to CloudGuard's app registration as *application* "
            "permissions -- delegated ones do not appear in a service token -- then "
            "re-run admin consent for this tenant, because consent covers only what "
            "the registration declared at the moment it was granted."
        )

    async def ensure_principal(self, connection: CloudConnection) -> PrincipalLookup:
        """Look the principal up. Returns the reason on failure, never silence.

        Every way this can fail used to collapse into the same silent nothing,
        and the connection card showed a spinner that would never stop --
        identical whether Entra needed another few seconds or the app
        registration had no permissions to grant in the first place. Those need
        different actions from different people, so they have to read
        differently.
        """
        if connection.service_principal_object_id:
            return PrincipalLookup(
                ready=True, object_id=connection.service_principal_object_id
            )
        if (
            connection.consent_status != ConsentStatus.GRANTED
            or not connection.tenant_id
        ):
            return PrincipalLookup(ready=False)

        try:
            tokens = auth.TokenProvider(connection.tenant_id)
            async with GraphClient(tokens) as graph:
                principal = await graph.find_service_principal(settings.azure_client_id)
        except AzureApiError as exc:
            log.warning(
                "azure.service_principal_lookup_failed",
                connection_id=str(connection.id),
                status_code=exc.azure_status_code,
                error=str(exc),
            )
            if exc.azure_status_code in (401, 403):
                # The overwhelmingly likely cause, and not something the
                # customer can fix in their own tenant: consent can only grant
                # permissions the app registration actually declares, so a
                # registration with none grants nothing and every Graph call is
                # refused afterwards.
                return PrincipalLookup(
                    ready=False,
                    problem=(
                        "Microsoft Graph refused this lookup. CloudGuard's own app "
                        "registration is most likely missing its API permissions, so "
                        "admin consent had nothing to grant. This is a setup step on "
                        "CloudGuard's side (AZURE_INTEGRATION.md §2.1)."
                    ),
                )
            return PrincipalLookup(
                ready=False, problem=f"Microsoft Graph could not be read: {exc}"
            )
        except Exception as exc:
            log.warning(
                "azure.service_principal_lookup_failed",
                connection_id=str(connection.id),
                error=str(exc),
            )
            return PrincipalLookup(
                ready=False,
                problem=f"Could not reach Microsoft Graph for this tenant: {exc}",
            )

        if principal and principal.get("id"):
            return PrincipalLookup(ready=True, object_id=str(principal["id"]))

        return PrincipalLookup(
            ready=False,
            problem=(
                "Admin consent completed, but CloudGuard's service principal is not "
                "visible in this directory yet. Entra can take a minute to publish it."
            ),
        )

    # ------------------------------------------------------------- artefacts

    def artifact_ready(self, connection: CloudConnection) -> bool:
        return bool(
            connection.service_principal_object_id and self.scope_path(connection)
        )

    def artifact(self, connection: CloudConnection) -> DeploymentArtifact:
        """The ARM template for this connection.

        Rendered from the *current* role version, not the one recorded on this
        connection. Redeploying is how a customer gets the newer role, so a
        template stamped with their stale version deployed the current actions
        under the old role's name and definition id -- which then read back as
        still behind, and left "Redeploy the role" as a button that could be
        pressed forever without changing anything on this screen.
        """
        scope = self.scope_path(connection)
        if not connection.service_principal_object_id or not scope:
            raise ValidationFailed(
                "Admin consent has not completed yet, so there is no service "
                "principal to grant access to."
            )
        context = TemplateContext(
            principal_id=connection.service_principal_object_id,
            scope_path=scope,
            scope_type=connection.scope_type,
        )
        return DeploymentArtifact(body=arm_template(context))

    def launch_url(self, connection: CloudConnection, artifact_url: str) -> str:
        return (
            "https://portal.azure.com/#create/Microsoft.Template/uri/"
            f"{quote(artifact_url, safe='')}"
        )

    # ------------------------------------------------------------- verifying

    async def probe(self, connection: CloudConnection) -> ConnectionCheck:
        """Verify ARM access. Returns ok=False silently on failure."""
        tenant_id = connection.tenant_id or ""
        check = ConnectionCheck(ok=False, tenant_id=tenant_id)

        try:
            tokens = auth.TokenProvider(tenant_id)
        except Exception:
            return check

        try:
            async with ArmClient(tokens) as arm:
                subscriptions = await arm.list_subscriptions()
                if not subscriptions:
                    return check
                check.permissions_verified.append(
                    f"Azure Resource Manager: {len(subscriptions)} subscription(s) readable"
                )
                check.subscription_id = str(subscriptions[0].get("subscriptionId") or "")

                # Confirm we can actually read resources in at least one
                # subscription.
                try:
                    await arm.list_resources(check.subscription_id)
                    check.permissions_verified.append("Resource listing confirmed")
                except AzureApiError:
                    return check
        except Exception:
            return check

        check.ok = True
        check.detail = "Connection verified"
        return check

    async def discover(self, connection: CloudConnection) -> list[DiscoveredAccount]:
        try:
            tokens = auth.TokenProvider(connection.tenant_id or "")
            async with ArmClient(tokens) as arm:
                subscriptions = await arm.list_subscriptions()
        except Exception as exc:
            log.warning(
                "azure.auto_discover_failed",
                connection_id=str(connection.id),
                error=str(exc),
            )
            return []

        found: list[DiscoveredAccount] = []
        for subscription in subscriptions:
            subscription_id = str(subscription.get("subscriptionId") or "")
            if not subscription_id:
                continue
            found.append(
                DiscoveredAccount(
                    account_id=subscription_id,
                    display_name=str(
                        subscription.get("displayName") or subscription_id
                    ),
                )
            )
        return found

    # ---------------------------------------------------------- grant drift

    def required_grant_version(self, connection: CloudConnection) -> str | None:
        return ROLE_VERSION

    def grant_is_behind(self, connection: CloudConnection) -> bool:
        """Whether this connection's deployed role is older than the one
        CloudGuard now needs.

        ``CloudConnection.role_version`` has been stamped at creation since
        connections existed, and until this read it back the version was a
        label rather than a mechanism: bumping ``ROLE_VERSION`` to ship a check
        needing a new ARM action would leave every existing customer silently
        collecting UNKNOWN for it, with no prompt and no explanation.
        """
        return not role_is_current(connection.role_version)

    def degraded_categories(
        self, connection: CloudConnection
    ) -> dict[EvidenceCategory, str]:
        if not self.grant_is_behind(connection):
            return {}
        explanation = (
            f"CloudGuard's scanner role was updated to {ROLE_VERSION} and this "
            f"connection still has {connection.role_version}, which does not grant "
            "the permissions these checks need. Redeploy the role from the "
            "connection page to enable them."
        )
        return {
            category: explanation
            for category in categories_behind(connection.role_version)
        }

    async def detect_grant_version(self, connection: CloudConnection) -> str | None:
        """Which role version Azure says is actually assigned, read from Azure.

        ``role_version`` was stamped at creation and never written again, so the
        column recorded which role a customer was *offered* on the day they
        connected -- not which one they have. Redeploying therefore could not
        change the access panel: the customer deployed v5, the row still said
        v2, and both the "behind" line and the degraded-category banner stayed
        up for good with no way to clear them.

        Read from the assignments rather than from a version label, because the
        label is not evidence. Every assignment CloudGuard's principal holds at
        the connection's scope is resolved to its definition and the granted
        actions unioned, which also makes the answer right for the customer who
        assigned the built-in Reader instead of deploying the template at all.

        Returns None when the question could not be answered -- no token, a
        failed call, or a principal holding nothing this scanner recognises.
        """
        principal = connection.service_principal_object_id
        scope = self.scope_path(connection)
        if not principal or not scope or not connection.tenant_id:
            return None

        try:
            tokens = auth.TokenProvider(connection.tenant_id)
            async with ArmClient(tokens) as arm:
                assignments = await arm.list_role_assignments_at_scope(scope)
                definition_ids = {
                    str((a.get("properties") or {}).get("roleDefinitionId") or "")
                    for a in assignments
                    if str((a.get("properties") or {}).get("principalId") or "").lower()
                    == principal.lower()
                }
                definition_ids.discard("")
                if not definition_ids:
                    return None

                granted: set[str] = set()
                for definition_id in sorted(definition_ids):
                    definition = await arm.get_role_definition(definition_id)
                    permissions = (
                        definition.get("properties") or {}
                    ).get("permissions") or []
                    granted |= actions_granted_by(permissions)
        except Exception as exc:
            log.warning(
                "azure.role_version_probe_failed",
                connection_id=str(connection.id),
                error=str(exc),
            )
            return None

        return version_of_granted(granted)

    # ------------------------------------------------------------ teardown

    def revocation_steps(self, connection: CloudConnection) -> dict:
        """What the customer must run to take CloudGuard's access away.

        CloudGuard cannot do this itself, and that is a design decision rather
        than a gap. Deleting its own role assignment needs
        ``Microsoft.Authorization/roleAssignments/delete``, and removing its
        service principal needs Graph ``Application.ReadWrite.All`` -- write
        permissions on the two most sensitive surfaces in a tenant. A
        CloudGuard holding the first could strip access from the customer's own
        administrators; holding the second it could rewrite any application in
        the directory. Both are far more dangerous than the read access they
        would revoke, and asking every customer to grant them permanently to
        support a rare teardown is the wrong trade.

        So the commands are generated instead, filled in for this connection,
        and the revocation check proves afterwards whether they worked. Read
        access is the one thing CloudGuard can honestly report on, because
        losing it is observable.
        """
        principal = connection.service_principal_object_id
        scope = self.scope_path(connection)
        role = f"{ROLE_NAME} ({connection.role_version})"

        steps: list[dict[str, str]] = []
        if principal and scope:
            steps.append(
                {
                    "title": "Remove the scanner role assignment",
                    "detail": "Ends CloudGuard's ability to read Azure resources.",
                    "command": (
                        f"az role assignment delete --assignee {principal} "
                        f"--scope {scope}"
                    ),
                }
            )
            steps.append(
                {
                    "title": "Delete the custom role definition",
                    "detail": "Optional. Removes the now-unused role from the scope.",
                    "command": (
                        f'az role definition delete --name "{role}" --scope {scope}'
                    ),
                }
            )
        if principal:
            steps.append(
                {
                    "title": "Remove CloudGuard from your directory",
                    "detail": (
                        "Withdraws admin consent by deleting the enterprise "
                        "application, ending directory access as well."
                    ),
                    "command": f"az ad sp delete --id {principal}",
                }
            )

        return {
            "principal_id": principal,
            "scope_path": scope,
            "role_name": role,
            "tenant_id": connection.tenant_id,
            "steps": steps,
            # Stated plainly so nobody expects a button that cannot exist.
            "why_manual": (
                "CloudGuard holds read-only access and no write permission of any "
                "kind, so it cannot remove its own access. These run under your "
                "credentials, not CloudGuard's."
            ),
            "portal_url": (
                "https://portal.azure.com/#view/Microsoft_AAD_IAM/"
                "StartboardApplicationsMenuBlade/~/AppAppsPreview"
            ),
        }

    # ------------------------------------------------- CloudGuard's own side

    def self_registration(self) -> dict:
        """What CloudGuard's own Entra app registration must declare.

        The other half of the deployment -- the ARM template grants
        subscription access in the customer's tenant, while directory access
        comes from application permissions on CloudGuard's own registration,
        which no template a customer runs can touch.
        """
        manifest = auth.app_registration_manifest()
        return {
            "required_permissions": auth.REQUIRED_GRAPH_PERMISSIONS,
            "required_resource_access": manifest,
            # Shell-safe by construction. An angle-bracket placeholder reads as
            # a placeholder and parses as input redirection, so a copied command
            # fails with "No such file or directory" and names the placeholder
            # as the missing file -- an error that says nothing about what went
            # wrong.
            "lookup_command": (
                'APP_ID=$(az ad app list --display-name CloudGuard '
                '--query "[0].appId" -o tsv)'
            ),
            "apply_command": (
                'az ad app update --id "$APP_ID" '
                f"--required-resource-accesses '{json.dumps(manifest)}'"
            ),
            "verify_command": (
                'az ad app show --id "$APP_ID" '
                '--query "requiredResourceAccess[].resourceAccess[].id" -o tsv'
            ),
            "grant_command": (
                "# Then, in each customer tenant, a Global Administrator "
                "re-runs the consent link from this page."
            ),
            "note": (
                "Consent grants what the registration declares at the moment it is "
                "granted. Adding a permission afterwards does not extend an existing "
                "grant -- every already-connected tenant must consent again."
            ),
        }
