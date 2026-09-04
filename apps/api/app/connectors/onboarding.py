"""How a customer grants CloudGuard read access, without naming a cloud.

Scanning was provider-neutral from the start -- ``CloudConnector`` in,
``CloudResource`` out, and nothing above the seam knows what ARM is. Onboarding
never was. ``services/cloud_connections.py`` imported Azure's token provider,
its ARM and Graph clients and its role definitions at six call sites, and
``MULTI_CLOUD.md`` §2 called it the Azure-coupled half of the application.

That was the right call while Azure was the only provider: an abstraction
guessed from one example is usually wrong in the places that matter, and §8
step 5 scheduled the split for when a second thing existed to split it *for*.
This is that split, written against two providers rather than one.

What is neutral is the **shape of the flow**, and it is the same shape in every
cloud:

1. the customer names a scope and CloudGuard creates a connection;
2. CloudGuard hands them something to deploy, generated from its declared
   permission set rather than hand-maintained;
3. CloudGuard proves the grant by *using* it, never by being told it exists;
4. the accounts beneath the scope are discovered rather than typed in.

What differs is the number of grants and what deploys them. Azure has two that
fail independently -- Entra admin consent for Graph, and an ARM role -- and
needs a service principal resolved between them. AWS has one cross-account role
and an external id, and nothing to consent to. So the steps a provider does not
have return "nothing to do" rather than being special-cased by the caller: a
connection with no consent step must not sit forever waiting for one.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.connectors.base import ConnectionCheck
from app.connectors.evidence import EvidenceCategory
from app.core.enums import ConnectionScope, Provider
from app.models.cloud_connection import CloudConnection


@dataclass(frozen=True)
class DiscoveredAccount:
    """One scannable unit found beneath a connection's scope.

    An Azure subscription, an AWS account, later a GCP project. The neutral
    half writes these into ``cloud_accounts``; the provider half decides what
    counts as one and what it is called.
    """

    account_id: str
    display_name: str
    # Anything about this account only its own cloud has a word for, stored on
    # the row it belongs to. Empty for Azure.
    provider_ref: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PrincipalLookup:
    """Whether the identity a grant points at is known yet.

    Azure creates CloudGuard's service principal during consent and does not
    always publish it before the callback fires, so the artifact step -- which
    needs that object id -- can arrive before the answer exists. AWS has no
    such step: the customer's trust policy names CloudGuard's own account, and
    there is nothing to look up in their environment.

    ``ready`` is therefore the question the caller actually asks: may setup
    proceed? The default says yes, so a provider with no principal to resolve
    gets the right answer by not overriding this.
    """

    ready: bool = True
    object_id: str | None = None
    problem: str | None = None


@dataclass(frozen=True)
class DeploymentArtifact:
    """The thing a customer deploys, rendered for one connection.

    An ARM template on Azure, a CloudFormation template on AWS. Generated from
    the provider's declared permission set rather than hand-maintained, which
    is the single most valuable pattern the Azure connector established
    (``MULTI_CLOUD.md`` §1): the permissions, the collector calls that need
    them and the customer's deployable artefact cannot drift apart, because a
    test checks all three against one declaration.
    """

    body: str
    media_type: str = "application/json"
    # What the provider's console saves it as. Named by the provider rather than
    # by the route, because the route serves both and "cloudguard-scanner.json"
    # is an ARM template's name.
    filename: str = "cloudguard-scanner.json"


class ProviderOnboarding(ABC):
    """One cloud's answer to "how does a customer grant us access".

    Stateless and constructed per call -- every method takes the connection it
    is about. The alternative would be a constructor taking half a connection,
    which is exactly the object being passed anyway.
    """

    provider: Provider

    #: The widest scope this cloud offers, and the only one that needs no id --
    #: an Azure tenant root, an AWS organization. Everything narrower names the
    #: management group, organizational unit or account it covers.
    root_scope: ConnectionScope

    #: What to tell the customer before anything is granted.
    initial_status_detail: str = "Grant access to continue."
    #: What to tell them once the first grant lands and the artefact is next.
    ready_to_deploy_detail: str = "Deploy the scanner role next."
    #: Prefix marking a status detail as "the grant is incomplete", so a later
    #: step can tell it apart from a healthy message without a schema change.
    #: Empty for a provider that cannot be partially granted.
    grant_incomplete_prefix: str = ""

    #: Whether this cloud has a consent step separate from the deployment.
    #:
    #: Azure does: admin consent for Graph and an ARM role, granted by different
    #: people at different moments and failing independently. AWS does not --
    #: the stack *is* the grant, and one successful assume-role proves the whole
    #: of it. A connection with no consent step must not sit forever waiting for
    #: one, which is what this flag exists to prevent.
    has_separate_consent: bool = True

    # ---------------------------------------------------------------- grants

    @abstractmethod
    def grant_version(self) -> str:
        """Which generation of the permission set an artefact would grant now.

        Stamped on a connection at creation and read back from the provider
        afterwards, so a customer running a role that predates a new rule can
        be offered a redeploy rather than silently collecting UNKNOWN.
        """

    @abstractmethod
    def scope_path(self, connection: CloudConnection) -> str | None:
        """The provider's own name for the scope a grant is written at.

        ``None`` when it is not knowable yet, which on Azure is any tenant-root
        connection before consent reports the tenant.
        """

    def start_url(self, connection: CloudConnection) -> tuple[str | None, str | None]:
        """Where the customer goes to make the first grant, or why they cannot.

        A signed consent link on Azure. Nothing on AWS, whose only grant is the
        deployment itself -- so ``(None, None)`` is a complete answer and not a
        failure to produce one.
        """
        return None, None

    async def grant_problem(self, connection: CloudConnection) -> str | None:
        """What the grant failed to cover, named, or ``None`` when it covered
        everything.

        Only meaningful where a grant can succeed while granting less than was
        asked for, which is Entra admin consent resolving ``/.default`` against
        whatever the app registration happens to declare.
        """
        return None

    async def ensure_principal(self, connection: CloudConnection) -> PrincipalLookup:
        """Resolve the identity the customer's grant has to point at."""
        return PrincipalLookup()

    # ------------------------------------------------------------- artefacts

    def requires_scope_id(self, scope_type: ConnectionScope) -> bool:
        """Whether this scope has to name something the customer types.

        The widest scope usually does not: an Azure tenant root is named by the
        tenant, which consent reports. AWS has no equivalent -- there is nothing
        to assume a role *in* until an account is named -- so it requires one at
        every scope, which is why this is a question rather than a comparison.
        """
        return scope_type != self.root_scope

    def initial_provider_ref(self, connection: CloudConnection) -> dict[str, Any]:
        """What this cloud needs recorded before anything is deployed.

        AWS generates its external id here, which is the one moment it can be
        generated safely: server-side, per connection, before any artefact names
        it. Empty for Azure, which keeps nothing per customer.
        """
        return {}

    @abstractmethod
    def artifact_ready(self, connection: CloudConnection) -> bool:
        """Whether everything the artefact needs filling in is known yet."""

    @abstractmethod
    def artifact(self, connection: CloudConnection) -> DeploymentArtifact:
        """Render the deployable artefact. Raises when it is not ready."""

    @abstractmethod
    def launch_url(self, connection: CloudConnection, artifact_url: str) -> str:
        """The console link that opens the artefact ready to deploy.

        Deploy to Azure, or CloudFormation's Launch Stack. Takes the URL the
        provider's console will fetch, because building that one needs a signed
        token and the API's own public origin -- neither of which is a
        provider's business.
        """

    # ------------------------------------------------------------- verifying

    @abstractmethod
    async def probe(self, connection: CloudConnection) -> ConnectionCheck:
        """Prove the grant by using it. Quiet on failure.

        Called on a loop while a customer is plausibly still deploying, so a
        refusal here is the normal state of a connection mid-setup rather than
        an error to report.
        """

    @abstractmethod
    async def discover(self, connection: CloudConnection) -> list[DiscoveredAccount]:
        """Every scannable unit beneath this connection's scope.

        Discovered rather than registered one at a time: an account created
        next week must be scanned rather than silently missed, because a CSPM
        that omits an environment nobody told it about reports a clean posture
        it never looked for.
        """

    # -------------------------------------------------------- grant drift

    def required_grant_version(self, connection: CloudConnection) -> str | None:
        """The version this connection should be on, or ``None`` if it has no
        such notion."""
        return self.grant_version()

    def grant_is_behind(self, connection: CloudConnection) -> bool:
        return connection.role_version != self.grant_version()

    def degraded_categories(
        self, connection: CloudConnection
    ) -> dict[EvidenceCategory, str]:
        """Categories this connection's deployed grant cannot fully serve.

        Category -> the sentence to show the customer. Empty when the grant is
        current, so the scanner can ask without knowing which cloud it is
        looking at.
        """
        return {}

    async def detect_grant_version(self, connection: CloudConnection) -> str | None:
        """What the provider says is actually deployed, read from the provider.

        ``None`` means the question could not be answered -- which is not the
        same as "behind", and the caller leaves the recorded version alone
        rather than replacing a fact with a probe that did not land.
        """
        return None

    # ------------------------------------------------------------ teardown

    @abstractmethod
    def revocation_steps(self, connection: CloudConnection) -> dict:
        """What the customer runs to take CloudGuard's access away.

        Generated rather than performed, in every cloud. Revoking CloudGuard's
        own access would need write permissions on the two most sensitive
        surfaces a tenant has, which are far more dangerous than the read
        access they would withdraw.
        """

    # ------------------------------------------------- CloudGuard's own side

    def self_registration(self) -> dict | None:
        """What CloudGuard's *own* identity in this cloud must declare.

        The half of the deployment no customer artefact can touch: Azure's
        application permissions live on CloudGuard's app registration, not on
        anything a template creates in the customer's tenant. ``None`` for a
        provider with no such half.
        """
        return None
