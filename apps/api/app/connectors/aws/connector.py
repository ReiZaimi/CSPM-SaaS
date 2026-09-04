"""The AWS connector: validate, collect, normalize.

Behind the same three-verb contract Azure sits behind, which is what
``MULTI_CLOUD.md`` §1 predicted would generalize and, as far as this connector
is concerned, did. Nothing above ``CloudConnector`` changed to accommodate AWS
except the region dimension, and that landed in the collection executor rather
than here (``DECISIONS.md`` §69).

.. warning::

   No call in this package has been made against a live AWS account. The
   checklist in ``docs/AWS_INTEGRATION.md`` §1 is what turns it from plausible
   into verified, and the provider is not offered in the UI until it has been
   run.
"""

from collections.abc import Awaitable, Callable

from aiobotocore.session import AioSession

from app.connectors.aws.client import AwsApiError, AwsClient
from app.connectors.aws.collector import AwsCollector
from app.connectors.aws.evidence import BASELINE_EVIDENCE, AwsEvidence, keys_in
from app.connectors.aws.iam import (
    INLINE_READ_ACTIONS,
    MANAGED_POLICY_ARNS,
    POLICY_VERSION,
    ROLE_NAME,
)
from app.connectors.aws.normalizer import AwsNormalizer
from app.connectors.base import (
    CloudConnector,
    ConnectionCheck,
    NormalizedState,
    RawSnapshot,
)
from app.connectors.evidence import EvidenceCategory, EvidenceKey
from app.connectors.planning import CollectionPlan
from app.core.enums import Provider
from app.core.logging import get_logger

log = get_logger(__name__)

# One read per category, made after the role is assumed. Enough to name which
# part of the grant is missing rather than reporting "the connection failed",
# and few enough that validating a connection is not itself a scan.
#
# The deeper listings are absent on purpose: they already degrade to UNKNOWN
# individually, so they cost a category rather than a connection.
PROBES: tuple[tuple[str, str, str, str], ...] = (
    ("ec2", "describe_regions", "the enabled regions", "ec2:DescribeRegions"),
    ("iam", "list_users", "IAM users", "iam:ListUsers"),
    ("s3", "list_buckets", "S3 buckets", "s3:ListAllMyBuckets"),
)


class AwsConnector(CloudConnector):
    provider = Provider.AWS

    def __init__(
        self,
        tenant_id: str,
        subscription_id: str | None = None,
        provider_ref: dict | None = None,
        session: AioSession | None = None,
    ) -> None:
        # Named ``tenant_id`` and ``subscription_id`` because the columns are,
        # and the columns are because renaming them would make every capture
        # already stored unreplayable (``DECISIONS.md`` §70). Here they mean the
        # organization and the account.
        self.tenant_id = tenant_id
        self.subscription_id = subscription_id
        # The role to assume in *this* account, and the external id its trust
        # policy requires. Per account rather than per connection, because an
        # organization-wide connection assumes one role in each member account
        # -- the same stack deployed everywhere, so the ARNs differ only by
        # account id, which is why discovery can write them without asking.
        reference = provider_ref or {}
        self.role_arn = str(reference.get("role_arn") or "")
        self.external_id = str(reference.get("external_id") or "")
        self._session = session
        self._normalizer = AwsNormalizer()

    def _collector(self) -> AwsCollector:
        return AwsCollector(
            self.tenant_id,
            self.subscription_id,
            role_arn=self.role_arn,
            external_id=self.external_id,
            session=self._session,
        )

    async def validate_connection(self) -> ConnectionCheck:
        """Prove the grant by using it, one read per category.

        AWS has one grant where Azure has two, so there is one way this fails
        rather than two independent ones -- but "the role could be assumed" is
        still not the same claim as "the role can read what a scan reads". A
        role deployed from an older stack assumes perfectly and refuses half the
        listings, which is a note rather than a failure: a connection that can
        still read eleven of its twelve categories is not a broken connection.
        """
        check = ConnectionCheck(ok=False, tenant_id=self.tenant_id)
        collector = self._collector()

        try:
            identity_client = AwsClient(
                collector.assumer, "sts", "us-east-1", session=self._session
            )
            async with identity_client as sts:
                identity = await sts.call("get_caller_identity")
        except Exception as exc:
            check.problems.append(
                f"CloudGuard could not assume the scanner role: {exc}"
            )
            check.detail = "The scanner role could not be assumed"
            return check

        check.subscription_id = str(identity.get("Account") or "") or None
        check.permissions_verified.append(
            f"Assumed {identity.get('Arn') or ROLE_NAME}"
        )

        for service, operation, described, action in PROBES:
            try:
                client = AwsClient(
                    collector.assumer, service, "us-east-1", session=self._session
                )
                async with client as probe:
                    await probe.call(operation)
            except AwsApiError as error:
                message = f"Could not read {described} ({action}): {error}"
                # A denial here costs a category, not the connection. The role
                # was assumed; something in the policy is short, and the scan
                # will report UNKNOWN for exactly the checks that needed it.
                (check.problems if not error.denied else check.notes).append(message)
            except Exception as exc:
                check.problems.append(f"Could not read {described}: {exc}")

        check.ok = not check.problems
        check.detail = (
            "Connection verified"
            if check.ok
            else "The scanner role is deployed but cannot read this account"
        )
        return check

    @staticmethod
    def required_permissions() -> dict:
        """What AWS is being asked for, in the form onboarding shows it.

        One grant, which is the shape difference a customer notices first: no
        consent screen, no directory permissions, one stack. The external id is
        deliberately absent -- it belongs to a connection rather than to the
        provider, and publishing it beside the permission list would put a
        per-customer secret on a screen that describes the product.
        """
        return {
            "grants": [
                {
                    "name": "Cross-account scanner role",
                    "detail": (
                        "A role in your account that CloudGuard assumes to read "
                        "your security configuration. It requires an external id "
                        "that CloudGuard generates and that only your trust "
                        "policy and CloudGuard know."
                    ),
                    "managed_policies": list(MANAGED_POLICY_ARNS),
                    "inline_actions": list(INLINE_READ_ACTIONS),
                }
            ],
            "policy_version": POLICY_VERSION,
            "writes": [],
            "note": (
                "Every action is a read of configuration. Nothing here can read "
                "the contents of a bucket, a database or a secret."
            ),
        }

    @staticmethod
    def evidence_keys_in(category: EvidenceCategory) -> frozenset[EvidenceKey]:
        return frozenset(keys_in(category))

    @staticmethod
    def baseline_evidence() -> frozenset[EvidenceKey]:
        return frozenset(BASELINE_EVIDENCE)

    async def collect(
        self,
        on_progress: Callable[[int, int], Awaitable[None]] | None = None,
        plan: CollectionPlan | None = None,
    ) -> RawSnapshot:
        return await self._collector().collect(on_progress, plan)

    async def collect_directory(
        self,
        on_progress: Callable[[int, int], Awaitable[None]] | None = None,
        plan: CollectionPlan | None = None,
    ) -> RawSnapshot:
        """The organization's account list, read once per scan.

        The AWS half of the split every cloud has. Smaller than Azure's, because
        AWS keeps identity in each account rather than above them -- so IAM is
        collected per account and only the account list belongs up here.
        """
        return await self._collector().collect_directory(on_progress, plan)

    def normalize(self, snapshot: RawSnapshot) -> NormalizedState:
        return self._normalizer.normalize(snapshot)


# Named for the import guard's benefit: a key added to the enum with no task and
# no rule would otherwise be invisible until a scan collected nothing for it.
_ALL_KEYS = frozenset(AwsEvidence)
