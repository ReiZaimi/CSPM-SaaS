"""Calling AWS: one client per service and region, over assumed credentials.

Azure is reached with plain REST because storing the provider's own JSON
verbatim was the point, and its ARM APIs are one uniform paginated shape.  AWS
is not one shape: EC2 and IAM speak a query protocol that answers XML, S3 speaks
REST-XML, and the rest speak JSON -- three parsers, three pagination idioms and
SigV4 underneath all of them.  ``aiobotocore`` handles exactly that layer and
nothing above it: what it returns is the provider's own response, parsed, and
that is what the snapshot stores (``DECISIONS.md`` §72).

Two properties from the Azure client are kept because they are not the SDK's
job and the scan depends on them:

* **A listing that stopped early is not a short listing.**  Paginators are
  bounded by :data:`MAX_PAGES` and stopping there records the key as truncated,
  which becomes ``PARTIAL`` and costs the rules their verdict rather than
  handing them an unknown fraction of an estate as though it were all of it.
* **A refusal is attributable.**  ``AccessDenied`` for one listing must cost one
  key, so errors carry the operation that raised them.

.. warning::

   No call in this module has been made against a live AWS account.  Operation
   names and response keys come from the published API reference; the checklist
   in ``docs/AWS_INTEGRATION.md`` §1 is what makes them verified.
"""

from types import TracebackType
from typing import Any, Self

from aiobotocore.session import AioSession, get_session
from botocore.config import Config
from botocore.exceptions import ClientError

from app.connectors.aws.auth import RoleAssumer
from app.core.errors import CloudConnectionError
from app.core.logging import get_logger

log = get_logger(__name__)

# How many pages of one listing to read before calling it truncated. High enough
# that no ordinary account reaches it, low enough that a pathological one cannot
# hold a scan open indefinitely -- the same trade the Azure client makes, and
# the same consequence when it is hit: PARTIAL, not a shorter answer.
MAX_PAGES = 200

# What botocore does about throttling before we hear about it. Adaptive mode
# backs off on the client side, which is what AWS's own guidance asks for and
# what keeps a regional fan-out from turning one throttled call into a wave of
# them.
RETRY_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=60,
    user_agent_extra="cloudguard-cspm",
)

# Errors that mean "this account has not switched the service on", which is not
# a permission problem and not a failure. A region with no GuardDuty detector
# has an answer -- there is no detector -- and reporting it as a failed read
# would degrade a rule that has all the evidence it needs.
NOT_ENABLED_CODES = frozenset(
    {
        "OptInRequired",
        "SubscriptionRequiredException",
        "InvalidAccessException",
        "ResourceNotFoundException",
        "NoSuchEntity",
        "NoSuchPublicAccessBlockConfiguration",
        "NoSuchBucketPolicy",
        "ServerSideEncryptionConfigurationNotFoundError",
    }
)

# Errors that mean the grant does not cover this call. Named so the message a
# customer sees can say which permission is missing rather than "an error".
DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "AuthorizationError",
    }
)


class AwsApiError(CloudConnectionError):
    """An AWS call that failed, carrying the code AWS gave it."""

    def __init__(self, message: str, code: str = "", operation: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.operation = operation

    @property
    def denied(self) -> bool:
        return self.code in DENIED_CODES

    @property
    def not_enabled(self) -> bool:
        """The service is off in this account or region, which is an answer."""
        return self.code in NOT_ENABLED_CODES and not self.denied


class AwsClient:
    """One AWS service in one region, over one connection's assumed session.

    Constructed per task, like the Azure clients, so :attr:`truncated` belongs
    to the listing that truncated. A single client shared across a wave would
    record the fact and lose which task it belonged to, and the resulting
    PARTIAL would be attributed to whichever task happened to be awaiting.
    """

    def __init__(
        self,
        assumer: RoleAssumer,
        service: str,
        region: str | None = None,
        *,
        session: AioSession | None = None,
    ) -> None:
        self.assumer = assumer
        self.service = service
        self.region = region
        self._session = session or get_session()
        self._client: Any = None
        self._context: Any = None
        self.truncated: set[str] = set()

    async def __aenter__(self) -> Self:
        credentials = await self.assumer.credentials()
        self._context = self._session.create_client(
            self.service,
            region_name=self.region,
            config=RETRY_CONFIG,
            **credentials.as_kwargs(),
        )
        self._client = await self._context.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._context is not None:
            await self._context.__aexit__(exc_type, exc, tb)
            self._context = None
            self._client = None

    # ------------------------------------------------------------------ calls

    def can_paginate(self, operation: str) -> bool:
        """Whether botocore has a paginator for this operation.

        Several reads that look like listings are not paginated at all --
        ``DescribeTrails`` and ``DescribeConfigurationRecorders`` answer in one
        response -- and asking for a paginator that does not exist raises. This
        is what lets one task body serve both without a table of exceptions.
        """
        return bool(self._client.can_paginate(operation))

    async def call(self, operation: str, **kwargs: Any) -> dict[str, Any]:
        """One API call, with AWS's error turned into one of ours.

        The response is returned as AWS shaped it, minus the response metadata
        -- which is a fact about the HTTP round trip rather than about the
        environment, changes on every call, and would make two identical
        readings hash differently and defeat the evidence store's deduplication.
        """
        try:
            method = getattr(self._client, operation)
            response: dict[str, Any] = await method(**kwargs)
        except ClientError as error:
            code = str(error.response.get("Error", {}).get("Code", ""))
            message = str(error.response.get("Error", {}).get("Message", error))
            raise AwsApiError(message, code=code, operation=operation) from error
        response.pop("ResponseMetadata", None)
        return response

    async def paginate(
        self, operation: str, key: str, **kwargs: Any
    ) -> list[dict[str, Any]]:
        """Every page of one listing, or as many as :data:`MAX_PAGES` allows.

        Returns the items AWS returned, in AWS's own shape. Stopping at the cap
        records the operation in :attr:`truncated`, which the task turns into
        PARTIAL -- because a list missing an unknown number of entries cannot
        support "none of them are public".
        """
        items: list[dict[str, Any]] = []
        pages = 0
        try:
            paginator = self._client.get_paginator(operation)
            async for page in paginator.paginate(**kwargs):
                items.extend(page.get(key) or [])
                pages += 1
                if pages >= MAX_PAGES:
                    self.truncated.add(operation)
                    log.warning(
                        "aws.pagination_truncated",
                        service=self.service,
                        region=self.region,
                        operation=operation,
                        pages=pages,
                        items=len(items),
                    )
                    break
        except ClientError as error:
            code = str(error.response.get("Error", {}).get("Code", ""))
            message = str(error.response.get("Error", {}).get("Message", error))
            raise AwsApiError(message, code=code, operation=operation) from error
        return items

    async def optional(self, operation: str, **kwargs: Any) -> dict[str, Any] | None:
        """A call whose absence is an answer rather than a failure.

        A bucket with no encryption configuration answers
        ``ServerSideEncryptionConfigurationNotFoundError``, and that *is* the
        finding -- treating it as a failed read would degrade the rule that was
        about to raise it. A denial is still a denial and still raises.
        """
        try:
            return await self.call(operation, **kwargs)
        except AwsApiError as error:
            if error.not_enabled:
                return None
            raise
