"""Assuming the customer's scanner role, and the external id that guards it.

CloudGuard authenticates as itself and then assumes a role the customer created
in their own account. Nothing about the customer is stored as a credential --
the same property the Azure design has and states in ``cloud_account.py``: the
role ARN is a name, and the external id is a name the customer's own trust
policy requires. Neither grants anything on its own.

**The external id is not optional, and this module is where that is enforced.**
Without one, anybody who learns CloudGuard's AWS account id can create a role
trusting it and have CloudGuard scan an environment on their behalf -- the
confused deputy, and the standard way third-party integrations get this wrong.
It is generated here, server-side, per connection, and never accepted from a
request body (``MULTI_CLOUD.md`` §5).

.. warning::

   Nothing in this file has been run against a live AWS account. The call
   shapes come from the published API reference; the checklist in
   ``docs/AWS_INTEGRATION.md`` §1 is what turns them from plausible into
   verified.
"""

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from aiobotocore.session import AioSession, get_session

from app.core.config import settings
from app.core.errors import NotConfigured
from app.core.logging import get_logger

log = get_logger(__name__)

# How long a set of assumed credentials is asked for. An hour is the default
# maximum for a role assumed with a session policy, and a scan of a large
# organization can outlast it -- which is why credentials are refreshed on
# demand below rather than fetched once at the start of a run.
SESSION_DURATION_SECONDS = 3600

# How long before expiry a session is treated as spent. A call that starts
# inside the window and finishes outside it fails with an expired token, and a
# scan losing a listing to arithmetic rather than to permissions is the kind of
# gap that reads as the customer's problem.
REFRESH_MARGIN = timedelta(minutes=5)

# What the assumed session is named in the customer's CloudTrail. Deliberately
# legible: a customer auditing their own logs should be able to tell at a glance
# which reads were CloudGuard's.
SESSION_NAME = "cloudguard-scanner"

# Where STS is called. The global endpoint is the documented default; a regional
# one is faster and, more to the point, keeps working when the global endpoint
# is degraded.
STS_REGION = "us-east-1"


def new_external_id() -> str:
    """A fresh external id for one connection.

    Generated here rather than accepted from the client, which is the whole
    security property: an id the customer chooses is an id an attacker can
    choose. Long enough not to be guessed, and URL-safe so it survives being
    passed through a CloudFormation console link.
    """
    return f"cg-{secrets.token_urlsafe(24)}"


def cloudguard_principal_arn() -> str:
    """The identity a customer's trust policy names.

    Read from configuration rather than derived, because the template a customer
    deploys has to name it exactly and a wrong value fails at the moment they
    click deploy rather than at the moment we call.
    """
    if not settings.aws_principal_arn:
        raise NotConfigured(
            "AWS_PRINCIPAL_ARN is not set, so CloudGuard cannot tell a customer "
            "which principal their scanner role should trust "
            "(docs/AWS_INTEGRATION.md §2)."
        )
    return settings.aws_principal_arn


@dataclass
class Credentials:
    """One set of assumed credentials, and when they stop being usable."""

    access_key_id: str
    secret_access_key: str
    session_token: str
    expires_at: datetime

    @property
    def spent(self) -> bool:
        return datetime.now(UTC) >= self.expires_at - REFRESH_MARGIN

    def as_kwargs(self) -> dict[str, str]:
        """In the form every ``create_client`` call wants them."""
        return {
            "aws_access_key_id": self.access_key_id,
            "aws_secret_access_key": self.secret_access_key,
            "aws_session_token": self.session_token,
        }


class RoleAssumer:
    """Holds one connection's assumed session, and renews it when it is spent.

    One per collection run. The credentials are shared across every service
    client the run opens, because they are a property of the *connection* and
    not of whichever listing happens to be asking -- and because assuming the
    role once per listing would put a few hundred ``sts:AssumeRole`` calls in
    front of every scan.
    """

    def __init__(
        self,
        role_arn: str,
        external_id: str,
        *,
        session: AioSession | None = None,
    ) -> None:
        if not role_arn:
            raise NotConfigured("This connection has no scanner role to assume.")
        if not external_id:
            # Refused rather than defaulted to empty. An assume-role call with
            # no external id succeeds against a role whose trust policy does not
            # require one, which is exactly the misconfiguration this guard
            # exists to keep CloudGuard from participating in.
            raise NotConfigured(
                "This connection has no external id. CloudGuard will not assume "
                "a role without one."
            )
        self.role_arn = role_arn
        self.external_id = external_id
        self._session = session or get_session()
        self._credentials: Credentials | None = None

    async def credentials(self) -> Credentials:
        """The current session, assumed or renewed as needed."""
        if self._credentials is not None and not self._credentials.spent:
            return self._credentials
        self._credentials = await self._assume()
        return self._credentials

    async def _assume(self) -> Credentials:
        if not settings.aws_access_key_id or not settings.aws_secret_access_key:
            raise NotConfigured(
                "CloudGuard's own AWS credentials are not configured "
                "(AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY). Nothing can be "
                "assumed without them (docs/AWS_INTEGRATION.md §2)."
            )

        async with self._session.create_client(
            "sts",
            region_name=STS_REGION,
            aws_access_key_id=settings.aws_access_key_id,
            aws_secret_access_key=settings.aws_secret_access_key,
        ) as sts:
            response: dict[str, Any] = await sts.assume_role(
                RoleArn=self.role_arn,
                RoleSessionName=SESSION_NAME,
                ExternalId=self.external_id,
                DurationSeconds=SESSION_DURATION_SECONDS,
            )

        payload = response["Credentials"]
        expires = payload["Expiration"]
        return Credentials(
            access_key_id=payload["AccessKeyId"],
            secret_access_key=payload["SecretAccessKey"],
            session_token=payload["SessionToken"],
            expires_at=expires if expires.tzinfo else expires.replace(tzinfo=UTC),
        )
