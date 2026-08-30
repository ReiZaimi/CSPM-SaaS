from datetime import datetime
from typing import ClassVar

from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import (
    CloudAccountStatus,
    ConnectionScope,
    ConsentStatus,
    Provider,
)
from app.models.base import Base, StrEnumType, TenantOwned, Timestamps, UUIDPrimaryKey


class CloudConnection(Base, UUIDPrimaryKey, TenantOwned, Timestamps):
    """One grant of read access to a customer's cloud, at a chosen scope.

    This is the thing a customer actually connects. Subscriptions are
    *discovered* beneath it (``cloud_accounts``), not registered one at a time --
    so a subscription created next week is scanned rather than silently missed.
    A CSPM that omits an environment nobody told it about reports a clean
    posture it never looked for.

    Two fields are deliberately not client-supplied:

    ``tenant_id`` is NULL until Entra's consent callback reports it. Nobody
    types it. That is not a convenience -- it is the whole tenant-binding
    guarantee. When the tenant came from a request body, any user could name an
    organization someone else had already consented for and validate against
    their environment, because CloudGuard's service principal was already
    present there. Now the tenant is whatever the admin who clicked the signed
    consent link actually consented in.

    ``service_principal_object_id`` is read back from Graph after consent. It is
    what the customer's RBAC assignment has to point at, so knowing it is what
    lets CloudGuard hand them an artifact with nothing left to fill in.
    """

    __tablename__ = "cloud_connections"
    __table_args__ = (
        # Scoped per organization, not globally: two organizations legitimately
        # holding separate connections to the same tenant is a real case
        # (a managed service provider and its client). What stops one of them
        # reading the other's environment is consent binding, not this
        # constraint.
        UniqueConstraint("organization_id", "provider", "tenant_id", "scope_id"),
    )

    provider: Mapped[Provider] = mapped_column(
        StrEnumType(Provider, 16), nullable=False, default=Provider.AZURE
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)

    scope_type: Mapped[ConnectionScope] = mapped_column(
        StrEnumType(ConnectionScope, 24), nullable=False, default=ConnectionScope.TENANT_ROOT
    )
    # The management group or subscription id. NULL for TENANT_ROOT, whose scope
    # is the tenant's root management group -- an id that equals the tenant id
    # and so is not known until consent completes.
    scope_id: Mapped[str | None] = mapped_column(String(200))

    # Which generation of the custom role the artifact was built from, so the UI
    # can tell a customer their deployed role predates a rule that needs more.
    role_version: Mapped[str] = mapped_column(String(16), nullable=False, default="v1")

    tenant_id: Mapped[str | None] = mapped_column(String(64), index=True)
    service_principal_object_id: Mapped[str | None] = mapped_column(String(64))

    consent_status: Mapped[ConsentStatus] = mapped_column(
        StrEnumType(ConsentStatus, 16), nullable=False, default=ConsentStatus.PENDING
    )
    consented_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Proof the RBAC grant works, from a live call -- never from the customer
    # telling us they did it.
    rbac_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    status: Mapped[CloudAccountStatus] = mapped_column(
        StrEnumType(CloudAccountStatus, 16), nullable=False, default=CloudAccountStatus.PENDING
    )
    status_detail: Mapped[str | None] = mapped_column(Text)
    last_discovery_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # How often this environment should be re-read, in hours. NULL means manual
    # only, and it is the default: turning a customer's cloud into a recurring
    # API cost without being asked would be a surprise on their Azure bill as
    # much as on ours.
    #
    # An interval rather than a time of day. "Every night at 03:00" needs a
    # timezone, a window, and an answer for what happens when a scan overruns
    # its slot; an interval says the only thing a scanner can actually promise,
    # which is that the environment is read at least this often.
    scan_interval_hours: Mapped[int | None] = mapped_column(Integer)

    # What the UI offers, and what the API accepts. Bounded at both ends for
    # different reasons: below an hour a scan would still be running when the
    # next was due, and beyond a month a "continuous" posture is a claim
    # CloudGuard cannot support.
    MIN_INTERVAL_HOURS: ClassVar[int] = 1
    MAX_INTERVAL_HOURS: ClassVar[int] = 24 * 30

    @property
    def is_scheduled(self) -> bool:
        return self.scan_interval_hours is not None

    @property
    def is_verified(self) -> bool:
        """Both grants proven. Subscriptions may still be undiscovered."""
        return (
            self.consent_status == ConsentStatus.GRANTED
            and self.tenant_id is not None
            and self.rbac_verified_at is not None
        )

    @property
    def scope_path(self) -> str | None:
        """The ARM scope an assignment is created at.

        A tenant's root management group is named with the tenant id, so
        TENANT_ROOT resolves only once consent has told us what that is.
        """
        if self.scope_type == ConnectionScope.SUBSCRIPTION:
            return f"/subscriptions/{self.scope_id}" if self.scope_id else None
        if self.scope_type == ConnectionScope.MANAGEMENT_GROUP:
            group = self.scope_id
        else:
            group = self.tenant_id
        return f"/providers/Microsoft.Management/managementGroups/{group}" if group else None
