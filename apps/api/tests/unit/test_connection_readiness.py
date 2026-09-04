"""What "Ready to scan" is allowed to mean.

A connection card showed three green ticks and "Ready to scan: Yes" over a
connection with no subscriptions beneath it, on a tenant where no scan was
possible. The flag it read was ``is_verified``, whose own docstring says
"Subscriptions may still be undiscovered" -- accurate about the grants, and not
an answer to the question the card was asking.

Same shape as the Graph probe that reported Directory.Read.All verified after
reading one unrelated endpoint: a green light asserting more than was checked.
"""

import uuid
from datetime import UTC, datetime

import pytest

from app.api.routes import cloud_connections as routes
from app.core.enums import (
    CloudAccountStatus,
    ConnectionScope,
    ConsentStatus,
    Provider,
)
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection


@pytest.fixture(autouse=True)
def _no_azure_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """The serializer builds consent and template URLs, neither under test."""
    monkeypatch.setattr(routes.service, "deployment_url", lambda c: None)
    monkeypatch.setattr(routes.service, "grant_start_url", lambda c: (None, None))
    monkeypatch.setattr(routes.service, "deploy_stalled", lambda c: False)
    monkeypatch.setattr(routes.service, "grant_upgrade_available", lambda c: False)


def verified_connection() -> CloudConnection:
    connection = CloudConnection(
        provider=Provider.AZURE,
        name="tes",
        scope_type=ConnectionScope.TENANT_ROOT,
        role_version="v1",
        consent_status=ConsentStatus.GRANTED,
        status=CloudAccountStatus.ACTIVE,
    )
    connection.id = uuid.uuid4()
    connection.tenant_id = "8e482025-7ac9-4323-81e5-bc9fa528afd7"
    connection.rbac_verified_at = datetime.now(UTC)
    # Server-generated in the database; supplied here because the response
    # model requires it.
    connection.created_at = datetime.now(UTC)
    return connection


def subscription(*, scannable: bool) -> CloudAccount:
    account = CloudAccount(
        provider=Provider.AZURE,
        account_name="Azure subscription 1",
        display_name="Azure subscription 1",
        tenant_id="8e482025-7ac9-4323-81e5-bc9fa528afd7",
        subscription_id=str(uuid.uuid4()),
        in_scope=scannable,
        consent_status=ConsentStatus.GRANTED,
        status=CloudAccountStatus.ACTIVE if scannable else CloudAccountStatus.DISABLED,
    )
    account.id = uuid.uuid4()
    account.created_at = datetime.now(UTC)
    if scannable:
        account.rbac_verified_at = datetime.now(UTC)
    return account


def test_a_verified_connection_with_nothing_beneath_it_is_not_ready() -> None:
    """The reported bug, stated as an assertion."""
    connection = verified_connection()
    data = routes._serialize(connection, 0, [])

    assert data["is_verified"] is True, "both grants really do work"
    assert data["is_ready_to_scan"] is False, "but there is nothing to scan"


def test_a_connection_with_a_scannable_subscription_is_ready() -> None:
    data = routes._serialize(verified_connection(), 1, [subscription(scannable=True)])
    assert data["is_ready_to_scan"] is True


def test_subscriptions_the_customer_excluded_do_not_make_it_ready() -> None:
    """Discovering a subscription and then excluding it from scanning leaves
    the connection exactly as unable to scan as before."""
    data = routes._serialize(verified_connection(), 1, [subscription(scannable=False)])
    assert data["is_ready_to_scan"] is False


def test_an_unverified_connection_is_never_ready() -> None:
    connection = verified_connection()
    connection.rbac_verified_at = None
    data = routes._serialize(connection, 1, [subscription(scannable=True)])
    assert data["is_ready_to_scan"] is False
