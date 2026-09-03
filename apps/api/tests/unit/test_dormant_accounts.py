"""Privileged accounts nobody signs into, and the licence that gates the read.

Two facts this pins, and they are separate. The reading costs no consent --
``AuditLog.Read.All`` has been granted since onboarding existed. It does cost an
Entra ID P1 or P2 licence, which admin consent cannot grant, so a tenant without
one must be told about a licence rather than sent to a Global Administrator who
would find nothing to fix (``DECISIONS.md`` section 63).
"""

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.base import RawSnapshot
from app.core.enums import Provider, ResourceType, RuleState
from app.core.errors import CloudConnectionError
from app.rules.azure.identity.dormant import AzureDormantPrivilegedAccountRule
from app.rules.base import RuleContext

CAPTURED = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
RULE = AzureDormantPrivilegedAccountRule()


def snapshot(users: list[dict], activity: dict | None, roles: dict) -> RawSnapshot:
    data: dict = {
        "users": users,
        "directory_roles": [{"id": "r1", "displayName": "Global Administrator"}],
        "user_role_map": roles,
    }
    if activity is not None:
        data["user_sign_in_activity"] = activity
    return RawSnapshot(
        provider=Provider.AZURE,
        tenant_id="tenant-1",
        subscription_id=None,
        collected_at=CAPTURED,
        data=data,
    )


def admin(user_id: str = "u1", **fields) -> dict:
    return {
        "id": user_id,
        "displayName": "Ada",
        "userPrincipalName": "ada@example.com",
        "accountEnabled": True,
        **fields,
    }


def signed_in(days_ago: float, field: str = "lastSignInDateTime") -> dict:
    return {field: (CAPTURED - timedelta(days=days_ago)).isoformat()}


def user_from(state, user_id: str = "u1"):
    return next(
        r
        for r in state.resources
        if r.resource_type == ResourceType.USER
        and r.provider_resource_id == f"/users/{user_id}"
    )


def verdict(users, activity, roles=None, errors=None) -> RuleState:
    state = AzureNormalizer().normalize(
        snapshot(
            users,
            activity,
            {"u1": ["Global Administrator"]} if roles is None else roles,
        )
    )
    resource = user_from(state)
    context = RuleContext(resources=state.resources, collection_errors=errors or {})
    return RULE.evaluate(resource, context).state


# ------------------------------------------------------------- normalization
def test_the_more_recent_of_the_two_sign_in_kinds_wins() -> None:
    """A service account authenticating nightly has no interactive sign-in at
    all. Judged on that alone, the tenant's busiest credentials read as its
    most dormant."""
    state = AzureNormalizer().normalize(
        snapshot(
            [admin()],
            {
                "u1": {
                    **signed_in(400),
                    **signed_in(3, "lastNonInteractiveSignInDateTime"),
                }
            },
            {"u1": ["Global Administrator"]},
        )
    )

    assert user_from(state).get("days_since_sign_in") == 3


def test_an_account_the_read_did_not_cover_carries_nothing() -> None:
    """Absent is not "never signed in". A user missing from the reading must
    stay tellable apart from one Entra holds no activity for."""
    state = AzureNormalizer().normalize(
        snapshot([admin()], {}, {"u1": ["Global Administrator"]})
    )

    assert user_from(state).get("sign_in_activity_read") is None
    assert user_from(state).get("days_since_sign_in") is None


def test_an_account_with_no_activity_is_read_and_empty() -> None:
    state = AzureNormalizer().normalize(
        snapshot([admin()], {"u1": None}, {"u1": ["Global Administrator"]})
    )

    assert user_from(state).get("sign_in_activity_read") is True
    assert user_from(state).get("last_sign_in") is None


# --------------------------------------------------------------- the verdict
def test_a_privileged_account_unused_for_months_fails() -> None:
    assert (
        verdict([admin()], {"u1": signed_in(200)}) is RuleState.FAIL
    )


def test_a_privileged_account_in_regular_use_passes() -> None:
    assert verdict([admin()], {"u1": signed_in(9)}) is RuleState.PASS


def test_an_account_that_has_never_signed_in_fails() -> None:
    assert (
        verdict([admin(createdDateTime=(CAPTURED - timedelta(days=500)).isoformat())],
                {"u1": None})
        is RuleState.FAIL
    )


def test_an_account_created_last_week_is_not_yet_dormant() -> None:
    """A new administrator who has not signed in yet is not an abandoned one,
    and reporting them would train a customer to ignore this check."""
    assert (
        verdict([admin(createdDateTime=(CAPTURED - timedelta(days=6)).isoformat())],
                {"u1": None})
        is RuleState.PASS
    )


def test_an_ordinary_account_is_out_of_scope() -> None:
    assert verdict([admin()], {"u1": signed_in(900)}, roles={}) is RuleState.NOT_APPLICABLE


def test_a_disabled_account_signs_nobody_in() -> None:
    assert (
        verdict([admin(accountEnabled=False)], {"u1": signed_in(900)})
        is RuleState.NOT_APPLICABLE
    )


def test_an_unread_account_is_unknown_rather_than_active() -> None:
    """The pass nobody earned, in the shape this rule would take it: an
    account whose activity was never read is not an account in daily use."""
    assert verdict([admin()], {}) is RuleState.UNKNOWN


def test_a_failed_reading_degrades_the_rule() -> None:
    assert (
        verdict(
            [admin()],
            {"u1": signed_in(9)},
            errors={"user_sign_in_activity": "Entra ID P1 or P2 licence required"},
        )
        is RuleState.UNKNOWN
    )


# ------------------------------------------------- what a 403 is actually about
class _Refusing:
    """A Graph client whose sign-in read is refused with one message."""

    def __init__(self, message: str) -> None:
        self.message = message
        self.truncated: set[str] = set()

    async def list_sign_in_activity(self) -> list[dict]:
        from app.connectors.azure.client import AzureApiError

        raise AzureApiError(f"Access denied. {self.message}", status_code=403)


async def _refusal(monkeypatch, message: str) -> str:
    from app.connectors.azure import plan as plan_module
    from app.connectors.azure.plan import AzurePlanBuilder

    class FakeTokens:
        def graph_token(self) -> str:
            # Consented in full: the only thing missing is the licence.
            import jwt

            from app.connectors.azure.auth import REQUIRED_GRAPH_PERMISSIONS

            return jwt.encode(
                {"roles": list(REQUIRED_GRAPH_PERMISSIONS)}, "irrelevant", algorithm="HS256"
            )

    monkeypatch.setattr(plan_module, "GraphClient", lambda *a, **kw: _Refusing(message))
    builder = AzurePlanBuilder(
        tokens=FakeTokens(), subscription_id=None, http_client=httpx.AsyncClient()
    )
    task = next(
        t
        for t in builder.build_directory_plan()
        if t.key.value == "user_sign_in_activity"
    )
    with pytest.raises(CloudConnectionError) as raised:
        await task.run({})
    return str(raised.value)


async def test_an_unlicensed_tenant_is_told_about_a_licence(monkeypatch) -> None:
    """The failure a fully consented tenant on the free tier actually gets.
    Sending its administrator to the consent screen would send them to fix a
    directory that is already correct."""
    message = await _refusal(
        monkeypatch, "Neither tenant is B2C or tenant doesn't have premium license"
    )

    assert "P1 or P2" in message
    assert "consent" in message.lower()


async def test_an_ordinary_refusal_keeps_its_own_explanation(monkeypatch) -> None:
    message = await _refusal(
        monkeypatch, "Insufficient privileges to complete the operation."
    )

    assert "P1 or P2" not in message
    assert "Insufficient privileges" in message
