"""What a 403 tells the customer.

Every collection category can fail, and the message it fails with is the whole
of what the customer sees -- it lands in ``collection_errors``, surfaces on the
scan as "affected checks are marked unknown, not passed", and is the only
instruction they get.

Both clients used to raise one sentence naming both remedies: check the Reader
role, and check admin consent. The two grants are independent -- a role
deployment on a subscription, and a Global Administrator consenting to
directory permissions -- and ``validate_connection`` already probes them
separately so the UI can say which one is missing. Merging them here threw that
away at the last step. Half of everyone reading it was sent to a blade that
looked correctly configured, because for their failure it was.

Identity is the case that made it obvious: every identity call goes through
Graph and none goes near Azure RBAC, so "check that the Reader role is
assigned" was advice that could never once have been right.
"""

import httpx
import pytest

from app.connectors.azure.client import ArmClient, AzureApiError, GraphClient


class FakeTokens:
    def arm_token(self) -> str:
        return "arm-token"

    def graph_token(self) -> str:
        return "graph-token"


def client_returning(status: int, payload: dict | None = None, text: str = ""):
    """An httpx client that answers every request the same way."""

    def handler(request: httpx.Request) -> httpx.Response:
        if payload is not None:
            return httpx.Response(status, json=payload)
        return httpx.Response(status, text=text)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def error_from(client_cls, status: int, payload: dict | None = None, text: str = ""):
    async with client_cls(FakeTokens(), client_returning(status, payload, text)) as api:
        with pytest.raises(AzureApiError) as raised:
            await api.get("/anything")
    return raised.value


# ------------------------------------------------------------------ the split
async def test_an_arm_403_points_at_the_role_assignment() -> None:
    message = str(await error_from(ArmClient, 403))

    assert "scanner role" in message
    assert "Access control (IAM)" in message
    # It must not route an RBAC failure to the consent screen. Naming consent
    # only to rule it out is the point, so the check is on the destination.
    assert "Enterprise applications" not in message


async def test_a_graph_403_points_at_admin_consent() -> None:
    """The identity category is collected entirely through Graph."""
    message = str(await error_from(GraphClient, 403))

    assert "Admin consent" in message
    assert "Enterprise applications" in message
    # Said explicitly, because the instinct is to go and check RBAC.
    assert "Azure role assignments do not affect this" in message


async def test_neither_403_mentions_the_reader_role() -> None:
    """CloudGuard stopped asking for Reader when the custom role landed, so a
    customer sent to look for a Reader assignment will not find one even on a
    correctly configured connection."""
    for client_cls in (ArmClient, GraphClient):
        assert "Reader role" not in str(await error_from(client_cls, 403))


async def test_the_two_surfaces_do_not_share_a_message() -> None:
    """A regression guard. The failure being fixed here was one message doing
    the work of two, and the cheapest way to reintroduce it is to write a
    shared default and forget to override it."""
    assert str(await error_from(ArmClient, 403)) != str(
        await error_from(GraphClient, 403)
    )


# ------------------------------------------------------- Azure's own account
async def test_azure_s_own_message_is_carried_through() -> None:
    """Graph answers a missing grant with wording that names the shape of the
    problem better than anything written here can."""
    message = str(
        await error_from(
            GraphClient,
            403,
            {"error": {"message": "Insufficient privileges to complete the operation."}},
        )
    )
    assert "Insufficient privileges to complete the operation." in message
    assert "Azure reported:" in message


async def test_nothing_is_appended_when_azure_said_nothing() -> None:
    message = str(await error_from(ArmClient, 403, text=""))
    assert "Azure reported:" not in message
    assert message.endswith(".")


async def test_an_unparseable_body_does_not_mask_the_403() -> None:
    """The detail is a courtesy; the instruction is the point."""
    message = str(await error_from(ArmClient, 403, text="<html>gateway</html>"))
    assert "scanner role" in message


# --------------------------------------------------- the other status codes
async def test_throttling_is_still_reported_as_throttling() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "30"})

    async with ArmClient(
        FakeTokens(), httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ) as api:
        with pytest.raises(AzureApiError) as raised:
            await api.get("/anything")

    assert "throttling" in str(raised.value)
    assert raised.value.azure_status_code == 429


async def test_other_failures_keep_their_status_and_detail() -> None:
    """Covers the shared detail extraction the 403 branch now reuses."""
    error = await error_from(ArmClient, 500, {"error": {"message": "Server blew up"}})
    assert "500" in str(error)
    assert "Server blew up" in str(error)
    assert error.azure_status_code == 500
