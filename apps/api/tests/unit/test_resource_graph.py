"""Inventory read through Resource Graph, and how it knows it read all of it.

The ARM resource listing it replaces could only ever infer completeness: it
followed ``nextLink`` until the page cap and, if a link remained, said so. That
is a guess about the tail of a list nobody saw. Resource Graph states
``totalRecords`` for the query, so a short read is caught by comparing two
numbers the service supplied -- which is the difference between "we read
everything" and "we did not notice reading only some of it".

Kept apart from the ARM client tests on purpose: separate paging model,
separate quota, separate class.
"""

import httpx
import pytest

from app.connectors.azure.client import RESOURCE_GRAPH_QUERY_URL, ResourceGraphClient


class FakeTokens:
    def arm_token(self) -> str:
        return "arm"


def graph_of(*pages: dict, record: list[dict] | None = None) -> httpx.AsyncClient:
    """A Resource Graph that answers each POST with the next prepared page."""
    remaining = list(pages)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert RESOURCE_GRAPH_QUERY_URL.split("?")[0] in request.url.path
        if record is not None:
            import json

            record.append(json.loads(request.content))
        return httpx.Response(200, json=remaining.pop(0) if remaining else {"data": []})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def rows(*ids: str) -> list[dict]:
    return [{"id": i, "name": i.rsplit("/", 1)[-1], "type": "microsoft.storage/x"} for i in ids]


async def collect(*pages: dict, record: list[dict] | None = None, **kwargs):
    client = ResourceGraphClient(FakeTokens(), graph_of(*pages, record=record))
    return await client.list_inventory("sub-1", **kwargs), client


# --------------------------------------------------------------- the query
async def test_the_query_is_scoped_to_one_subscription() -> None:
    sent: list[dict] = []
    await collect({"data": rows("/a"), "totalRecords": 1, "count": 1}, record=sent)

    assert sent[0]["subscriptions"] == ["sub-1"]
    assert sent[0]["options"]["resultFormat"] == "objectArray"


async def test_the_query_is_ordered_so_paging_is_stable() -> None:
    """Resource Graph's skip token is only meaningful over an ordered query;
    without it pages can repeat or drop rows, which would be a miscount
    presented as an inventory."""
    sent: list[dict] = []
    await collect({"data": rows("/a"), "totalRecords": 1}, record=sent)

    assert "order by id asc" in sent[0]["query"]


async def test_configuration_is_not_projected() -> None:
    """Inventory answers what exists. The configuration a rule judges comes
    from the ARM listing for that type, stored verbatim -- projecting
    ``properties`` here would hold a second, staler copy of it in every
    snapshot."""
    sent: list[dict] = []
    await collect({"data": rows("/a"), "totalRecords": 1}, record=sent)

    assert "properties" not in sent[0]["query"]


# --------------------------------------------------------------- the paging
async def test_every_page_is_followed_to_the_end() -> None:
    sent: list[dict] = []
    found, client = await collect(
        {"data": rows("/a", "/b"), "totalRecords": 3, "$skipToken": "next"},
        {"data": rows("/c"), "totalRecords": 3},
        record=sent,
    )

    assert [r["id"] for r in found] == ["/a", "/b", "/c"]
    assert sent[1]["options"]["$skipToken"] == "next"
    assert not client.truncated, "a complete read records no gap"


async def test_a_short_read_against_the_stated_total_is_truncation() -> None:
    """The check ARM paging could not make. The service said the query matched
    four rows; three arrived, and no rule may conclude anything from the set."""
    found, client = await collect({"data": rows("/a", "/b", "/c"), "totalRecords": 4})

    assert len(found) == 3, "what was read is still kept"
    assert client.truncated


async def test_the_services_own_truncation_flag_is_believed() -> None:
    """Sent as the string "true", which is not falsy -- reading it as a boolean
    would silently pass every truncated result through as complete."""
    _found, client = await collect(
        {"data": rows("/a"), "totalRecords": 1, "resultTruncated": "true"}
    )

    assert client.truncated


async def test_the_page_cap_stops_the_walk_and_records_the_gap() -> None:
    """A query that keeps offering another page must degrade one category, not
    hold the scan open."""
    endless = [
        {"data": rows(f"/{n}"), "totalRecords": 99, "$skipToken": "more"}
        for n in range(5)
    ]
    found, client = await collect(*endless, max_pages=3)

    assert len(found) == 3
    assert client.truncated


# ------------------------------------------------------------ the boundary
async def test_a_denied_query_names_the_role_not_consent() -> None:
    """Resource Graph is ARM permissions, and a customer sent to check admin
    consent for it would find a correctly configured blade."""
    from app.connectors.azure.client import AzureApiError

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": {"message": "denied"}})

    client = ResourceGraphClient(
        FakeTokens(), httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )

    with pytest.raises(AzureApiError) as raised:
        await client.list_inventory("sub-1")

    assert "Redeploy the role" in str(raised.value)
    assert "consent" in str(raised.value), "and says what it is not"
