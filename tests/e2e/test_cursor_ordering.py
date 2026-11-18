"""Cursor-paginated list tools order tied items by id, so paging through them returns each item once.

The API returns items tied on the sort field (many public incidents share a date to the
second) in an order that changes between requests, unless id follows the sort field.
"""

import random

import httpx
import pytest

from tests.e2e.harness import call_tool, sent_params, tool_output

# (tool, arguments, endpoint, key holding the items)
CURSOR_TOOLS = [
    pytest.param("list_public_incidents", {}, "/public-incidents/secrets", "incidents", id="public-incidents"),
    pytest.param(
        "list_public_occurrences",
        {"incident_id": 7},
        "/public-incidents/secrets/7/occurrences",
        "occurrences",
        id="public-occurrences",
    ),
    pytest.param(
        "list_internal_occurrences",
        {"source_id": 55, "ordering": "-date"},
        "/occurrences/secrets",
        "occurrences",
        id="repo-occurrences",
    ),
]


def _tied_items_endpoint(endpoint: str, total: int):
    """total items sharing one date, ordered by id only when the ordering names it.

    Otherwise each request orders them differently, as the API does. The cursor is an
    offset into that order.
    """
    shuffles = random.Random(0)

    def respond(request: httpx.Request) -> httpx.Response:
        ids = list(range(total))
        if "-id" in request.url.params.get("ordering", "").split(","):
            ids.reverse()
        else:
            shuffles.shuffle(ids)
        offset = int(request.url.params.get("cursor", "0"))
        per_page = int(request.url.params["per_page"])
        page = [{"id": i, "date": "2026-11-09T12:30:37Z"} for i in ids[offset : offset + per_page]]
        headers = {}
        if offset + per_page < total:
            headers["Link"] = f'<https://api.gitguardian.com/v1{endpoint}?cursor={offset + per_page}>; rel="next"'
        return httpx.Response(200, json=page, headers=headers)

    return respond


@pytest.mark.parametrize(("tool", "arguments", "endpoint", "items_key"), CURSOR_TOOLS)
async def test_paging_through_tied_items_returns_each_once(
    mcp_client, gg_api, mock_token_scopes, tool, arguments, endpoint, items_key
):
    """
    GIVEN 30 items that all share one date
    WHEN the tool is called page by page with the next_arguments it returns
    THEN every item comes back exactly once
    """
    gg_api.get(endpoint).mock(side_effect=_tied_items_endpoint(endpoint, total=30))

    seen: list[int] = []
    call_arguments = {**arguments, "page_size": 10}
    for _ in range(5):
        output = tool_output(await call_tool(mcp_client, tool, call_arguments))
        seen.extend(item["id"] for item in output[items_key])
        if not output["has_more"]:
            break
        call_arguments = output["next_arguments"]

    assert sorted(seen) == list(range(30))


@pytest.mark.parametrize(
    ("ordering", "sent"),
    [
        pytest.param("date", "date,id", id="ascending"),
        pytest.param("-risk_score", "-risk_score,-id", id="descending"),
    ],
)
async def test_ordering_gets_an_id_tiebreaker_in_its_direction(mcp_client, gg_api, mock_token_scopes, ordering, sent):
    """
    GIVEN an ordering
    WHEN list_public_incidents is called with it
    THEN the API receives it with id appended, in the sort field's direction, unless it names id already
    """
    route = gg_api.get("/public-incidents/secrets").respond(200, json=[])

    await call_tool(mcp_client, "list_public_incidents", {"ordering": ordering})

    assert sent_params(route)["ordering"] == sent


async def test_repo_occurrences_without_an_ordering_send_none(mcp_client, gg_api, mock_token_scopes):
    """
    GIVEN no ordering
    WHEN list_internal_occurrences is called
    THEN no ordering is sent, and the API's default order (by id) applies
    """
    route = gg_api.get("/occurrences/secrets").respond(200, json=[])

    await call_tool(mcp_client, "list_internal_occurrences", {"source_id": 55})

    assert "ordering" not in sent_params(route)


async def test_an_ordering_by_id_gets_no_second_id(mcp_client, gg_api, mock_token_scopes):
    """
    GIVEN an ordering by id, which list_public_occurrences offers
    WHEN the tool is called with it
    THEN the API receives it unchanged, since id already breaks every tie
    """
    route = gg_api.get("/public-incidents/secrets/7/occurrences").respond(200, json=[])

    await call_tool(mcp_client, "list_public_occurrences", {"incident_id": 7, "ordering": "-id"})

    assert sent_params(route)["ordering"] == "-id"
