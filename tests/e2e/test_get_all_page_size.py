"""get_all on the cursor-paginated list tools keeps its pages small, so its result fits the size budget.

The first page is always returned whole, so the page size is what bounds a get_all result.
"""

import json

import httpx
import pytest

from gg_api_core.client import DEFAULT_PAGINATION_MAX_BYTES, PAGINATE_ALL_PER_PAGE
from tests.e2e.harness import call_tool, tool_output


def _output(result: dict) -> dict:
    """The tool's fields, whether or not its output is wrapped under "result"."""
    output = tool_output(result)
    return output["result"] if set(output) == {"result"} else output


# (tool, arguments, endpoint, key holding the items, key holding the next cursor)
CURSOR_TOOLS = [
    pytest.param(
        "list_public_incidents", {}, "/public-incidents/secrets", "incidents", "cursor", id="public-incidents"
    ),
    pytest.param(
        "list_public_occurrences",
        {"incident_id": 7},
        "/public-incidents/secrets/7/occurrences",
        "occurrences",
        "cursor",
        id="public-occurrences",
    ),
    pytest.param(
        "list_repo_occurrences",
        {"source_id": 55},
        "/occurrences/secrets",
        "occurrences",
        "cursor",
        id="repo-occurrences",
    ),
    pytest.param("list_sources", {}, "/sources", "sources", "next_cursor", id="sources"),
]


def _cursor_pages(endpoint: str, total: int, item_bytes: int = 1500):
    """A cursor-paginated endpoint: the cursor is the offset, and each page holds per_page items."""

    def respond(request: httpx.Request) -> httpx.Response:
        offset = int(request.url.params.get("cursor", "0"))
        per_page = int(request.url.params["per_page"])
        items = [{"id": i, "note": "x" * item_bytes} for i in range(offset, min(offset + per_page, total))]
        headers = {}
        if offset + per_page < total:
            headers["Link"] = f'<https://api.gitguardian.com/v1{endpoint}?cursor={offset + per_page}>; rel="next"'
        return httpx.Response(200, json=items, headers=headers)

    return respond


@pytest.mark.parametrize(("tool", "arguments", "endpoint", "items_key", "cursor_key"), CURSOR_TOOLS)
async def test_get_all_asks_for_small_pages_and_stays_within_its_budget(
    mcp_client, gg_api, mock_token_scopes, tool, arguments, endpoint, items_key, cursor_key
):
    """
    GIVEN 200 items of about 1.5 KB each, and get_all asked for pages of 100
    WHEN the tool is called
    THEN every request asks for small pages, and the result fits the size budget and says more remain
    """
    route = gg_api.get(endpoint).mock(side_effect=_cursor_pages(endpoint, total=200))

    output = _output(await call_tool(mcp_client, tool, {**arguments, "get_all": True, "per_page": 100}))

    assert {call.request.url.params["per_page"] for call in route.calls} == {str(PAGINATE_ALL_PER_PAGE)}
    assert len(json.dumps(output[items_key])) <= DEFAULT_PAGINATION_MAX_BYTES
    assert output["has_more"] is True


@pytest.mark.parametrize(("tool", "arguments", "endpoint", "items_key", "cursor_key"), CURSOR_TOOLS)
async def test_get_all_resumed_with_its_cursor_returns_every_item_once(
    mcp_client, gg_api, mock_token_scopes, tool, arguments, endpoint, items_key, cursor_key
):
    """
    GIVEN 90 items, more than one get_all call holds
    WHEN get_all is called again with the cursor it returns, until has_more is false
    THEN every item comes back exactly once, in order, and every call fits the size budget
    """
    gg_api.get(endpoint).mock(side_effect=_cursor_pages(endpoint, total=90))

    seen: list[int] = []
    call_arguments = {**arguments, "get_all": True, "per_page": 100}
    for _ in range(10):
        output = _output(await call_tool(mcp_client, tool, call_arguments))
        assert len(json.dumps(output[items_key])) <= DEFAULT_PAGINATION_MAX_BYTES
        seen.extend(item["id"] for item in output[items_key])
        if not output["has_more"]:
            break
        call_arguments = {**call_arguments, "cursor": output[cursor_key]}

    assert seen == list(range(90))
