"""get_all on the cursor-paginated list tools keeps its pages small, so its result fits the size budget.

The first page is always returned whole, so the page size is what bounds a get_all result.
"""

import json

import httpx
import pytest

from gg_api_core.client import DEFAULT_PAGINATION_MAX_BYTES, PAGINATE_ALL_PER_PAGE
from tests.e2e.harness import call_tool, tool_output

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
        {"source_id": 55},
        "/occurrences/secrets",
        "occurrences",
        id="repo-occurrences",
    ),
    pytest.param("list_sources", {}, "/sources", "sources", id="sources"),
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


@pytest.mark.parametrize(("tool", "arguments", "endpoint", "items_key"), CURSOR_TOOLS)
async def test_get_all_asks_for_small_pages_and_stays_within_its_budget(
    mcp_client, gg_api, mock_token_scopes, tool, arguments, endpoint, items_key
):
    """
    GIVEN 200 items of about 1.5 KB each, and get_all asked for pages of 100
    WHEN the tool is called
    THEN every request asks for small pages, and the result fits the size budget, says more remain, and says
         the size budget stopped it
    """
    route = gg_api.get(endpoint).mock(side_effect=_cursor_pages(endpoint, total=200))

    output = tool_output(await call_tool(mcp_client, tool, {**arguments, "get_all": True, "page_size": 100}))

    assert {call.request.url.params["per_page"] for call in route.calls} == {str(PAGINATE_ALL_PER_PAGE)}
    assert len(json.dumps(output[items_key])) <= DEFAULT_PAGINATION_MAX_BYTES
    assert output["has_more"] is True
    assert output["stop_reason"] == "size_budget"
    assert output["page_size"] == PAGINATE_ALL_PER_PAGE


@pytest.mark.parametrize(("tool", "arguments", "endpoint", "items_key"), CURSOR_TOOLS)
async def test_get_all_resumed_with_its_next_arguments_returns_every_item_once(
    mcp_client, gg_api, mock_token_scopes, tool, arguments, endpoint, items_key
):
    """
    GIVEN 90 items, more than one get_all call holds
    WHEN the tool is called again with the next_arguments it returns, until has_more is false
    THEN every item comes back exactly once, in order, every call fits the size budget, and the last result
         says it reached the end
    """
    gg_api.get(endpoint).mock(side_effect=_cursor_pages(endpoint, total=90))

    seen: list[int] = []
    call_arguments = {**arguments, "get_all": True, "page_size": 100}
    for _ in range(10):
        output = tool_output(await call_tool(mcp_client, tool, call_arguments))
        assert len(json.dumps(output[items_key])) <= DEFAULT_PAGINATION_MAX_BYTES
        seen.extend(item["id"] for item in output[items_key])
        if not output["has_more"]:
            break
        call_arguments = output["next_arguments"]

    assert seen == list(range(90))
    assert output["stop_reason"] == "end"
    assert output["next_arguments"] is None
