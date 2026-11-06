"""Workspace tools: list_sources and get_remediation_workflow."""

import httpx
import pytest

from tests.e2e.harness import (
    assert_authenticated_request,
    call_tool,
    sent_params,
    tool_output,
)


class TestListSources:
    async def test_filters_and_cursor_pagination(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN source filters and a next page advertised via the Link header
        WHEN list_sources is called
        THEN the query carries the filters (booleans lowercased) and the cursor
             comes back decoded with has_more=True
        """
        source = {"id": 55, "name": "ggmcp", "type": "github"}
        route = gg_api.get("/sources").respond(
            200,
            json=[source],
            headers={"Link": '<https://api.gitguardian.com/v1/sources?cursor=abc%3D%3D>; rel="next"'},
        )

        result = await call_tool(
            mcp_client,
            "list_sources",
            {"params": {"type": "github", "monitored": True, "search": "gg"}},
        )

        params = sent_params(route)
        assert_authenticated_request(route)
        assert params == {"search": "gg", "type": "github", "monitored": "true", "per_page": "20"}
        output = tool_output(result)
        assert output["sources"] == [source]
        assert output["next_cursor"] == "abc=="
        assert output["has_more"] is True

    @pytest.mark.parametrize(
        ("filters", "expected_query"),
        [
            pytest.param({"health": "safe"}, {"health": "safe", "per_page": "20"}, id="health"),
            pytest.param({"visibility": "private"}, {"visibility": "private", "per_page": "20"}, id="visibility"),
            pytest.param(
                {"source_criticality": "unknown"},
                {"source_criticality": "unknown", "per_page": "20"},
                id="source-criticality",
            ),
            pytest.param({"team_id": 1}, {"team_id": "1", "per_page": "20"}, id="team"),
            pytest.param(
                {"ordering": "-last_scan_date"},
                {"ordering": "-last_scan_date", "per_page": "20"},
                id="ordering",
            ),
        ],
    )
    async def test_each_filter_is_forwarded(self, mcp_client, gg_api, mock_token_scopes, filters, expected_query):
        """
        GIVEN one source filter
        WHEN list_sources is called
        THEN the sources query carries exactly that filter and the page size
        """
        route = gg_api.get("/sources").respond(200, json=[])

        await call_tool(mcp_client, "list_sources", {"params": filters})

        assert sent_params(route) == expected_query

    async def test_get_all_follows_the_cursor_to_the_last_page(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN two pages of sources linked by a cursor
        WHEN list_sources is called with get_all=True
        THEN the second page is requested with that cursor and both pages come back
        """
        first, second = {"id": 1, "name": "a"}, {"id": 2, "name": "b"}
        route = gg_api.get("/sources").mock(
            side_effect=[
                httpx.Response(
                    200,
                    json=[first],
                    headers={"Link": '<https://api.gitguardian.com/v1/sources?cursor=cD0x>; rel="next"'},
                ),
                httpx.Response(200, json=[second]),
            ]
        )

        result = await call_tool(mcp_client, "list_sources", {"params": {"get_all": True}})

        assert route.call_count == 2
        assert dict(route.calls[1].request.url.params)["cursor"] == "cD0x"
        output = tool_output(result)
        assert output["sources"] == [first, second]
        assert output["has_more"] is False


class TestGetRemediationWorkflow:
    async def test_workflow_is_fetched_and_wrapped(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a workspace with a remediation workflow
        WHEN get_remediation_workflow is called
        THEN /remediation-workflow is read with the caller's token and the
             workflow comes back under a "workflow" key, untouched
        """
        workflow = {
            "id": 6,
            "account_id": 8,
            "steps": [{"title": "Rotate the secret", "description": "Contact DevOps."}],
        }
        route = gg_api.get("/remediation-workflow").respond(200, json=workflow)

        result = await call_tool(mcp_client, "get_remediation_workflow", {})

        assert_authenticated_request(route)
        assert tool_output(result) == {"workflow": workflow}
