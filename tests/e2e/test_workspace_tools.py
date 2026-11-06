"""Workspace metadata and remediation tools: list_sources, read_custom_tags,
find_current_source_id, list_remediation_targets.
"""

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
