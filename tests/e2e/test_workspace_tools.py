"""Workspace metadata and remediation tools: list_sources, read_custom_tags,
find_current_source_id, remediate_secret_incidents.
"""

from http import HTTPStatus

import httpx
import pytest

from tests.e2e.harness import (
    TEST_MEMBER_ID,
    assert_authenticated_request,
    call_tool,
    sent_params,
    token_info,
    tool_error_text,
    tool_output,
    unwrap_result,
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


class TestReadCustomTags:
    @pytest.mark.xfail(
        strict=True,
        reason="SI-3891: read_custom_tags requires tag_id even when listing tags",
    )
    async def test_list_tags_does_not_require_a_tag_id(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN existing custom tags
        WHEN read_custom_tags is called with action=list_tags and no tag ID
        THEN /custom_tags is queried and the payload is returned untouched
        """
        tags = [{"id": "1", "key": "team", "value": "payments"}]
        route = gg_api.get("/custom_tags").respond(200, json=tags)

        result = await call_tool(mcp_client, "read_custom_tags", {"params": {"action": "list_tags"}})

        assert route.called
        assert sent_params(route) == {}
        assert tool_output(result) == tags

    async def test_get_tag_fetches_one_tag_by_id(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a tag id
        WHEN read_custom_tags is called with action=get_tag
        THEN /custom_tags/{id} is queried and the tag returned verbatim
        """
        tag = {"id": "9", "key": "env", "value": "prod"}
        route = gg_api.get("/custom_tags/9").respond(200, json=tag)

        result = await call_tool(mcp_client, "read_custom_tags", {"params": {"action": "get_tag", "tag_id": 9}})

        assert route.called
        assert tool_output(result) == tag


class TestFindCurrentSourceId:
    async def test_remote_server_cannot_introspect_git_and_says_so(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN the hosted (HTTP) server, which has no access to the caller's repo
        WHEN find_current_source_id is called without remote_url
        THEN it returns the run-git-yourself suggestion without touching the API
        """
        result = await call_tool(mcp_client, "find_current_source_id", {})

        output = unwrap_result(result)
        assert "git config --get remote.origin.url" in output["suggestion"]
        assert output["message"] == "The repository could not be detected server-side."
        assert not [call for call in gg_api.calls if call.request.url.path == "/v1/sources"]

    async def test_remote_url_is_parsed_and_matched_against_sources(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a git remote URL
        WHEN find_current_source_id is called
        THEN sources are searched by the bare repository name and the exact
             match's id is returned
        """
        route = gg_api.get("/sources").respond(
            200, json=[{"id": 55, "name": "ggmcp", "full_name": "GitGuardian/ggmcp"}]
        )

        result = await call_tool(
            mcp_client,
            "find_current_source_id",
            {"remote_url": "https://github.com/GitGuardian/ggmcp.git"},
        )

        params = sent_params(route)
        assert params == {"search": "ggmcp", "per_page": "50"}
        output = unwrap_result(result)
        assert output["source_id"] == 55
        assert output["repository_name"] == "ggmcp"

    @pytest.mark.xfail(
        strict=True,
        reason="SI-3891: source lookup swallows API failures and reports the repository as missing",
    )
    async def test_api_failure_surfaces_as_a_tool_error(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN the sources endpoint rejecting the token with 403
        WHEN find_current_source_id is called
        THEN the API failure surfaces as a tool error
        """
        gg_api.get("/sources").respond(
            status_code=HTTPStatus.FORBIDDEN,
            json={"detail": "Forbidden"},
        )

        result = await call_tool(mcp_client, "find_current_source_id", {"remote_url": "git@github.com:acme/app.git"})

        assert str(HTTPStatus.FORBIDDEN.value) in tool_error_text(result)


class TestRemediateSecretIncidents:
    OCCURRENCES = [
        {"id": 1, "incident": {"id": 501, "assignee_id": TEST_MEMBER_ID}, "filepath": "a.py"},
        {"id": 2, "incident": {"id": 502, "assignee_id": 9999}, "filepath": "b.py"},
    ]

    async def test_default_flow_lists_default_branch_occurrences_and_renders_instructions(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN a source with occurrences
        WHEN remediate_secret_incidents is called
        THEN occurrences are fetched restricted to the default branch and the
             result carries remediation instructions plus the occurrence list
        """
        route = gg_api.get("/occurrences/secrets").respond(200, json={"results": self.OCCURRENCES})

        result = await call_tool(mcp_client, "remediate_secret_incidents", {"params": {"source_id": 55}})

        params = sent_params(route)
        assert params["source_id"] == "55"
        assert params["tags"] == "DEFAULT_BRANCH"
        assert params["with_sources"] == "false"
        output = unwrap_result(result)
        assert output["occurrences_count"] == 2
        assert output["suggested_occurrences_for_remediation_count"] == 2
        assert output["remediation_instructions"]
        assert output["sub_tools_results"]["list_repo_occurrences"]["occurrences"] == self.OCCURRENCES

    async def test_mine_keeps_only_the_callers_occurrences(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN occurrences assigned to different members
        WHEN remediate_secret_incidents is called with mine=True
        THEN only occurrences whose incident is assigned to the caller remain
        """
        gg_api.get("/occurrences/secrets").respond(200, json={"results": self.OCCURRENCES})

        result = await call_tool(mcp_client, "remediate_secret_incidents", {"params": {"source_id": 55, "mine": True}})

        output = unwrap_result(result)
        occurrences = output["sub_tools_results"]["list_repo_occurrences"]["occurrences"]
        assert [occ["id"] for occ in occurrences] == [1]
        assert output["occurrences_count"] == 1

    @pytest.mark.xfail(
        strict=True,
        reason="SI-3891: remediation silently returns every incident when the mine filter fails",
    )
    async def test_mine_fails_closed_when_the_member_lookup_breaks(
        self, mcp_client, gg_api, mock_token_scopes, no_retry_delay
    ):
        """
        GIVEN the token-info endpoint failing during the mine filter
        WHEN remediate_secret_incidents is called with mine=True
        THEN the API failure surfaces instead of returning everyone's incidents
        """
        gg_api.get("/occurrences/secrets").respond(200, json={"results": self.OCCURRENCES})
        # First call: the per-request scope fetch (must succeed for the tool to
        # be dispatched at all). Second call: filter_mine's member lookup.
        gg_api.get("/api_tokens/self").mock(
            side_effect=[httpx.Response(200, json=token_info())] + [httpx.Response(500, text="boom")] * 4
        )

        result = await call_tool(mcp_client, "remediate_secret_incidents", {"params": {"source_id": 55, "mine": True}})

        assert "500" in tool_error_text(result)
