"""Workspace metadata and remediation tools: list_sources, read_custom_tags,
find_current_source_id, list_remediation_targets.
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


class TestListRemediationTargets:
    OCCURRENCES = [
        {
            "id": 1,
            "incident_id": 501,
            "filepath": "a.py",
        },
        {
            "id": 2,
            "incident_id": 502,
            "filepath": "b.py",
        },
    ]

    async def test_default_flow_returns_one_page_of_occurrence_data(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a source with occurrences and another page available
        WHEN list_remediation_targets is called
        THEN one default-branch page is returned with a continuation cursor and no remediation plan
        """
        route = gg_api.get("/occurrences/secrets").respond(
            200,
            json=self.OCCURRENCES,
            headers={"Link": '<https://api.gitguardian.com/v1/occurrences/secrets?cursor=page2>; rel="next"'},
        )

        result = await call_tool(mcp_client, "list_remediation_targets", {"params": {"source_id": 55}})

        params = sent_params(route)
        assert params["source_id"] == "55"
        assert params["tags"] == "DEFAULT_BRANCH"
        assert params["ordering"] == "-date"
        assert params["with_sources"] == "false"
        assert params["per_page"] == "20"
        assert route.call_count == 1
        output = unwrap_result(result)
        assert set(output) == {
            "occurrences",
            "occurrences_count",
            "cursor",
            "has_more",
            "applied_filters",
            "suggestion",
        }
        assert output["occurrences"] == self.OCCURRENCES
        assert output["occurrences_count"] == 2
        assert output["cursor"] == "page2"
        assert output["has_more"] is True
        assert output["applied_filters"]["tags"] == ["DEFAULT_BRANCH"]

    async def test_mine_keeps_only_the_callers_incidents(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN occurrences whose incident is assigned to the caller
        WHEN list_remediation_targets is called with mine=True
        THEN the API filters by incident assignee and its flat occurrence payload is preserved
        """
        route = gg_api.get("/occurrences/secrets").respond(200, json=[self.OCCURRENCES[0]])

        result = await call_tool(mcp_client, "list_remediation_targets", {"params": {"source_id": 55, "mine": True}})

        output = unwrap_result(result)
        assert sent_params(route)["incident_assignee_id"] == str(TEST_MEMBER_ID)
        assert "member_assignee_id" not in sent_params(route)
        assert output["occurrences"] == [self.OCCURRENCES[0]]
        assert output["occurrences_count"] == 1

    async def test_mine_fails_closed_when_the_member_lookup_breaks(
        self, mcp_client, gg_api, mock_token_scopes, no_retry_delay
    ):
        """
        GIVEN the token-info endpoint failing during the mine filter
        WHEN list_remediation_targets is called with mine=True
        THEN the API failure surfaces instead of returning everyone's incidents
        """
        occurrences = gg_api.get("/occurrences/secrets").respond(200, json=self.OCCURRENCES)
        # First call: the per-request scope fetch (must succeed for the tool to
        # be dispatched at all). Second call: the mine filter's member lookup.
        gg_api.get("/api_tokens/self").mock(
            side_effect=[httpx.Response(200, json=token_info())] + [httpx.Response(500, text="boom")] * 4
        )

        result = await call_tool(mcp_client, "list_remediation_targets", {"params": {"source_id": 55, "mine": True}})

        assert "500" in tool_error_text(result)
        assert not occurrences.called
