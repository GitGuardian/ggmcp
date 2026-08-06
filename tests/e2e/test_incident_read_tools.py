"""Read-path incident tools: list_incidents, count_incidents, get_incident,
list_repo_occurrences.

These are the highest-traffic tools of the remote server. The tests pin the
exact wire contract with the GitGuardian API (paths, query params, and their
serialization) and the reshaping applied to responses, so any refactor of the
functional core that drifts either side fails here.
"""

import json
from http import HTTPStatus

import httpx
import pytest

from tests.e2e.harness import (
    TEST_MEMBER_ID,
    call_tool,
    sent_params,
    token_info,
    tool_error_text,
    tool_output,
    unwrap_result,
)

INCIDENT = {"id": 77, "status": "TRIGGERED", "severity": "high", "detector": {"name": "aws_iam"}}

DEFAULT_LIST_QUERY = {
    "page": "1",
    "page_size": "20",
    "ordering": "-date",
    "status__in": "TRIGGERED,ASSIGNED,RESOLVED",
    "severity__in": "10,20,30,100",
    "validity__in": "valid,failed_to_check,no_checker,not_checked",
    "tags__nin": "TEST_FILE,FALSE_POSITIVE,CHECK_RUN_SKIP_FALSE_POSITIVE,CHECK_RUN_SKIP_LOW_RISK,CHECK_RUN_SKIP_TEST_CRED",
}


class TestListIncidents:
    async def test_default_call_applies_the_opinionated_filters(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN no explicit filters
        WHEN list_incidents is called
        THEN the API receives the documented default filters (open statuses,
             low/info severity excluded, noise tags excluded) and the response
             is reshaped with pagination flags and the applied-filter echo
        """
        route = gg_api.get("/incidents-for-mcp").respond(
            200, json={"results": [INCIDENT], "count": 1, "next": None, "previous": None}
        )

        result = await call_tool(mcp_client, "list_incidents", {"params": {}})

        assert sent_params(route) == DEFAULT_LIST_QUERY
        output = unwrap_result(result)
        assert output["incidents"] == [INCIDENT]
        assert output["page"] == 1
        assert output["page_size"] == 20
        assert output["has_next"] is False
        assert output["has_previous"] is False
        assert output["applied_filters"]["status"] == ["TRIGGERED", "ASSIGNED", "RESOLVED"]

    async def test_filters_serialize_to_the_api_dialect(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN severity names, source ids, booleans, a count floor and a date
        WHEN list_incidents is called
        THEN they serialize as severity codes, source__in, lowercase booleans,
             a ">=N" operator string, and a date-only bound
        """
        route = gg_api.get("/incidents-for-mcp").respond(200, json={"results": [], "next": None, "previous": None})

        await call_tool(
            mcp_client,
            "list_incidents",
            {
                "params": {
                    "severity": ["critical", "high"],
                    "source_ids": [11, 22],
                    "publicly_shared": True,
                    "occurrence_count_min": 3,
                    "date_after": "2026-07-01T15:30:00Z",
                    "status": None,
                    "validity": None,
                    "exclude_tags": None,
                }
            },
        )

        params = sent_params(route)
        assert params["severity__in"] == "10,20"
        assert params["source__in"] == "11,22"
        assert params["publicly_shared"] == "true"
        assert params["occurrence_count"] == ">=3"
        assert params["date__ge"] == "2026-07-01"
        assert "status__in" not in params
        assert "validity__in" not in params
        assert "tags__nin" not in params

    async def test_mine_resolves_the_caller_to_a_member_id_before_filtering(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN mine=True
        WHEN list_incidents is called
        THEN the server resolves the caller via /api_tokens/self and /members/{id}
             and filters incidents on assignee_member_id
        """
        member = gg_api.get(f"/members/{TEST_MEMBER_ID}").respond(
            200, json={"id": TEST_MEMBER_ID, "email": "dev@corp.test"}
        )
        incidents = gg_api.get("/incidents-for-mcp").respond(200, json={"results": [], "next": None, "previous": None})

        await call_tool(mcp_client, "list_incidents", {"params": {"mine": True}})

        assert member.called
        assert sent_params(incidents)["assignee_member_id"] == str(TEST_MEMBER_ID)

    @pytest.mark.xfail(
        strict=True,
        reason="SI-3891: mine=True is not rejected clearly for service tokens",
    )
    async def test_service_token_without_member_id_rejects_mine_filter(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a service token without a member ID
        WHEN list_incidents is called with mine=True
        THEN the tool fails clearly without querying unfiltered incidents
        """
        gg_api.get("/api_tokens/self").respond(200, json=token_info(member_id=None))
        incidents = gg_api.get("/incidents-for-mcp").respond(200, json={"results": []})

        result = await call_tool(mcp_client, "list_incidents", {"params": {"mine": True}})

        assert "mine" in tool_error_text(result).lower()
        assert not incidents.called

    async def test_mine_conflicting_with_assignee_id_short_circuits(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN mine=True together with a different explicit assignee_id
        WHEN list_incidents is called
        THEN a conflict error is returned and the incidents API is never queried
        """
        gg_api.get(f"/members/{TEST_MEMBER_ID}").respond(200, json={"id": TEST_MEMBER_ID})
        incidents = gg_api.get("/incidents-for-mcp").respond(200, json={"results": []})

        result = await call_tool(mcp_client, "list_incidents", {"params": {"mine": True, "assignee_id": 1}})

        output = unwrap_result(result)
        assert output["error"].startswith(f"Conflict: 'mine=True' implies assignee_id={TEST_MEMBER_ID}")
        assert not incidents.called

    async def test_get_all_accumulates_page_number_pagination_until_exhausted(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN two pages of incidents
        WHEN list_incidents is called with get_all=True
        THEN both pages are fetched and merged into a single response
        """
        pages = {
            "1": {"results": [{"id": 1}], "next": "https://api.gitguardian.com/v1/incidents-for-mcp?page=2"},
            "2": {"results": [{"id": 2}], "next": None},
        }
        route = gg_api.get("/incidents-for-mcp").mock(
            side_effect=lambda request: httpx.Response(200, json=pages[request.url.params["page"]])
        )

        result = await call_tool(mcp_client, "list_incidents", {"params": {"get_all": True}})

        assert route.call_count == 2
        output = unwrap_result(result)
        assert [i["id"] for i in output["incidents"]] == [1, 2]
        assert output["has_more"] is False

    @pytest.mark.xfail(
        strict=True,
        reason="SI-3891: list_incidents swallows downstream authorization failures into its result payload",
    )
    async def test_api_rejection_surfaces_as_a_tool_error(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN the API rejecting the token with 401
        WHEN list_incidents is called
        THEN the call fails with a tool error naming the status
        """
        gg_api.get("/incidents-for-mcp").respond(
            status_code=HTTPStatus.UNAUTHORIZED,
            json={"detail": "Invalid API key."},
        )

        result = await call_tool(mcp_client, "list_incidents", {"params": {}})

        assert str(HTTPStatus.UNAUTHORIZED.value) in tool_error_text(result)


class TestCountIncidents:
    async def test_count_uses_the_dedicated_endpoint_with_the_same_filters(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN default filters
        WHEN count_incidents is called
        THEN /incidents-for-mcp/count receives the same filter dialect and the
             count comes back with the applied-filter echo
        """
        route = gg_api.get("/incidents-for-mcp/count").respond(200, json={"count": 1337})

        result = await call_tool(mcp_client, "count_incidents", {"params": {}})

        params = sent_params(route)
        assert params == {
            key: value for key, value in DEFAULT_LIST_QUERY.items() if key not in ("page", "page_size", "ordering")
        }
        output = unwrap_result(result)
        assert output["count"] == 1337
        assert output["applied_filters"]["severity"] == [10, 20, 30, 100]

    async def test_count_mine_filters_on_the_resolved_member(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN mine=True
        WHEN count_incidents is called
        THEN the count query filters on the caller's member id
        """
        gg_api.get(f"/members/{TEST_MEMBER_ID}").respond(200, json={"id": TEST_MEMBER_ID})
        route = gg_api.get("/incidents-for-mcp/count").respond(200, json={"count": 2})

        result = await call_tool(mcp_client, "count_incidents", {"params": {"mine": True}})

        assert sent_params(route)["assignee_member_id"] == str(TEST_MEMBER_ID)
        assert unwrap_result(result)["count"] == 2


class TestGetIncident:
    async def test_incident_is_fetched_by_id_and_wrapped(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN an incident id
        WHEN get_incident is called with defaults
        THEN the incident endpoint is hit without query params and the raw
             incident is returned under the incident key
        """
        route = gg_api.get("/incidents/secrets/77").respond(200, json=INCIDENT)

        result = await call_tool(mcp_client, "get_incident", {"params": {"incident_id": 77}})

        assert str(route.calls.last.request.url) == "https://api.gitguardian.com/v1/incidents/secrets/77"
        assert tool_output(result) == {"incident": INCIDENT}

    async def test_call_tool_result_carries_both_structured_and_text_content(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN a successful tool call in stateless JSON mode
        WHEN the raw CallToolResult is inspected
        THEN it carries the payload both as structuredContent and as JSON text,
             with isError false
        """
        gg_api.get("/incidents/secrets/77").respond(200, json=INCIDENT)

        result = await call_tool(mcp_client, "get_incident", {"params": {"incident_id": 77}})

        assert result["isError"] is False
        assert result["structuredContent"] == {"incident": INCIDENT}
        assert result["content"][0]["type"] == "text"
        assert json.loads(result["content"][0]["text"]) == {"incident": INCIDENT}

    async def test_non_default_occurrence_count_is_forwarded(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN with_occurrences=50
        WHEN get_incident is called
        THEN the with_occurrences query param is sent
        """
        route = gg_api.get("/incidents/secrets/77").respond(200, json=INCIDENT)

        await call_tool(mcp_client, "get_incident", {"params": {"incident_id": 77, "with_occurrences": 50}})

        assert sent_params(route)["with_occurrences"] == "50"

    async def test_unknown_incident_surfaces_as_a_tool_error(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN the API answering 404
        WHEN get_incident is called
        THEN the call fails with a tool error naming the status
        """
        incident_id = 987654
        gg_api.get(f"/incidents/secrets/{incident_id}").respond(
            status_code=HTTPStatus.NOT_FOUND,
            json={"detail": "Not found."},
        )

        result = await call_tool(mcp_client, "get_incident", {"params": {"incident_id": incident_id}})

        assert str(HTTPStatus.NOT_FOUND.value) in tool_error_text(result)


class TestListRepoOccurrences:
    async def test_occurrences_query_and_cursor_pagination(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a source id and a next page advertised via the Link header
        WHEN list_repo_occurrences is called
        THEN the query carries the default noise filters and the decoded cursor
             is handed back with has_more=True
        """
        occurrence = {"id": 9, "incident": {"id": 77}, "filepath": "src/config.py"}
        route = gg_api.get("/occurrences/secrets").respond(
            200,
            json={"results": [occurrence]},
            headers={"Link": '<https://api.gitguardian.com/v1/occurrences/secrets?cursor=cD0yMDI2%3D%3D>; rel="next"'},
        )

        result = await call_tool(mcp_client, "list_repo_occurrences", {"params": {"source_id": 55}})

        params = sent_params(route)
        assert params["source_id"] == "55"
        assert params["with_sources"] == "false"
        assert params["per_page"] == "20"
        assert params["status"] == "TRIGGERED,ASSIGNED,RESOLVED"
        assert params["severity"] == "critical,high,medium,unknown"
        assert params["validity"] == "valid,failed_to_check,no_checker,unknown"
        assert params["exclude_tags"] == (
            "TEST_FILE,FALSE_POSITIVE,CHECK_RUN_SKIP_FALSE_POSITIVE,CHECK_RUN_SKIP_LOW_RISK,CHECK_RUN_SKIP_TEST_CRED"
        )
        output = unwrap_result(result)
        assert output["occurrences"] == [occurrence]
        assert output["occurrences_count"] == 1
        assert output["cursor"] == "cD0yMDI2=="
        assert output["has_more"] is True

    async def test_mine_filters_on_the_token_member_id(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN mine=True
        WHEN list_repo_occurrences is called
        THEN the member id from /api_tokens/self is sent as member_assignee_id
        """
        route = gg_api.get("/occurrences/secrets").respond(200, json={"results": []})

        await call_tool(mcp_client, "list_repo_occurrences", {"params": {"mine": True}})

        assert sent_params(route)["member_assignee_id"] == str(TEST_MEMBER_ID)

    @pytest.mark.xfail(
        strict=True,
        reason="SI-3891: mine=True silently drops the assignee filter for service tokens",
    )
    async def test_service_token_without_member_id_rejects_mine_filter(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a service-account token whose member_id is null
        WHEN list_repo_occurrences is called with mine=True
        THEN the tool fails clearly without querying unfiltered occurrences
        """
        gg_api.get("/api_tokens/self").respond(200, json=token_info(member_id=None))
        occurrences = gg_api.get("/occurrences/secrets").respond(200, json={"results": []})

        result = await call_tool(mcp_client, "list_repo_occurrences", {"params": {"mine": True}})

        assert "mine" in tool_error_text(result).lower()
        assert not occurrences.called
