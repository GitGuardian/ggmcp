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

# Turns off the filters list_incidents and count_incidents apply by default.
NO_DEFAULT_FILTERS = {"status": None, "severity": None, "validity": None, "exclude_tags": None}

INCIDENT_ENDPOINTS = {"list_incidents": "/incidents-for-mcp", "count_incidents": "/incidents-for-mcp/count"}


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

    @pytest.mark.parametrize(
        ("filters", "expected"),
        [
            pytest.param(
                {"source_criticality": ["critical", "high"]},
                {"source_criticality__in": "critical,high"},
                id="source-criticality",
            ),
            pytest.param(
                {"detector_group_name": ["AWS Keys"]}, {"detector_group_name__in": "AWS Keys"}, id="detector-group"
            ),
            pytest.param(
                {"detector_category": ["specific"]}, {"detector_category__in": "specific"}, id="detector-category"
            ),
            pytest.param({"presence": ["present"]}, {"presence__in": "present"}, id="presence"),
            pytest.param(
                {"issue_tracker": ["jira_cloud_notifier"]},
                {"issue_tracker__in": "jira_cloud_notifier"},
                id="issue-tracker",
            ),
            pytest.param(
                {"secret_manager_type": ["hashicorpvault", "awssecretsmanager"]},
                {"secret_manager_type__in": "hashicorpvault,awssecretsmanager"},
                id="secret-manager-type",
            ),
            pytest.param({"teams": [1]}, {"teams__in": "1"}, id="teams"),
            pytest.param({"search": "aws"}, {"search": "aws"}, id="search"),
            pytest.param(
                {"date_after": "2024-01-01", "date_before": "2025-12-31"},
                {"date__ge": "2024-01-01", "date__le": "2025-12-31"},
                id="date-range",
            ),
        ],
    )
    async def test_each_filter_maps_to_its_api_parameter(
        self, mcp_client, gg_api, mock_token_scopes, filters, expected
    ):
        """
        GIVEN one tool filter
        WHEN list_incidents is called
        THEN the API receives it under its own query parameter, serialized the
             way the API expects
        """
        route = gg_api.get("/incidents-for-mcp").respond(200, json={"results": [], "next": None, "previous": None})

        await call_tool(mcp_client, "list_incidents", {"params": filters})

        params = sent_params(route)
        assert {key: params.get(key) for key in expected} == expected


@pytest.mark.parametrize("tool_name", ["list_incidents", "count_incidents"])
class TestSharedIncidentFilters:
    @pytest.mark.parametrize(
        ("filters", "expected_query", "expected_echo"),
        [
            pytest.param(
                {
                    "score_min": 0,
                    "score_max": 0,
                    "occurrence_count_min": 0,
                    "opened_for_days": 0,
                    "assignee_id": 0,
                    "similar_to": 0,
                    "has_related_issues": False,
                    "location": False,
                    "feedback": False,
                    "publicly_shared": False,
                },
                {
                    "score__ge": "0",
                    "score__le": "0",
                    "occurrence_count": ">=0",
                    "opened_for": ">=0",
                    "assignee_member_id": "0",
                    "similar_to": "0",
                    "has_related_issues": "false",
                    "location": "false",
                    "feedback": "false",
                    "publicly_shared": "false",
                },
                {
                    "score_min": 0,
                    "score_max": 0,
                    "assignee_id": 0,
                    "similar_to": 0,
                    "has_related_issues": False,
                    "location": False,
                    "feedback": False,
                    "publicly_shared": False,
                },
                id="zero-and-false",
            ),
            pytest.param(
                {"status": [], "severity": [], "validity": [], "exclude_tags": []},
                {},
                {},
                id="empty-lists-clear-defaults",
            ),
            pytest.param(
                {"severity": ["CRITICAL", "20", 100, "custom"]},
                {"severity__in": "10,20,100,custom"},
                {"severity": ["CRITICAL", "20", 100, "custom"]},
                id="mixed-severity-values",
            ),
        ],
    )
    async def test_filter_edge_cases_preserve_query_and_echo(
        self, mcp_client, gg_api, mock_token_scopes, tool_name, filters, expected_query, expected_echo
    ):
        """
        GIVEN zero, false, empty, or mixed-type filter values
        WHEN either internal incident tool is called
        THEN query serialization and the applied-filter echo retain their existing behavior
        """
        route = gg_api.get(INCIDENT_ENDPOINTS[tool_name]).respond(
            200, json={"results": [], "count": 0, "next": None, "previous": None}
        )

        result = await call_tool(mcp_client, tool_name, {"params": {**NO_DEFAULT_FILTERS, **filters}})

        pagination = {"page": "1", "page_size": "20", "ordering": "-date"} if tool_name == "list_incidents" else {}
        assert sent_params(route) == {**pagination, **expected_query}
        # The existing echo omits zero occurrence/day floors even though the API receives them.
        assert unwrap_result(result)["applied_filters"] == expected_echo

    async def test_mine_conflicting_with_assignee_id_short_circuits(
        self, mcp_client, gg_api, mock_token_scopes, tool_name
    ):
        """
        GIVEN mine=True together with a different explicit assignee_id
        WHEN either internal incident tool is called
        THEN a conflict error is returned and the incidents API is never queried
        """
        gg_api.get(f"/members/{TEST_MEMBER_ID}").respond(200, json={"id": TEST_MEMBER_ID})
        incidents = gg_api.get(INCIDENT_ENDPOINTS[tool_name]).respond(200, json={"results": [], "count": 0})

        result = await call_tool(mcp_client, tool_name, {"params": {"mine": True, "assignee_id": 1}})

        assert tool_error_text(result).startswith(f"Conflict: 'mine=True' implies assignee_id={TEST_MEMBER_ID}")
        assert not incidents.called


@pytest.mark.parametrize("tool_name", ["list_incidents", "count_incidents"])
class TestSharedIncidentErrors:
    async def test_api_rejection_surfaces_as_a_tool_error(self, mcp_client, gg_api, mock_token_scopes, tool_name):
        """
        GIVEN the API rejecting the token with 401
        WHEN either internal incident tool is called
        THEN the call fails with a tool error naming the status
        """
        gg_api.get(INCIDENT_ENDPOINTS[tool_name]).respond(
            status_code=HTTPStatus.UNAUTHORIZED,
            json={"detail": "Invalid API key."},
        )

        result = await call_tool(mcp_client, tool_name, {"params": {}})

        assert str(HTTPStatus.UNAUTHORIZED.value) in tool_error_text(result)


class TestCountIncidents:
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

    async def test_zero_occurrences_is_forwarded_not_dropped(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN with_occurrences=0
        WHEN get_incident is called
        THEN the API is asked for no occurrences explicitly, instead of falling
             back to its default of 20
        """
        route = gg_api.get("/incidents/secrets/77").respond(200, json=INCIDENT)

        await call_tool(mcp_client, "get_incident", {"params": {"incident_id": 77, "with_occurrences": 0}})

        assert sent_params(route) == {"with_occurrences": "0"}


class TestListRepoOccurrences:
    async def test_occurrences_query_and_cursor_pagination(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a source id and a next page advertised via the Link header
        WHEN list_repo_occurrences is called
        THEN the query carries the default noise filters and the decoded cursor
             is handed back with has_more=True
        """
        occurrence = {"id": 9, "incident_id": 77, "filepath": "src/config.py"}
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
        THEN the member id from /api_tokens/self is sent as incident_assignee_id
        """
        route = gg_api.get("/occurrences/secrets").respond(200, json={"results": []})

        await call_tool(mcp_client, "list_repo_occurrences", {"params": {"mine": True}})

        assert sent_params(route)["incident_assignee_id"] == str(TEST_MEMBER_ID)
        assert "member_assignee_id" not in sent_params(route)

    @pytest.mark.parametrize("tool_name", ["list_repo_occurrences"])
    async def test_service_token_without_member_id_rejects_mine_filter(
        self, mcp_client, gg_api, mock_token_scopes, tool_name
    ):
        """
        GIVEN a service-account token whose member_id is null
        WHEN an occurrences tool is called with mine=True
        THEN the tool fails clearly without querying unfiltered occurrences
        """
        gg_api.get("/api_tokens/self").respond(200, json=token_info(member_id=None))
        occurrences = gg_api.get("/occurrences/secrets").respond(200, json={"results": []})

        result = await call_tool(mcp_client, tool_name, {"params": {"mine": True}})

        assert "mine" in tool_error_text(result).lower()
        assert not occurrences.called

    @pytest.mark.parametrize("tool_name", ["list_repo_occurrences"])
    async def test_incident_occurrences_can_be_paged_beyond_100(self, mcp_client, gg_api, mock_token_scopes, tool_name):
        """
        GIVEN an incident with 150 occurrences across two API pages
        WHEN its occurrences are requested with a cursor and all exclusions disabled
        THEN all 150 locations are returned exactly once with the incident scope preserved
        """
        occurrences = [{"id": i, "incident_id": 501, "filepath": f"file{i}.py"} for i in range(150)]
        route = gg_api.get("/occurrences/secrets").mock(
            side_effect=[
                httpx.Response(
                    200,
                    json=occurrences[:100],
                    headers={"Link": '<https://api.gitguardian.com/v1/occurrences/secrets?cursor=next100>; rel="next"'},
                ),
                httpx.Response(200, json=occurrences[100:]),
            ]
        )
        filters = {
            "incident_id": 501,
            "tags": [],
            "exclude_tags": [],
            "status": [],
            "severity": [],
            "validity": [],
            "per_page": 100,
            "get_all": False,
        }
        first = unwrap_result(await call_tool(mcp_client, tool_name, {"params": filters}))
        assert first["has_more"] is True
        assert first["occurrences_count"] == 100
        second = unwrap_result(
            await call_tool(mcp_client, tool_name, {"params": {**filters, "cursor": first["cursor"]}})
        )
        assert second["has_more"] is False
        assert second["cursor"] is None
        assert second["occurrences_count"] == 50
        assert first["occurrences"] + second["occurrences"] == occurrences
        assert second["applied_filters"]["incident_id"] == 501
        assert route.call_count == 2
        for call in route.calls:
            query = call.request.url.params
            assert query["incident_id"] == "501"
            assert query["per_page"] == "100"
            assert not {"source_id", "tags", "exclude_tags", "status", "severity", "validity"}.intersection(query)
        assert route.calls[1].request.url.params["cursor"] == "next100"

    async def test_size_limited_pagination_resumes_without_skipping_a_page(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN three occurrence pages whose pairs exceed the aggregation byte limit
        WHEN get_all results are continued using the returned cursor
        THEN each page is returned once, including pages deferred by the byte limit
        """
        occurrences = [{"id": i, "incident_id": 501, "filepath": "a.py", "content": "x" * 12_000} for i in range(3)]

        def page_response(request):
            index = int(request.url.params.get("cursor", "0"))
            headers = {}
            if index < 2:
                headers["Link"] = f'<https://api.gitguardian.com/v1/occurrences/secrets?cursor={index + 1}>; rel="next"'
            return httpx.Response(200, json=[occurrences[index]], headers=headers)

        gg_api.get("/occurrences/secrets").mock(side_effect=page_response)
        params = {"source_id": 55, "get_all": True}
        returned = []
        for _ in range(3):
            output = unwrap_result(await call_tool(mcp_client, "list_repo_occurrences", {"params": params}))
            returned.extend(output["occurrences"])
            if not output["has_more"]:
                break
            assert output["cursor"] is not None
            params["cursor"] = output["cursor"]

        assert [occ["id"] for occ in returned] == [0, 1, 2]
        assert output["has_more"] is False

    async def test_get_all_stops_when_the_last_page_is_empty(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN an occurrence page followed by an empty terminal page
        WHEN get_all follows the final cursor
        THEN the response clears the cursor and does not advertise more data
        """
        occurrence = {"id": 1, "incident_id": 501, "filepath": "a.py"}
        gg_api.get("/occurrences/secrets").mock(
            side_effect=[
                httpx.Response(
                    200,
                    json=[occurrence],
                    headers={"Link": '<https://api.gitguardian.com/v1/occurrences/secrets?cursor=end>; rel="next"'},
                ),
                httpx.Response(200, json=[]),
            ]
        )

        output = unwrap_result(
            await call_tool(mcp_client, "list_repo_occurrences", {"params": {"source_id": 55, "get_all": True}})
        )

        assert output["occurrences"] == [occurrence]
        assert output["has_more"] is False
        assert output["cursor"] is None

    async def test_date_range_and_presence_are_forwarded(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a date range and a presence filter
        WHEN list_repo_occurrences is called
        THEN both reach the occurrences query unchanged
        """
        route = gg_api.get("/occurrences/secrets").respond(200, json={"results": []})

        await call_tool(
            mcp_client,
            "list_repo_occurrences",
            {"params": {"from_date": "2024-01-01", "to_date": "2024-12-31", "presence": "present"}},
        )

        params = sent_params(route)
        assert params["from_date"] == "2024-01-01"
        assert params["to_date"] == "2024-12-31"
        assert params["presence"] == "present"
