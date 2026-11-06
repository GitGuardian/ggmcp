"""Public Monitoring tools: list_public_incidents, get_public_incident,
list_public_occurrences.

The public endpoints use their own query dialect (plain names, comma-joined
lists, cursor pagination), separate from the internal incidents endpoints.
The tests pin that dialect and the response reshaping.
"""

import httpx
import pytest

from tests.e2e.harness import (
    assert_authenticated_request,
    call_tool,
    sent_params,
    tool_error_text,
    tool_output,
    unwrap_result,
)

PUBLIC_INCIDENT = {"id": 103, "status": "TRIGGERED", "detector": {"name": "slackbot_token"}}
PUBLIC_OCCURRENCE = {"id": 2733, "incident_id": 103, "filepath": "stripe1.py"}

# Turns off the status, severity and validity filters list_public_incidents applies by default.
NO_DEFAULT_FILTERS = {"status": None, "severity": None, "validity": None}


class TestListPublicIncidents:
    async def test_default_call_applies_the_documented_filters(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN no explicit filters
        WHEN list_public_incidents is called
        THEN the API receives the default statuses, severities and validities as
             comma-joined lists, newest first, and the incidents come back counted
        """
        route = gg_api.get("/public-incidents/secrets").respond(200, json=[PUBLIC_INCIDENT])

        result = await call_tool(mcp_client, "list_public_incidents", {"params": {}})

        assert_authenticated_request(route)
        assert sent_params(route) == {
            "per_page": "20",
            "status": "TRIGGERED,ASSIGNED,RESOLVED",
            "severity": "critical,high,medium,unknown",
            "validity": "valid,failed_to_check,no_checker,unknown",
            "ordering": "-date",
        }
        output = unwrap_result(result)
        assert output["incidents"] == [PUBLIC_INCIDENT]
        assert output["incidents_count"] == 1
        assert output["has_more"] is False

    @pytest.mark.parametrize(
        ("filters", "expected"),
        [
            pytest.param(
                {"status": ["TRIGGERED", "ASSIGNED", "RESOLVED", "IGNORED"]},
                {"status": "TRIGGERED,ASSIGNED,RESOLVED,IGNORED"},
                id="status-list",
            ),
            pytest.param(
                {"severity": ["critical", "high", "medium", "low", "info", "unknown"]},
                {"severity": "critical,high,medium,low,info,unknown"},
                id="severity-list",
            ),
            pytest.param(
                {"validity": ["valid", "invalid", "failed_to_check", "no_checker", "unknown"]},
                {"validity": "valid,invalid,failed_to_check,no_checker,unknown"},
                id="validity-list",
            ),
            pytest.param(
                {"date_after": "2024-01-01T00:00:00Z", "date_before": "2026-01-01T00:00:00Z"},
                {"date_after": "2024-01-01T00:00:00Z", "date_before": "2026-01-01T00:00:00Z"},
                id="date-range",
            ),
            pytest.param(
                {"triggered_at_after": "2024-01-01T00:00:00Z", "triggered_at_before": "2026-01-01T00:00:00Z"},
                {"triggered_at_after": "2024-01-01T00:00:00Z", "triggered_at_before": "2026-01-01T00:00:00Z"},
                id="triggered-range",
            ),
            pytest.param(
                {"risk_score_min": 0, "risk_score_max": 100, "ordering": "-risk_score"},
                {"risk_score_min": "0", "risk_score_max": "100", "ordering": "-risk_score"},
                id="zero-risk-floor-is-kept",
            ),
            pytest.param({"assignee_id": 1778296}, {"assignee_id": "1778296"}, id="assignee"),
            pytest.param({"ignorer_id": 492181}, {"ignorer_id": "492181"}, id="ignorer"),
            pytest.param({"resolver_id": 492181}, {"resolver_id": "492181"}, id="resolver"),
            pytest.param({"tags": "FROM_HISTORICAL_SCAN"}, {"tags": "FROM_HISTORICAL_SCAN"}, id="tags"),
            pytest.param(
                {"detector_group_name": "slackbot_token"},
                {"detector_group_name": "slackbot_token"},
                id="detector-group",
            ),
            pytest.param({"feedback": True}, {"feedback": "true"}, id="feedback"),
            pytest.param(
                {"declarative_secret_status": "revoked"},
                {"declarative_secret_status": "revoked"},
                id="declarative-status",
            ),
        ],
    )
    async def test_each_filter_is_forwarded(self, mcp_client, gg_api, mock_token_scopes, filters, expected):
        """
        GIVEN one public-incident filter
        WHEN list_public_incidents is called
        THEN the API receives it under its own name, lists comma-joined
        """
        route = gg_api.get("/public-incidents/secrets").respond(200, json=[])

        await call_tool(mcp_client, "list_public_incidents", {"params": {**NO_DEFAULT_FILTERS, **filters}})

        params = sent_params(route)
        assert {key: params.get(key) for key in expected} == expected

    async def test_cursor_is_forwarded_and_the_next_one_returned(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a cursor from a previous page and a next page advertised via Link
        WHEN list_public_incidents is called with that cursor
        THEN the cursor reaches the API and the next one comes back decoded
        """
        route = gg_api.get("/public-incidents/secrets").respond(
            200,
            json=[PUBLIC_INCIDENT],
            headers={"Link": '<https://api.gitguardian.com/v1/public-incidents/secrets?cursor=cD0y>; rel="next"'},
        )

        result = await call_tool(mcp_client, "list_public_incidents", {"params": {"cursor": "cD0x", "per_page": 1}})

        params = sent_params(route)
        assert params["cursor"] == "cD0x"
        assert params["per_page"] == "1"
        output = unwrap_result(result)
        assert output["cursor"] == "cD0y"
        assert output["has_more"] is True

    async def test_get_all_follows_the_cursor_to_the_last_page(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN two pages linked by a cursor
        WHEN list_public_incidents is called with get_all=True
        THEN the second page is requested with that cursor and both pages come back
        """
        second = {**PUBLIC_INCIDENT, "id": 104}
        route = gg_api.get("/public-incidents/secrets").mock(
            side_effect=[
                httpx.Response(
                    200,
                    json=[PUBLIC_INCIDENT],
                    headers={
                        "Link": '<https://api.gitguardian.com/v1/public-incidents/secrets?cursor=cD01>; rel="next"'
                    },
                ),
                httpx.Response(200, json=[second]),
            ]
        )

        result = await call_tool(mcp_client, "list_public_incidents", {"params": {"get_all": True}})

        assert route.call_count == 2
        assert dict(route.calls[1].request.url.params)["cursor"] == "cD01"
        output = unwrap_result(result)
        assert output["incidents"] == [PUBLIC_INCIDENT, second]
        assert output["has_more"] is False


class TestGetPublicIncident:
    async def test_incident_is_fetched_by_id_and_wrapped(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a public incident id
        WHEN get_public_incident is called
        THEN the public endpoint for that id is read and the incident comes back
             under an "incident" key
        """
        route = gg_api.get("/public-incidents/secrets/103").respond(200, json=PUBLIC_INCIDENT)

        result = await call_tool(mcp_client, "get_public_incident", {"params": {"incident_id": 103}})

        assert_authenticated_request(route)
        assert tool_output(result) == {"incident": PUBLIC_INCIDENT}

    async def test_unknown_incident_surfaces_as_a_tool_error(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN an id the API does not know
        WHEN get_public_incident is called
        THEN the call fails as a tool error that names the 404
        """
        gg_api.get("/public-incidents/secrets/999999999").respond(404, json={"detail": "Not found."})

        result = await call_tool(mcp_client, "get_public_incident", {"params": {"incident_id": 999999999}})

        assert "404" in tool_error_text(result)


class TestListPublicOccurrences:
    async def test_default_call_reads_the_incident_occurrences_newest_first(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN only an incident id
        WHEN list_public_occurrences is called
        THEN that incident's occurrences are read newest first and come back counted
        """
        route = gg_api.get("/public-incidents/secrets/103/occurrences").respond(200, json=[PUBLIC_OCCURRENCE])

        result = await call_tool(mcp_client, "list_public_occurrences", {"params": {"incident_id": 103}})

        assert_authenticated_request(route)
        assert sent_params(route) == {"per_page": "20", "ordering": "-date"}
        output = unwrap_result(result)
        assert output["occurrences"] == [PUBLIC_OCCURRENCE]
        assert output["occurrences_count"] == 1
        assert output["has_more"] is False

    @pytest.mark.parametrize(
        ("filters", "expected"),
        [
            pytest.param({"source_id": 1}, {"source_id": "1"}, id="source"),
            pytest.param({"presence": "present"}, {"presence": "present"}, id="presence"),
            pytest.param({"sha": "7474a92c9f"}, {"sha": "7474a92c9f"}, id="sha"),
            pytest.param({"filepath": "hello.py"}, {"filepath": "hello.py"}, id="filepath"),
            pytest.param(
                {"attachment_reason": "by_dev_from_perimeter,on_github_org_in_perimeter"},
                {"attachment_reason": "by_dev_from_perimeter,on_github_org_in_perimeter"},
                id="attachment-reason",
            ),
            pytest.param({"severity": "critical,high"}, {"severity": "critical,high"}, id="severity"),
            pytest.param({"status": "TRIGGERED,ASSIGNED"}, {"status": "TRIGGERED,ASSIGNED"}, id="status"),
            pytest.param(
                {"validity": "valid,invalid,no_checker"}, {"validity": "valid,invalid,no_checker"}, id="validity"
            ),
            pytest.param(
                {"tags": "FROM_HISTORICAL_SCAN,INTERNALLY_LEAKED"},
                {"tags": "FROM_HISTORICAL_SCAN,INTERNALLY_LEAKED"},
                id="tags",
            ),
            pytest.param(
                {"date_after": "2020-01-01T00:00:00Z"}, {"date_after": "2020-01-01T00:00:00Z"}, id="date-after"
            ),
            pytest.param({"cursor": "cD0x", "per_page": 1}, {"cursor": "cD0x", "per_page": "1"}, id="cursor"),
        ],
    )
    async def test_each_filter_is_forwarded(self, mcp_client, gg_api, mock_token_scopes, filters, expected):
        """
        GIVEN one occurrence filter
        WHEN list_public_occurrences is called
        THEN the API receives it under its own name
        """
        route = gg_api.get("/public-incidents/secrets/103/occurrences").respond(200, json=[])

        await call_tool(mcp_client, "list_public_occurrences", {"params": {"incident_id": 103, **filters}})

        params = sent_params(route)
        assert {key: params.get(key) for key in expected} == expected

    async def test_get_all_follows_the_cursor_to_the_last_page(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN two pages of occurrences linked by a cursor
        WHEN list_public_occurrences is called with get_all=True
        THEN the second page is requested with that cursor and both pages come back
        """
        second = {**PUBLIC_OCCURRENCE, "id": 2734}
        route = gg_api.get("/public-incidents/secrets/103/occurrences").mock(
            side_effect=[
                httpx.Response(
                    200,
                    json=[PUBLIC_OCCURRENCE],
                    headers={
                        "Link": '<https://api.gitguardian.com/v1/public-incidents/secrets/103/occurrences?cursor=cD0x>; rel="next"'
                    },
                ),
                httpx.Response(200, json=[second]),
            ]
        )

        result = await call_tool(
            mcp_client, "list_public_occurrences", {"params": {"incident_id": 103, "get_all": True}}
        )

        assert route.call_count == 2
        assert dict(route.calls[1].request.url.params)["cursor"] == "cD0x"
        output = unwrap_result(result)
        assert output["occurrences"] == [PUBLIC_OCCURRENCE, second]
        assert output["has_more"] is False
