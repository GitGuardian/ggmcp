"""list_internal_incident_locations and create_internal_incident_code_fix_request.

Locations are where an internal incident's secret still is, and code fix requests open
pull requests on customer repositories, so the tests pin the query and the exact body.
"""

import httpx
import pytest

from tests.e2e.harness import call_tool, sent_body, sent_params, tool_error_text, tool_output

LOCATIONS = "/incidents/secrets/42/locations"
LOCATION = {
    "id": 501,
    "incident_id": 42,
    "filepath": "config/settings.py",
    "matches": [{"name": "password", "line_start": 3, "line_end": 3}],
    "remediation_prs": [],
}


class TestListInternalIncidentLocations:
    async def test_locations_are_listed_with_the_filters_and_the_pagination_contract(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN an incident whose locations span two pages
        WHEN list_internal_incident_locations is called with a source, active and a search
        THEN the filters reach the API under its names, and next_arguments resume with them
        """
        route = gg_api.get(LOCATIONS).respond(
            200,
            json=[LOCATION],
            headers={"Link": f'<https://api.gitguardian.com/v1{LOCATIONS}?cursor=cD0x>; rel="next"'},
        )

        result = await call_tool(
            mcp_client,
            "list_internal_incident_locations",
            {"incident_id": 42, "source_id": 7, "active": True, "search": "config", "page_size": 1},
        )

        assert sent_params(route) == {"source": "7", "active": "true", "search": "config", "per_page": "1"}
        output = tool_output(result)
        assert output["locations"] == [LOCATION]
        assert output["next_arguments"] == {
            "incident_id": 42,
            "source_id": 7,
            "active": True,
            "search": "config",
            "page_size": 1,
            "cursor": "cD0x",
        }


class TestCreateInternalIncidentCodeFixRequest:
    async def test_a_request_sends_the_incident_and_its_locations(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN two locations of an incident
        WHEN create_internal_incident_code_fix_request is called
        THEN /code-fix-requests receives that incident with exactly those locations, and the result names them
        """
        route = gg_api.post("/code-fix-requests").respond(201, json={"message": "1 code fix request created"})

        result = await call_tool(
            mcp_client, "create_internal_incident_code_fix_request", {"incident_id": 42, "location_ids": [501, 502]}
        )

        assert sent_body(route) == {"locations": [{"issue_id": 42, "location_ids": [501, 502]}]}
        assert tool_output(result) == {
            "incident_kind": "internal",
            "incident_id": 42,
            "location_ids": [501, 502],
            "response": {"message": "1 code fix request created"},
        }

    async def test_a_request_without_locations_is_refused(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN no location IDs
        WHEN create_internal_incident_code_fix_request is called
        THEN the call is refused naming location_ids, and no request is created
        """
        route = gg_api.post("/code-fix-requests").respond(201, json={})

        result = await call_tool(
            mcp_client, "create_internal_incident_code_fix_request", {"incident_id": 42, "location_ids": []}
        )

        assert "location_ids" in tool_error_text(result)
        assert not route.called

    async def test_the_apis_refusal_is_passed_on(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN a workspace where the API refuses code fixes with a 400
        WHEN create_internal_incident_code_fix_request is called
        THEN the error carries the API's reason and does not suggest the request may have gone through
        """
        gg_api.post("/code-fix-requests").respond(400, json={"detail": "Code fix is not enabled for this workspace."})

        result = await call_tool(
            mcp_client, "create_internal_incident_code_fix_request", {"incident_id": 42, "location_ids": [501]}
        )

        text = tool_error_text(result)
        assert "Code fix is not enabled" in text
        assert "may or may not have been applied" not in text

    @pytest.mark.parametrize(
        "failure",
        [
            pytest.param(httpx.ReadTimeout("timed out"), id="timeout"),
            pytest.param(httpx.Response(502, json={"detail": "Bad gateway."}), id="server-error"),
        ],
    )
    async def test_an_unknown_outcome_says_where_to_check(
        self, mcp_client, gg_api, mock_token_scopes, no_retry_delay, failure
    ):
        """
        GIVEN a code fix request that times out or gets a server error
        WHEN create_internal_incident_code_fix_request is called
        THEN it is sent once, and the error says to check the locations' pull requests before asking again
        """
        route = gg_api.post("/code-fix-requests")
        if isinstance(failure, httpx.Response):
            route.mock(return_value=failure)
        else:
            route.mock(side_effect=failure)

        result = await call_tool(
            mcp_client, "create_internal_incident_code_fix_request", {"incident_id": 42, "location_ids": [501]}
        )

        text = tool_error_text(result)
        assert route.call_count == 1
        assert "may or may not have been applied" in text
        assert "list_internal_incident_locations" in text
