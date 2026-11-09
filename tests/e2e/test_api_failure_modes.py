"""Resilience of the client core (_request) observed through real tool calls:
500 retries, network failures, and the downstream-401 re-auth bridge.
"""

from http import HTTPStatus

import pytest

from tests.e2e.harness import call_tool, rpc, tool_error_text

INCIDENT = {"id": 77, "status": "TRIGGERED"}


LIST_TOOL_CALLS = [
    pytest.param("list_incidents", "/incidents-for-mcp", {}, id="list_incidents"),
    pytest.param("count_incidents", "/incidents-for-mcp/count", {}, id="count_incidents"),
    pytest.param("list_repo_occurrences", "/occurrences/secrets", {"source_id": 1}, id="list_repo_occurrences"),
    pytest.param("list_public_incidents", "/public-incidents/secrets", {}, id="list_public_incidents"),
    pytest.param(
        "list_public_occurrences",
        "/public-incidents/secrets/103/occurrences",
        {"incident_id": 103},
        id="list_public_occurrences",
    ),
]


@pytest.mark.parametrize(("tool_name", "endpoint", "params"), LIST_TOOL_CALLS)
async def test_a_rejected_list_query_surfaces_as_a_tool_error(
    mcp_client, gg_api, mock_token_scopes, tool_name, endpoint, params
):
    """
    GIVEN the API rejecting a list query with 400
    WHEN the list tool is called
    THEN the call fails as a tool error naming the status, not as a successful result
    """
    gg_api.get(endpoint).respond(400, json={"detail": "Invalid filter."})

    result = await call_tool(mcp_client, tool_name, {"params": params})

    assert "400" in tool_error_text(result)


class TestServerErrorRetries:
    async def test_persistent_500s_fail_after_three_retries(
        self, mcp_client, gg_api, mock_token_scopes, no_retry_delay
    ):
        """
        GIVEN the API failing with 500 on every attempt
        WHEN get_incident is called
        THEN exactly four requests are made (initial + 3 retries) and the tool fails
        """
        route = gg_api.get("/incidents/secrets/77").respond(500, text="boom")

        result = await call_tool(mcp_client, "get_incident", {"params": {"incident_id": 77}})

        assert route.call_count == 4
        assert "500" in tool_error_text(result)


class TestDownstreamUnauthorizedBridge:
    async def test_a_downstream_401_during_a_tool_call_triggers_reauthentication(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN a token the API rejects with 401 during a scan
        WHEN scan_secrets is called
        THEN the response asks the MCP client to authenticate again
        """
        gg_api.post("/multiscan").respond(
            status_code=HTTPStatus.UNAUTHORIZED,
            json={"detail": "Invalid API key."},
        )

        response = await rpc(
            mcp_client,
            "tools/call",
            {
                "name": "scan_secrets",
                "arguments": {"params": {"documents": [{"document": "x", "filename": "x.py"}]}},
            },
        )

        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert "www-authenticate" in response.headers
