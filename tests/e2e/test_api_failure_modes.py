"""Resilience of the client core (_request) observed through real tool calls:
refusal messages, 500 retries, network failures, and the downstream-401 re-auth bridge.
"""

from http import HTTPStatus

import httpx
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
    THEN the call fails as a tool error giving the status and the API's reason, not as a successful result
    """
    gg_api.get(endpoint).respond(400, json={"detail": "Invalid filter."})

    result = await call_tool(mcp_client, tool_name, {"params": params})

    assert "GitGuardian API returned 400 Bad Request: Invalid filter." in tool_error_text(result)


@pytest.mark.parametrize(("tool_name", "endpoint", "params"), LIST_TOOL_CALLS)
async def test_a_rejected_token_on_a_list_call_triggers_reauthentication(
    mcp_client, gg_api, mock_token_scopes, tool_name, endpoint, params
):
    """
    GIVEN the API rejecting the caller's token with 401 on a list endpoint
    WHEN the list tool is called
    THEN the response asks the MCP client to authenticate again
    """
    gg_api.get(endpoint).respond(HTTPStatus.UNAUTHORIZED, json={"detail": "Invalid API key."})

    response = await rpc(mcp_client, "tools/call", {"name": tool_name, "arguments": {"params": params}})

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert "www-authenticate" in response.headers


ALREADY_IN_STATE_CALLS = [
    pytest.param(
        "assign_incident",
        "/incidents/secrets/77/assign",
        {"incident_id": 77, "assignee_member_id": 4242},
        "Incident already assigned to this user.",
        id="assign",
    ),
    pytest.param(
        "manage_private_incident",
        "/incidents/secrets/77/unassign",
        {"incident_id": 77, "action": "unassign"},
        "Incident not assigned.",
        id="unassign",
    ),
    pytest.param(
        "manage_private_incident",
        "/incidents/secrets/77/resolve",
        {"incident_id": 77, "action": "resolve", "secret_revoked": False},
        "Incident is already resolved.",
        id="resolve",
    ),
    pytest.param(
        "manage_private_incident",
        "/incidents/secrets/77/ignore",
        {"incident_id": 77, "action": "ignore", "ignore_reason": "test_credential"},
        "Incident is already ignored.",
        id="ignore",
    ),
    pytest.param(
        "manage_private_incident",
        "/incidents/secrets/77/reopen",
        {"incident_id": 77, "action": "reopen"},
        "Incident is already open.",
        id="reopen",
    ),
]


class TestRefusalMessages:
    async def test_a_missing_or_out_of_scope_incident_says_retrying_will_not_help(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN the API answering 404 for an incident, as it does for one outside the caller's teams
        WHEN get_incident is called
        THEN the tool error gives the API's reason, both possible causes, and says retrying will not help
        """
        gg_api.get("/incidents/secrets/77").respond(404, json={"detail": "Not found."})

        result = await call_tool(mcp_client, "get_incident", {"params": {"incident_id": 77}})

        text = tool_error_text(result)
        assert "GitGuardian API returned 404 Not Found: Not found." in text
        assert "incidents outside the caller's teams also return 404" in text
        assert "internal and public incident IDs are not interchangeable" in text
        assert "Retrying will not help." in text

    @pytest.mark.parametrize(("tool_name", "endpoint", "params", "detail"), ALREADY_IN_STATE_CALLS)
    async def test_an_incident_already_in_the_requested_state_says_nothing_changed(
        self, mcp_client, gg_api, mock_token_scopes, tool_name, endpoint, params, detail
    ):
        """
        GIVEN the API answering 409 because the incident is already in the requested state
        WHEN the write tool is called
        THEN the tool error gives the API's reason and tells the agent not to retry
        """
        gg_api.post(endpoint).respond(409, json={"detail": detail})

        result = await call_tool(mcp_client, tool_name, {"params": params})

        text = tool_error_text(result)
        assert f"GitGuardian API returned 409 Conflict: {detail}" in text
        assert "Nothing was changed: the incident is already in the requested state. Do not retry." in text

    async def test_a_non_json_refusal_is_reported_without_flooding_the_agent(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN the API answering 403 with a long HTML page instead of JSON
        WHEN get_incident is called
        THEN the tool error names the status and keeps only the start of the page
        """
        gg_api.get("/incidents/secrets/77").respond(403, text="<html>" + "x" * 5000 + "</html>")

        result = await call_tool(mcp_client, "get_incident", {"params": {"incident_id": 77}})

        text = tool_error_text(result)
        assert "GitGuardian API returned 403 Forbidden: <html>xxx" in text
        assert len(text) < 600


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

    @pytest.mark.parametrize("status", [500, 503])
    async def test_a_read_that_fails_once_is_retried(
        self, mcp_client, gg_api, mock_token_scopes, no_retry_delay, status
    ):
        """
        GIVEN the API failing a read once with a transient status
        WHEN get_incident is called
        THEN the read is retried after one second and the tool succeeds
        """
        route = gg_api.get("/incidents/secrets/77").mock(
            side_effect=[httpx.Response(status, text="busy"), httpx.Response(200, json=INCIDENT)]
        )

        result = await call_tool(mcp_client, "get_incident", {"params": {"incident_id": 77}})

        assert route.call_count == 2
        assert not result.get("isError")
        assert no_retry_delay == [1.0]

    async def test_a_rate_limited_read_waits_for_the_apis_retry_after(
        self, mcp_client, gg_api, mock_token_scopes, no_retry_delay
    ):
        """
        GIVEN the API rate-limiting a read with Retry-After: 3
        WHEN get_incident is called
        THEN the read is retried after exactly that delay and the tool succeeds
        """
        route = gg_api.get("/incidents/secrets/77").mock(
            side_effect=[httpx.Response(429, headers={"Retry-After": "3"}), httpx.Response(200, json=INCIDENT)]
        )

        result = await call_tool(mcp_client, "get_incident", {"params": {"incident_id": 77}})

        assert route.call_count == 2
        assert not result.get("isError")
        assert no_retry_delay == [3.0]

    async def test_a_long_retry_after_fails_the_read_at_once(
        self, mcp_client, gg_api, mock_token_scopes, no_retry_delay
    ):
        """
        GIVEN the API rate-limiting a read with a Retry-After longer than the server waits
        WHEN get_incident is called
        THEN the tool fails at once with the 429 instead of holding the call open
        """
        route = gg_api.get("/incidents/secrets/77").respond(
            429, headers={"Retry-After": "60"}, json={"detail": "Throttled."}
        )

        result = await call_tool(mcp_client, "get_incident", {"params": {"incident_id": 77}})

        assert route.call_count == 1
        assert "GitGuardian API returned 429 Too Many Requests: Throttled." in tool_error_text(result)
        assert no_retry_delay == []

    @pytest.mark.parametrize("status", [429, 500, 503])
    async def test_a_failed_write_is_never_retried(self, mcp_client, gg_api, mock_token_scopes, no_retry_delay, status):
        """
        GIVEN the API failing a comment write, which it may have applied before failing
        WHEN manage_incident_comment adds a comment
        THEN the write is sent exactly once, so the comment cannot be posted twice
        """
        route = gg_api.post("/incidents/secrets/77/notes").respond(status, json={"detail": "Unavailable."})

        result = await call_tool(
            mcp_client, "manage_incident_comment", {"params": {"incident_id": 77, "action": "add", "comment": "hi"}}
        )

        assert route.call_count == 1
        assert str(status) in tool_error_text(result)
        assert no_retry_delay == []


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
