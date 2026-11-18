"""Resilience of the client core (_request) observed through real tool calls:
refusal messages, 500 retries, network failures, and the downstream-401 re-auth bridge.
"""

import logging
from http import HTTPStatus

import httpx
import pytest

from tests.e2e.harness import call_tool, rpc, tool_error_text

INCIDENT = {"id": 77, "status": "TRIGGERED"}


LIST_TOOL_CALLS = [
    pytest.param("list_internal_incidents", "/incidents-for-mcp", {}, id="list_internal_incidents"),
    pytest.param("count_internal_incidents", "/incidents-for-mcp/count", {}, id="count_internal_incidents"),
    pytest.param("list_internal_occurrences", "/occurrences/secrets", {"source_id": 1}, id="list_internal_occurrences"),
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

    result = await call_tool(mcp_client, tool_name, params)

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

    response = await rpc(mcp_client, "tools/call", {"name": tool_name, "arguments": params})

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert "www-authenticate" in response.headers


ALREADY_IN_STATE_CALLS = [
    pytest.param(
        "assign_internal_incident",
        "/incidents/secrets/77/assign",
        {"incident_id": 77, "assignee_member_id": 4242},
        "Incident already assigned to this user.",
        id="assign",
    ),
    pytest.param(
        "unassign_internal_incident",
        "/incidents/secrets/77/unassign",
        {"incident_id": 77},
        "Incident not assigned.",
        id="unassign",
    ),
    pytest.param(
        "resolve_internal_incident",
        "/incidents/secrets/77/resolve",
        {"incident_id": 77, "secret_revoked": False},
        "Incident is already resolved.",
        id="resolve",
    ),
    pytest.param(
        "ignore_internal_incident",
        "/incidents/secrets/77/ignore",
        {"incident_id": 77, "ignore_reason": "test_credential"},
        "Incident is already ignored.",
        id="ignore",
    ),
    pytest.param(
        "reopen_internal_incident",
        "/incidents/secrets/77/reopen",
        {"incident_id": 77},
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
        WHEN get_internal_incident is called
        THEN the tool error gives the API's reason, both possible causes, and says retrying will not help
        """
        gg_api.get("/incidents/secrets/77").respond(404, json={"detail": "Not found."})

        result = await call_tool(mcp_client, "get_internal_incident", {"incident_id": 77})

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

        result = await call_tool(mcp_client, tool_name, params)

        text = tool_error_text(result)
        assert f"GitGuardian API returned 409 Conflict: {detail}" in text
        assert "Nothing was changed: the incident is already in the requested state. Do not retry." in text

    async def test_a_non_json_refusal_is_reported_without_flooding_the_agent(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN the API answering 403 with a long HTML page instead of JSON
        WHEN get_internal_incident is called
        THEN the tool error names the status and keeps only the start of the page
        """
        gg_api.get("/incidents/secrets/77").respond(403, text="<html>" + "x" * 5000 + "</html>")

        result = await call_tool(mcp_client, "get_internal_incident", {"incident_id": 77})

        text = tool_error_text(result)
        assert "GitGuardian API returned 403 Forbidden: <html>xxx" in text
        assert len(text) < 600


class TestServerErrorRetries:
    async def test_persistent_500s_fail_after_three_retries(
        self, mcp_client, gg_api, mock_token_scopes, no_retry_delay
    ):
        """
        GIVEN the API failing with 500 on every attempt
        WHEN get_internal_incident is called
        THEN exactly four requests are made (initial + 3 retries) and the tool fails
        """
        route = gg_api.get("/incidents/secrets/77").respond(500, text="boom")

        result = await call_tool(mcp_client, "get_internal_incident", {"incident_id": 77})

        assert route.call_count == 4
        assert "500" in tool_error_text(result)

    @pytest.mark.parametrize("status", [500, 502, 503, 504])
    async def test_a_read_that_fails_once_is_retried(
        self, mcp_client, gg_api, mock_token_scopes, no_retry_delay, status
    ):
        """
        GIVEN the API failing a read once with a transient status
        WHEN get_internal_incident is called
        THEN the read is retried after one second and the tool succeeds
        """
        route = gg_api.get("/incidents/secrets/77").mock(
            side_effect=[httpx.Response(status, text="busy"), httpx.Response(200, json=INCIDENT)]
        )

        result = await call_tool(mcp_client, "get_internal_incident", {"incident_id": 77})

        assert route.call_count == 2
        assert not result.get("isError")
        assert no_retry_delay == [1.0]

    async def test_a_rate_limited_read_waits_for_the_apis_retry_after(
        self, mcp_client, gg_api, mock_token_scopes, no_retry_delay
    ):
        """
        GIVEN the API rate-limiting a read with Retry-After: 3
        WHEN get_internal_incident is called
        THEN the read is retried after exactly that delay and the tool succeeds
        """
        route = gg_api.get("/incidents/secrets/77").mock(
            side_effect=[httpx.Response(429, headers={"Retry-After": "3"}), httpx.Response(200, json=INCIDENT)]
        )

        result = await call_tool(mcp_client, "get_internal_incident", {"incident_id": 77})

        assert route.call_count == 2
        assert not result.get("isError")
        assert no_retry_delay == [3.0]

    async def test_a_long_retry_after_fails_the_read_at_once(
        self, mcp_client, gg_api, mock_token_scopes, no_retry_delay
    ):
        """
        GIVEN the API rate-limiting a read with a Retry-After longer than the server waits
        WHEN get_internal_incident is called
        THEN the tool fails at once with the 429 instead of holding the call open
        """
        route = gg_api.get("/incidents/secrets/77").respond(
            429, headers={"Retry-After": "60"}, json={"detail": "Throttled."}
        )

        result = await call_tool(mcp_client, "get_internal_incident", {"incident_id": 77})

        assert route.call_count == 1
        assert "GitGuardian API returned 429 Too Many Requests: Throttled." in tool_error_text(result)
        assert no_retry_delay == []

    async def test_a_read_that_times_out_once_is_retried(self, mcp_client, gg_api, mock_token_scopes, no_retry_delay):
        """
        GIVEN a read that times out once, then answers
        WHEN get_internal_incident is called
        THEN the read is repeated at once and the tool succeeds
        """
        route = gg_api.get("/incidents/secrets/77").mock(
            side_effect=[httpx.ReadTimeout("timed out"), httpx.Response(200, json=INCIDENT)]
        )

        result = await call_tool(mcp_client, "get_internal_incident", {"incident_id": 77})

        assert route.call_count == 2
        assert not result.get("isError")
        assert no_retry_delay == []

    async def test_a_read_that_keeps_timing_out_is_retried_only_once(
        self, mcp_client, gg_api, mock_token_scopes, no_retry_delay
    ):
        """
        GIVEN a read that times out on every attempt
        WHEN get_internal_incident is called
        THEN it is tried twice in all, and the timeout reaches the agent
        """
        route = gg_api.get("/incidents/secrets/77").mock(side_effect=httpx.ReadTimeout("timed out"))

        result = await call_tool(mcp_client, "get_internal_incident", {"incident_id": 77})

        assert route.call_count == 2
        assert "timed out" in tool_error_text(result)

    async def test_a_write_that_times_out_is_never_retried(self, mcp_client, gg_api, mock_token_scopes, no_retry_delay):
        """
        GIVEN a comment write that times out, which the API may still have applied
        WHEN add_internal_incident_comment adds a comment
        THEN the write is sent exactly once
        """
        route = gg_api.post("/incidents/secrets/77/notes").mock(side_effect=httpx.ReadTimeout("timed out"))

        result = await call_tool(mcp_client, "add_internal_incident_comment", {"incident_id": 77, "comment": "hi"})

        assert route.call_count == 1
        assert "timed out" in tool_error_text(result)

    @pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
    async def test_a_failed_write_is_never_retried(self, mcp_client, gg_api, mock_token_scopes, no_retry_delay, status):
        """
        GIVEN the API failing a comment write, which it may have applied before failing
        WHEN add_internal_incident_comment adds a comment
        THEN the write is sent exactly once, so the comment cannot be posted twice
        """
        route = gg_api.post("/incidents/secrets/77/notes").respond(status, json={"detail": "Unavailable."})

        result = await call_tool(mcp_client, "add_internal_incident_comment", {"incident_id": 77, "comment": "hi"})

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
                "arguments": {"documents": [{"document": "x", "filename": "x.py"}]},
            },
        )

        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert "www-authenticate" in response.headers

    async def test_the_oauth_proxy_challenge_still_names_its_metadata(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN the OAuth proxy deployment and a token the API rejects
        WHEN a tool is called
        THEN the 401 challenge still points at the authorization metadata, not a bare invalid_token
        """
        gg_api.get("/sources").respond(status_code=HTTPStatus.UNAUTHORIZED, json={"detail": "Invalid API key."})

        response = await rpc(mcp_client, "tools/call", {"name": "list_sources", "arguments": {}})

        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert "resource_metadata=" in response.headers["www-authenticate"]


class TestRawBearerRejectedToken:
    """Raw-bearer mode (no OAuth proxy): each request brings its own PAT."""

    async def test_a_token_the_api_rejects_gets_a_401_on_a_tool_call(
        self, raw_bearer_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN a raw-bearer server and a PAT the API rejects with 401
        WHEN a tool is called
        THEN the HTTP status is 401 with an invalid_token challenge, as for a missing token
        """
        gg_api.get("/sources").respond(status_code=HTTPStatus.UNAUTHORIZED, json={"detail": "Invalid API key."})

        response = await rpc(raw_bearer_client, "tools/call", {"name": "list_sources", "arguments": {}})

        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert response.headers["www-authenticate"] == 'Bearer error="invalid_token"'

    async def test_a_token_the_api_rejects_gets_a_401_on_tools_list(self, raw_bearer_client, gg_api):
        """
        GIVEN a raw-bearer server and a PAT the API rejects when its scopes are looked up
        WHEN the tools are listed
        THEN the HTTP status is 401
        """
        gg_api.get("/api_tokens/self").respond(status_code=HTTPStatus.UNAUTHORIZED, json={"detail": "Invalid API key."})

        response = await rpc(raw_bearer_client, "tools/list", {})

        assert response.status_code == HTTPStatus.UNAUTHORIZED

    async def test_a_valid_token_is_unaffected(self, raw_bearer_client, gg_api, mock_token_scopes):
        """
        GIVEN a raw-bearer server and a valid PAT
        WHEN a tool is called
        THEN it answers 200 with no challenge
        """
        gg_api.get("/sources").respond(200, json=[])

        response = await rpc(raw_bearer_client, "tools/call", {"name": "list_sources", "arguments": {}})

        assert response.status_code == HTTPStatus.OK
        assert "www-authenticate" not in response.headers


class TestRedirects:
    async def test_a_same_origin_redirect_on_a_read_is_followed(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN the API answers list_sources with a 301 to another path on its own origin
        WHEN list_sources is called
        THEN the redirect is followed and the sources are returned
        """
        gg_api.get("/sources").respond(301, headers={"Location": "https://api.gitguardian.com/v1/sources/"})
        moved = gg_api.get("/sources/").respond(200, json=[{"id": 9, "full_name": "acme/app"}])

        result = await call_tool(mcp_client, "list_sources", {})

        assert moved.called
        assert "acme/app" in str(result)

    async def test_a_cross_origin_redirect_never_receives_the_scanned_documents(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN the API answers a scan with a 307 to another host
        WHEN scan_secrets is called
        THEN the tool fails naming the redirect, and the other host never receives the documents
        """
        gg_api.post("/multiscan").respond(307, headers={"Location": "https://collector.example/collect"})
        collector = gg_api.post("https://collector.example/collect").respond(200, json=[])

        result = await call_tool(
            mcp_client, "scan_secrets", {"documents": [{"document": "x = 1\n", "filename": "a.py"}]}
        )

        assert "redirect" in tool_error_text(result).lower()
        assert not collector.called


class TestOneRecordPerFailure:
    async def test_an_api_refusal_logs_no_error_and_no_traceback(self, mcp_client, gg_api, mock_token_scopes, caplog):
        """
        GIVEN the API refusing get_internal_incident with a 404
        WHEN the tool is called
        THEN nothing is logged at ERROR, no record carries a traceback, and tool_call_failed is a warning
        """
        gg_api.get("/incidents/secrets/77").respond(404, json={"detail": "Not found."})

        with caplog.at_level(logging.WARNING):
            await call_tool(mcp_client, "get_internal_incident", {"incident_id": 77})

        assert [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR] == []
        assert [r.getMessage() for r in caplog.records if r.exc_info] == []
        (failed,) = [r for r in caplog.records if r.getMessage() == "tool_call_failed"]
        assert failed.levelno == logging.WARNING

    async def test_a_token_rejected_by_the_scope_check_gets_a_401_and_logs_no_error(self, mcp_client, gg_api, caplog):
        """
        GIVEN a token the API rejects with 401 when a tool call looks up its scopes
        WHEN list_sources is called
        THEN the client gets the 401 challenge, nothing is logged at ERROR, and tool_call_failed is a warning
        """
        gg_api.get("/api_tokens/self").respond(status_code=HTTPStatus.UNAUTHORIZED, json={"detail": "Invalid API key."})
        sources_route = gg_api.get("/sources").respond(200, json=[])

        with caplog.at_level(logging.WARNING):
            response = await rpc(mcp_client, "tools/call", {"name": "list_sources", "arguments": {}})

        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert "resource_metadata=" in response.headers["www-authenticate"]
        assert not sources_route.called
        assert [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR] == []
        (failed,) = [r for r in caplog.records if r.getMessage() == "tool_call_failed"]
        assert failed.levelno == logging.WARNING

    async def test_a_scope_refusal_is_logged_once_as_a_failed_call(self, mcp_client, gg_api, mock_token_scopes, caplog):
        """
        GIVEN a scan-only token
        WHEN a client calls a tool that needs incidents:write
        THEN the refusal is logged once, as a tool_call_failed warning
        """
        mock_token_scopes(["scan"])

        with caplog.at_level(logging.WARNING):
            await call_tool(mcp_client, "reopen_internal_incident", {"incident_id": 77})

        outcomes = [r for r in caplog.records if r.getMessage().startswith("tool_call")]
        assert [(r.getMessage(), r.levelno) for r in outcomes] == [("tool_call_failed", logging.WARNING)]

    async def test_a_scope_refusal_records_the_missing_scopes(self, mcp_client, gg_api, mock_token_scopes, caplog):
        """
        GIVEN a token with incidents:read but not incidents:write
        WHEN a client calls a tool that needs incidents:write
        THEN the tool_call_failed record lists incidents:write in missing_scopes
        """
        mock_token_scopes(["scan", "incidents:read"])

        with caplog.at_level(logging.WARNING):
            await call_tool(mcp_client, "assign_internal_incident", {"incident_id": 77, "mine": True})

        (failed,) = [r for r in caplog.records if r.getMessage() == "tool_call_failed"]
        assert failed.missing_scopes == ["incidents:write"]
        assert failed.failure_kind == "expected"

    @pytest.mark.parametrize(
        ("tool", "arguments"),
        [
            pytest.param("get_internal_incident", {"params": {"incident_id": 77}}, id="bad-arguments"),
            pytest.param("resolve_internal_incident", {"incident_id": 77}, id="deliberate-refusal"),
            pytest.param(
                "get_gitguardian_resource", {"url": "https://[invalid/workspace/1/incidents/77"}, id="bad-link"
            ),
        ],
    )
    async def test_a_mistake_the_caller_can_fix_is_their_fault_and_no_error(
        self, mcp_client, gg_api, mock_token_scopes, caplog, tool, arguments
    ):
        """
        GIVEN a call refused before any API answer: invalid arguments, a missing decision, a malformed link
        WHEN the tool is called
        THEN tool_call_failed is a warning marked expected and fault=client, and nothing is logged at ERROR
        """
        with caplog.at_level(logging.WARNING):
            await call_tool(mcp_client, tool, arguments)

        (failed,) = [r for r in caplog.records if r.getMessage() == "tool_call_failed"]
        assert (failed.levelno, failed.failure_kind, failed.fault) == (logging.WARNING, "expected", "client")
        assert [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR] == []

    async def test_an_unexpected_failure_logs_one_traceback(
        self, mcp_client, gg_api, mock_token_scopes, no_retry_delay, caplog
    ):
        """
        GIVEN the API failing get_internal_incident with a 500 on every retry
        WHEN the tool is called
        THEN exactly one record carries the traceback: the tool_call_failed error
        """
        gg_api.get("/incidents/secrets/77").respond(500, json={"detail": "boom"})

        with caplog.at_level(logging.WARNING):
            await call_tool(mcp_client, "get_internal_incident", {"incident_id": 77})

        with_traceback = [r for r in caplog.records if r.exc_info]
        assert [(r.getMessage(), r.levelno) for r in with_traceback] == [("tool_call_failed", logging.ERROR)]
