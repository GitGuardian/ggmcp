"""Resilience of the client core (_request) observed through real tool calls:
500 retries, network failures, and the downstream-401 re-auth bridge.
"""

import httpx

from tests.e2e.harness import call_tool, rpc, tool_error_text, tool_output

INCIDENT = {"id": 77, "status": "TRIGGERED"}


class TestServerErrorRetries:
    async def test_a_transient_500_is_retried_until_success(
        self, mcp_client, gg_api, mock_token_scopes, no_retry_delay
    ):
        """
        GIVEN the API failing once with 500 then recovering
        WHEN get_incident is called
        THEN the request is retried and the tool succeeds
        """
        route = gg_api.get("/incidents/secrets/77").mock(
            side_effect=[httpx.Response(500, text="boom"), httpx.Response(200, json=INCIDENT)]
        )

        result = await call_tool(mcp_client, "get_incident", {"params": {"incident_id": 77}})

        assert route.call_count == 2
        assert tool_output(result) == {"incident": INCIDENT}

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


class TestNetworkFailures:
    async def test_a_connection_error_surfaces_as_a_tool_error(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN the API being unreachable
        WHEN get_incident is called
        THEN the network failure surfaces as a tool error, not a protocol crash
        """
        gg_api.get("/incidents/secrets/77").mock(side_effect=httpx.ConnectError("connection refused"))

        result = await call_tool(mcp_client, "get_incident", {"params": {"incident_id": 77}})

        assert "connection refused" in tool_error_text(result)

    async def test_a_read_timeout_surfaces_as_a_tool_error(self, mcp_client, gg_api, mock_token_scopes):
        """
        GIVEN the API hanging past the client timeout
        WHEN get_incident is called
        THEN the timeout surfaces as a tool error
        """
        gg_api.get("/incidents/secrets/77").mock(side_effect=httpx.ReadTimeout("timed out"))

        result = await call_tool(mcp_client, "get_incident", {"params": {"incident_id": 77}})

        assert "timed out" in tool_error_text(result)


class TestDownstreamUnauthorizedBridge:
    async def test_a_downstream_401_during_a_tool_call_does_not_reach_the_reauth_bridge(
        self, mcp_client, gg_api, mock_token_scopes
    ):
        """
        GIVEN a token the API rejects with 401 during a scan
        WHEN scan_secrets is called
        THEN the response stays HTTP 200 with a tool error naming the 401,
             and carries no re-auth metadata
        """
        gg_api.post("/multiscan").respond(401, json={"detail": "Invalid API key."})

        response = await rpc(
            mcp_client,
            "tools/call",
            {
                "name": "scan_secrets",
                "arguments": {"params": {"documents": [{"document": "x", "filename": "x.py"}]}},
            },
        )

        # TODO(SI-3891): the re-auth bridge is dead code on this path. FastMCP
        # v3 wraps the tool's DownstreamUnauthorizedError in a ToolError before
        # DownstreamUnauthorizedMiddleware can catch it, so the response is
        # never rewritten to HTTP 401 and clients cannot re-run the OAuth flow.
        assert response.status_code == 200
        assert "www-authenticate" not in response.headers
        result = response.json()["result"]
        assert result["isError"] is True
        assert "401" in result["content"][0]["text"]
