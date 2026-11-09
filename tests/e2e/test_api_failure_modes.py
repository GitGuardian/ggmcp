"""Resilience of the client core (_request) observed through real tool calls:
500 retries, network failures, and the downstream-401 re-auth bridge.
"""

from http import HTTPStatus

import pytest

from tests.e2e.harness import call_tool, rpc, tool_error_text

INCIDENT = {"id": 77, "status": "TRIGGERED"}


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
    @pytest.mark.xfail(
        strict=True,
        reason="SI-3891: FastMCP wraps downstream authorization failures before the reauthentication middleware",
    )
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
