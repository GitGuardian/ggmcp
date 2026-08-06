import json
import logging
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
import structlog
from fastmcp import Client
from fastmcp.tools import ToolResult
from gg_api_core.log_context import clear_caller_identity_cache, record_downstream_call, record_truncation
from gg_api_core.logging_config import configure_logging
from gg_api_core.mcp_server import get_mcp_server
from gg_api_core.middleware import RequestLoggingContextMiddleware, ToolCallLoggingMiddleware
from mcp.types import TextContent

TOKEN_INFO = {
    "id": "tok-uuid",
    "type": "personal_access_token",
    "scopes": ["scan", "incidents:read"],
    "member_id": 480870,
    "workspace_id": 8,
}


def _ctx(name, arguments=None):
    return SimpleNamespace(message=SimpleNamespace(name=name, arguments=arguments))


def _message_ctx(message=None, session_id=None, method="tools/list"):
    """A middleware context shaped like the fields the middleware reads."""
    fastmcp_context = SimpleNamespace(session_id=session_id) if session_id else None
    return SimpleNamespace(message=message, fastmcp_context=fastmcp_context, method=method)


class FakeServer:
    """Stands in for AbstractGitGuardianFastMCP's identity-resolution surface."""

    authentication_mode = SimpleNamespace(value="TEST")

    def __init__(self, token="tok-a", token_info=None):
        self._token = token
        self._token_info = TOKEN_INFO if token_info is None else token_info
        self.token_info_calls = 0

    def get_personal_access_token(self):
        return self._token

    async def get_token_info(self):
        self.token_info_calls += 1
        if isinstance(self._token_info, Exception):
            raise self._token_info
        return self._token_info


@pytest.fixture(autouse=True)
def _clean_identity_cache():
    clear_caller_identity_cache(all_tokens=True)
    yield
    clear_caller_identity_cache(all_tokens=True)


class TestToolCallLoggingMiddleware:
    async def test_logs_successful_call(self, caplog):
        """
        GIVEN a tool call that succeeds
        WHEN the call is handled
        THEN a tool_call record carries the tool, status and elapsed time
        """

        async def call_next(ctx):
            return "result"

        with caplog.at_level(logging.INFO, logger="gg_api_core.middleware"):
            result = await ToolCallLoggingMiddleware().on_call_tool(
                _ctx("get_incident", {"incident_id": "123"}), call_next
            )

        assert result == "result"
        rec = next(r for r in caplog.records if r.getMessage() == "tool_call")
        assert rec.tool == "get_incident"
        assert rec.status == "ok"
        assert isinstance(rec.elapsed_ms, int)

    async def test_logs_and_reraises_on_failure(self, caplog):
        """
        GIVEN a tool call that raises
        WHEN the call is handled
        THEN a tool_call_failed record is emitted and the error propagates
        """

        async def call_next(ctx):
            raise ValueError("boom")

        with caplog.at_level(logging.ERROR, logger="gg_api_core.middleware"):
            with pytest.raises(ValueError, match="boom"):
                await ToolCallLoggingMiddleware().on_call_tool(_ctx("scan_secrets"), call_next)

        rec = next(r for r in caplog.records if r.getMessage() == "tool_call_failed")
        assert rec.tool == "scan_secrets"
        assert rec.exc_info is not None

    async def test_pins_the_arguments_shape_when_none_are_sent(self, caplog):
        """
        GIVEN a tool call with no arguments
        WHEN it is logged
        THEN `arguments` is an empty mapping, not None
        """

        async def call_next(ctx):
            return ToolResult(content=[])

        with caplog.at_level(logging.INFO, logger="gg_api_core.middleware"):
            await ToolCallLoggingMiddleware().on_call_tool(_ctx("list_detectors", None), call_next)

        rec = next(r for r in caplog.records if r.getMessage() == "tool_call")
        assert rec.arguments == {}

    async def test_records_the_size_of_what_the_model_receives(self, caplog):
        """
        GIVEN a tool returning text content and a list of rows
        WHEN the call is logged
        THEN response size and item count are reported
        """

        async def call_next(ctx):
            return ToolResult(
                content=[TextContent(type="text", text='{"data": [1, 2, 3]}')],
                structured_content={"data": [1, 2, 3]},
            )

        with caplog.at_level(logging.INFO, logger="gg_api_core.middleware"):
            await ToolCallLoggingMiddleware().on_call_tool(_ctx("list_incidents"), call_next)

        rec = next(r for r in caplog.records if r.getMessage() == "tool_call")
        assert rec.result_bytes == len('{"data": [1, 2, 3]}')
        assert rec.result_items == 3
        assert rec.result_blocks == 1

    async def test_splits_downstream_time_out_of_elapsed(self, caplog):
        """
        GIVEN a tool that makes two GitGuardian API calls
        WHEN the call is logged
        THEN downstream call count and time are reported separately
        """

        async def call_next(ctx):
            record_downstream_call(duration_ms=30.0, status=200)
            record_downstream_call(duration_ms=12.0, status=200)
            return ToolResult(content=[])

        with caplog.at_level(logging.INFO, logger="gg_api_core.middleware"):
            await ToolCallLoggingMiddleware().on_call_tool(_ctx("get_incident"), call_next)

        rec = next(r for r in caplog.records if r.getMessage() == "tool_call")
        assert rec.downstream_calls == 2
        assert rec.downstream_ms == 42
        assert rec.downstream_statuses == [200]

    async def test_flags_a_clipped_response(self, caplog):
        """
        GIVEN a tool whose pagination hit the byte cap
        WHEN the call is logged
        THEN the line is flagged as truncated
        """

        async def call_next(ctx):
            record_truncation()
            return ToolResult(content=[])

        with caplog.at_level(logging.INFO, logger="gg_api_core.middleware"):
            await ToolCallLoggingMiddleware().on_call_tool(_ctx("list_incidents"), call_next)

        rec = next(r for r in caplog.records if r.getMessage() == "tool_call")
        assert rec.truncated is True

    async def test_grades_the_failure_on_the_failed_line(self, caplog):
        """
        GIVEN a tool failing with a wrapped GitGuardian 400
        WHEN the failure is logged
        THEN status, fault and error class are fields on that same line
        """
        request = httpx.Request("GET", "https://api.gitguardian.com/v1/incidents/secrets")
        response = httpx.Response(400, json={"code": "invalid_severity"}, request=request)

        async def call_next(ctx):
            raise httpx.HTTPStatusError("bad request", request=request, response=response)

        with caplog.at_level(logging.ERROR, logger="gg_api_core.middleware"):
            with pytest.raises(httpx.HTTPStatusError):
                await ToolCallLoggingMiddleware().on_call_tool(_ctx("list_incidents"), call_next)

        rec = next(r for r in caplog.records if r.getMessage() == "tool_call_failed")
        assert rec.upstream_status == 400
        assert rec.fault == "client"
        assert rec.gg_error_code == "invalid_severity"
        assert rec.error_class == "httpx.HTTPStatusError"

    async def test_downstream_stats_do_not_leak_between_calls(self, caplog):
        """
        GIVEN one tool call that made a downstream request
        WHEN a second call makes none
        THEN the second line reports zero downstream calls
        """

        async def call_next_with_downstream(ctx):
            record_downstream_call(duration_ms=10.0, status=200)
            return ToolResult(content=[])

        async def call_next_without(ctx):
            return ToolResult(content=[])

        middleware = ToolCallLoggingMiddleware()
        with caplog.at_level(logging.INFO, logger="gg_api_core.middleware"):
            await middleware.on_call_tool(_ctx("get_incident"), call_next_with_downstream)
            await middleware.on_call_tool(_ctx("list_detectors"), call_next_without)

        first, second = (r for r in caplog.records if r.getMessage() == "tool_call")
        assert first.downstream_calls == 1
        assert second.downstream_calls == 0


class TestRequestLoggingContextMiddleware:
    async def test_binds_request_id_and_clears_after(self):
        """
        GIVEN an MCP message without a request ID
        WHEN the message is handled
        THEN a request ID is bound only for that message
        """
        seen: dict = {}

        async def call_next(ctx):
            seen.update(structlog.contextvars.get_contextvars())
            return "ok"

        result = await RequestLoggingContextMiddleware(FakeServer()).on_message(_message_ctx(), call_next)

        assert result == "ok"
        assert seen["request_id"]
        assert "request_id" not in structlog.contextvars.get_contextvars()

    async def test_prefers_inbound_x_request_id_header(self, monkeypatch):
        """
        GIVEN an MCP message with an X-Request-ID header
        WHEN the message is handled
        THEN the inbound request ID is bound
        """
        seen: dict = {}

        async def call_next(ctx):
            seen.update(structlog.contextvars.get_contextvars())
            return "ok"

        monkeypatch.setattr("gg_api_core.middleware.get_http_headers", lambda: {"x-request-id": "trace-123"})
        await RequestLoggingContextMiddleware(FakeServer()).on_message(_message_ctx(), call_next)

        assert seen["request_id"] == "trace-123"

    @pytest.mark.parametrize("inbound", ["trace 123", "trace\nforged", "x" * 65, ""])
    async def test_rejects_unsafe_inbound_request_id(self, monkeypatch, inbound):
        """
        GIVEN an X-Request-ID that is unsafe to stamp on every log line
        WHEN the message is handled
        THEN a fresh id is minted instead of adopting it
        """
        seen: dict = {}

        async def call_next(ctx):
            seen.update(structlog.contextvars.get_contextvars())
            return "ok"

        monkeypatch.setattr("gg_api_core.middleware.get_http_headers", lambda: {"x-request-id": inbound})
        await RequestLoggingContextMiddleware(FakeServer()).on_message(_message_ctx(), call_next)

        assert seen["request_id"] != inbound
        uuid.UUID(seen["request_id"])

    async def test_binds_caller_identity_and_session_and_user_agent(self, monkeypatch):
        """
        GIVEN a message from an authenticated caller over HTTP
        WHEN the message is handled
        THEN account, workspace, member, token, session and user-agent fields are all bound
        """
        seen: dict = {}

        async def call_next(ctx):
            seen.update(structlog.contextvars.get_contextvars())
            return "ok"

        monkeypatch.setattr("gg_api_core.middleware.get_http_headers", lambda: {"user-agent": "cursor/1.4.0"})
        await RequestLoggingContextMiddleware(FakeServer()).on_message(_message_ctx(session_id="sess-1"), call_next)

        assert seen["authentication_mode"] == "TEST"
        assert seen["account_id"] == 8
        assert seen["workspace_id"] == 8
        assert seen["member_id"] == 480870
        assert seen["token_id"] == "tok-uuid"
        assert seen["mcp_session_id"] == "sess-1"
        assert seen["user_agent"] == "cursor/1.4.0"
        assert seen["token_scopes_hash"]

    async def test_all_bound_fields_are_released_after_the_message(self, monkeypatch):
        """
        GIVEN a message that binds caller identity
        WHEN the message completes
        THEN none of the bound fields remain in the context
        """

        async def call_next(ctx):
            return "ok"

        monkeypatch.setattr("gg_api_core.middleware.get_http_headers", lambda: {"user-agent": "cursor/1.4.0"})
        await RequestLoggingContextMiddleware(FakeServer()).on_message(_message_ctx(session_id="sess-1"), call_next)

        assert structlog.contextvars.get_contextvars() == {}

    async def test_unresolvable_caller_identity_does_not_fail_the_message(self):
        """
        GIVEN a token the API rejects
        WHEN the message is handled
        THEN the message still runs, without the identity fields
        """
        seen: dict = {}

        async def call_next(ctx):
            seen.update(structlog.contextvars.get_contextvars())
            return "ok"

        server = FakeServer(token_info=RuntimeError("401 Unauthorized"))
        result = await RequestLoggingContextMiddleware(server).on_message(_message_ctx(), call_next)

        assert result == "ok"
        assert seen["request_id"]
        assert "account_id" not in seen
        assert "workspace_id" not in seen

    async def test_identity_is_fetched_once_across_messages(self):
        """
        GIVEN several messages from the same token
        WHEN each is handled
        THEN token info is fetched only once
        """

        async def call_next(ctx):
            return "ok"

        server = FakeServer()
        middleware = RequestLoggingContextMiddleware(server)
        for _ in range(3):
            await middleware.on_message(_message_ctx(), call_next)

        assert server.token_info_calls == 1

    async def test_logs_client_identity_on_initialize(self, caplog):
        """
        GIVEN an initialize request carrying clientInfo and a protocol version
        WHEN it is handled
        THEN an mcp_initialize event records both
        """
        params = SimpleNamespace(
            clientInfo=SimpleNamespace(name="claude-ai", version="0.1.0"),
            protocolVersion="2025-06-18",
        )

        async def call_next(ctx):
            return None

        with caplog.at_level(logging.INFO, logger="gg_api_core.middleware"):
            await RequestLoggingContextMiddleware(FakeServer()).on_initialize(
                _message_ctx(message=SimpleNamespace(params=params)), call_next
            )

        rec = next(r for r in caplog.records if r.getMessage() == "mcp_initialize")
        assert rec.client_name == "claude-ai"
        assert rec.client_version == "0.1.0"
        assert rec.protocol_version == "2025-06-18"

    async def test_every_middleware_log_carries_request_identity_through_the_real_stack(self, capsys):
        """
        GIVEN a server built by get_mcp_server
        WHEN a tool is listed and called through the full middleware stack
        THEN rendered lines from downstream middleware carry the request identity
        """
        mcp = get_mcp_server("Test Server")
        mcp._fetch_token_scopes_from_api = AsyncMock(return_value={"scan"})
        mcp.get_token_info = AsyncMock(return_value=TOKEN_INFO)

        @mcp.tool(name="ping_tool", description="Tool used to drive the middleware stack")
        async def ping_tool():
            return "pong"

        @mcp.tool(name="filtered_tool", description="Tool the token cannot satisfy", required_scopes=["nope:write"])
        async def filtered_tool():
            return "unreachable"

        configure_logging(log_level="INFO", log_format="json")
        async with Client(mcp) as client:
            await client.list_tools()
            await client.call_tool("ping_tool", {})

        rendered = [json.loads(line) for line in capsys.readouterr().err.strip().splitlines() if line.startswith("{")]

        tool_call = next(payload for payload in rendered if payload["event"] == "tool_call")
        assert tool_call["tool"] == "ping_tool"
        assert tool_call["authentication_mode"] == mcp.authentication_mode.value
        assert tool_call["request_id"]
        assert tool_call["account_id"] == TOKEN_INFO["workspace_id"]
        assert tool_call["token_id"] == TOKEN_INFO["id"]

        list_tools = next(payload for payload in rendered if payload["event"] == "list_tools")
        assert list_tools["request_id"]
        assert list_tools["account_id"] == TOKEN_INFO["workspace_id"]
        assert list_tools["token_id"] == TOKEN_INFO["id"]
