"""Unknown tool names remain explicit client failures without Sentry noise."""

import json
import logging
from io import StringIO

import pytest
import sentry_sdk
import structlog

from gg_api_core.logging_config import configure_logging
from tests.e2e.harness import call_tool, mcp_headers, tool_error_text
from tests.test_sentry_logging import sentry_capture as sentry_capture


@pytest.fixture
def json_logs():
    """Render production log context into a stream owned by this fixture."""
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    config = structlog.get_config()
    configure_logging(log_format="json")
    stream = StringIO()
    handler = next(handler for handler in root.handlers if handler.name == "ggmcp-log")
    handler.setStream(stream)
    try:
        yield stream
    finally:
        root.handlers = handlers
        root.setLevel(level)
        structlog.configure(**config)


@pytest.mark.parametrize("tool", ["get_current_token_info", "get_incident", "list_incidents", "nonexistent_tool"])
async def test_unknown_tool_is_a_client_failure(sentry_capture, mcp_client, mock_token_scopes, caplog, json_logs, tool):
    """
    GIVEN a stale or unsupported tool name
    WHEN it is called over HTTP/JSON-RPC with the production Sentry integration active
    THEN it returns an explicit error, logs a client warning, and emits zero Sentry events
    """
    events, transactions = sentry_capture
    assert sentry_sdk.get_client().get_integration("mcp") is not None

    with caplog.at_level(logging.WARNING), sentry_sdk.start_transaction(name="unknown-tool"):
        result = await call_tool(mcp_client, tool, headers={**mcp_headers(), "X-Request-ID": "unknown-tool-request"})

    sentry_sdk.flush()
    assert tool_error_text(result) == f"Unknown tool: {tool!r}"
    (failed,) = [record for record in caplog.records if record.getMessage() == "tool_call_failed"]
    assert (failed.levelno, failed.failure_kind, failed.fault) == (logging.WARNING, "expected", "client")
    assert failed.tool == tool
    (rendered,) = [
        record
        for line in json_logs.getvalue().splitlines()
        if (record := json.loads(line)).get("event") == "tool_call_failed"
    ]
    assert rendered["request_id"] == "unknown-tool-request"
    assert not failed.exc_info
    assert [record.getMessage() for record in caplog.records if record.levelno >= logging.ERROR] == []
    assert events == []
    (span,) = [span for span in transactions[0]["spans"] if span["op"] == "mcp.server"]
    assert span["data"]["mcp.tool.failure_kind"] == "expected"


async def test_server_failure_keeps_its_sentry_event(
    sentry_capture, mcp_client, gg_api, mock_token_scopes, no_retry_delay, caplog
):
    """
    GIVEN a real upstream server failure
    WHEN an available tool is called
    THEN its failure stays a server error with exactly one Sentry event
    """
    events, _ = sentry_capture
    gg_api.get("/incidents/secrets/77").respond(500, json={"detail": "boom"})

    with caplog.at_level(logging.WARNING):
        result = await call_tool(mcp_client, "get_internal_incident", {"incident_id": 77})

    sentry_sdk.flush()
    assert "500" in tool_error_text(result)
    (failed,) = [record for record in caplog.records if record.getMessage() == "tool_call_failed"]
    assert (failed.levelno, failed.failure_kind, failed.fault) == (logging.ERROR, "unexpected", "server")
    assert len(events) == 1
