"""Unknown tool calls are client mistakes without Sentry noise."""

import logging

import sentry_sdk

from tests.e2e.harness import call_tool, tool_error_text
from tests.test_sentry_logging import sentry_capture as sentry_capture


async def test_unknown_tool_is_a_client_failure(sentry_capture, mcp_client, mock_token_scopes, caplog):
    """An unknown tool returns an explicit MCP error and logs a client warning without a Sentry event."""
    events, _ = sentry_capture
    assert sentry_sdk.get_client().get_integration("mcp") is not None

    with caplog.at_level(logging.WARNING):
        result = await call_tool(mcp_client, "nonexistent_tool")

    sentry_sdk.flush()
    assert tool_error_text(result) == "Unknown tool: 'nonexistent_tool'"
    (failed,) = [record for record in caplog.records if record.getMessage() == "tool_call_failed"]
    assert (failed.levelno, failed.failure_kind, failed.fault) == (logging.WARNING, "expected", "client")
    assert failed.tool == "nonexistent_tool"
    assert not failed.exc_info
    assert [record.getMessage() for record in caplog.records if record.levelno >= logging.ERROR] == []
    assert events == []
