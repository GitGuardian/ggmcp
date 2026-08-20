import logging
from types import SimpleNamespace

import pytest
from gg_api_core.log_context import current_tool_name
from gg_api_core.middleware import ToolCallLoggingMiddleware


def _ctx(name, arguments=None):
    return SimpleNamespace(message=SimpleNamespace(name=name, arguments=arguments))


class TestToolCallLoggingMiddleware:
    async def test_logs_successful_call(self, caplog):
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
        assert isinstance(rec.duration_ms, int)

    async def test_logs_and_reraises_on_failure(self, caplog):
        async def call_next(ctx):
            raise ValueError("boom")

        with caplog.at_level(logging.ERROR, logger="gg_api_core.middleware"):
            with pytest.raises(ValueError, match="boom"):
                await ToolCallLoggingMiddleware().on_call_tool(_ctx("scan_secrets"), call_next)

        rec = next(r for r in caplog.records if r.getMessage() == "tool_call_failed")
        assert rec.tool == "scan_secrets"
        assert rec.exc_info is not None

    async def test_exposes_tool_name_to_downstream_calls(self):
        """
        GIVEN a tool call passing through the middleware
        WHEN the tool body runs
        THEN current_tool_name() returns the tool name inside the call and None after it
        """
        seen: dict[str, str | None] = {}

        async def call_next(ctx):
            seen["tool"] = current_tool_name()
            return "result"

        await ToolCallLoggingMiddleware().on_call_tool(_ctx("list_incidents"), call_next)

        assert seen["tool"] == "list_incidents"
        assert current_tool_name() is None

    async def test_clears_tool_name_when_tool_raises(self):
        """
        GIVEN a tool call that raises
        WHEN the middleware re-raises
        THEN the tracked tool name is cleared
        """

        async def call_next(ctx):
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            await ToolCallLoggingMiddleware().on_call_tool(_ctx("scan_secrets"), call_next)

        assert current_tool_name() is None
