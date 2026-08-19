import logging
from types import SimpleNamespace

import pytest

from ggmcp.transport.middleware import ToolCallLoggingMiddleware


def _ctx(name, arguments=None):
    return SimpleNamespace(message=SimpleNamespace(name=name, arguments=arguments))


class TestToolCallLoggingMiddleware:
    async def test_logs_successful_call(self, caplog):
        async def call_next(ctx):
            return "result"

        with caplog.at_level(logging.INFO, logger="ggmcp.transport.middleware"):
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

        with caplog.at_level(logging.ERROR, logger="ggmcp.transport.middleware"):
            with pytest.raises(ValueError, match="boom"):
                await ToolCallLoggingMiddleware().on_call_tool(_ctx("scan_secrets"), call_next)

        rec = next(r for r in caplog.records if r.getMessage() == "tool_call_failed")
        assert rec.tool == "scan_secrets"
        assert rec.exc_info is not None
