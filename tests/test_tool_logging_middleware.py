import logging
from types import SimpleNamespace

import pytest
import structlog
from gg_api_core.middleware import RequestLoggingContextMiddleware, ToolCallLoggingMiddleware


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
        assert isinstance(rec.elapsed_ms, int)

    async def test_logs_and_reraises_on_failure(self, caplog):
        async def call_next(ctx):
            raise ValueError("boom")

        with caplog.at_level(logging.ERROR, logger="gg_api_core.middleware"):
            with pytest.raises(ValueError, match="boom"):
                await ToolCallLoggingMiddleware().on_call_tool(_ctx("scan_secrets"), call_next)

        rec = next(r for r in caplog.records if r.getMessage() == "tool_call_failed")
        assert rec.tool == "scan_secrets"
        assert rec.exc_info is not None


class TestRequestLoggingContextMiddleware:
    async def test_binds_request_id_and_clears_after(self):
        seen: dict = {}

        async def call_next(ctx):
            seen.update(structlog.contextvars.get_contextvars())
            return "ok"

        server = SimpleNamespace(caches_token_info=False)
        result = await RequestLoggingContextMiddleware(server).on_message(SimpleNamespace(), call_next)

        assert result == "ok"
        assert seen["request_id"]
        assert "account_id" not in seen  # server does not cache token info
        # binding does not leak past the request
        assert "request_id" not in structlog.contextvars.get_contextvars()

    async def test_binds_account_id_when_server_caches_token_info(self):
        seen: dict = {}

        async def call_next(ctx):
            seen.update(structlog.contextvars.get_contextvars())
            return "ok"

        class Server:
            caches_token_info = True

            async def get_token_info(self):
                return {"workspace_id": 780778}

        await RequestLoggingContextMiddleware(Server()).on_message(SimpleNamespace(), call_next)

        assert seen["account_id"] == 780778
        assert seen["request_id"]

    async def test_prefers_inbound_x_request_id_header(self, monkeypatch):
        seen: dict = {}

        async def call_next(ctx):
            seen.update(structlog.contextvars.get_contextvars())
            return "ok"

        monkeypatch.setattr("gg_api_core.middleware.get_http_headers", lambda: {"x-request-id": "trace-123"})
        server = SimpleNamespace(caches_token_info=False)
        await RequestLoggingContextMiddleware(server).on_message(SimpleNamespace(), call_next)

        assert seen["request_id"] == "trace-123"
