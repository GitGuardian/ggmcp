"""Sentry capture ownership and payload safety."""

import json
import logging
from unittest.mock import AsyncMock

import pytest
import sentry_sdk
import structlog
from fastmcp import Client
from fastmcp.exceptions import ToolError
from gg_api_core.logging_config import configure_logging
from gg_api_core.mcp_server import get_mcp_server
from gg_api_core.sentry_integration import _MAX_SCRUB_DEPTH, _scrub_sentry_payload, init_sentry
from sentry_sdk.transport import Transport


class _CollectingTransport(Transport):
    """Keep captured Sentry events in memory."""

    def __init__(self, events: list[dict]):
        super().__init__()
        self._events = events

    def capture_envelope(self, envelope) -> None:
        event = envelope.get_event()
        if event is not None:
            self._events.append(event)


@pytest.fixture
def sentry_events(monkeypatch):
    """Initialize the production Sentry configuration with a local transport."""
    events: list[dict] = []
    real_init = sentry_sdk.init

    def init_with_local_transport(**kwargs):
        return real_init(**kwargs, transport=_CollectingTransport(events))

    monkeypatch.setattr(sentry_sdk, "init", init_with_local_transport)
    monkeypatch.setenv("SENTRY_DSN", "https://public@localhost/1")
    assert init_sentry() is True
    sentry_sdk.get_isolation_scope().clear_breadcrumbs()
    try:
        yield events
    finally:
        sentry_sdk.get_isolation_scope().clear_breadcrumbs()
        sentry_sdk.get_global_scope().set_client(None)


class TestSentryPayloadScrubbing:
    def test_depth_limit_redacts_the_remaining_subtree(self):
        """
        GIVEN a secret beyond the payload scrubber's depth limit
        WHEN the payload is scrubbed
        THEN the recursion guard redacts the remaining subtree
        """
        secret = "deep-secret"
        payload: object = f"https://example.com?apikey={secret}"
        for _ in range(_MAX_SCRUB_DEPTH + 1):
            payload = {"nested": payload}

        assert secret not in json.dumps(_scrub_sentry_payload(payload))

    def test_captured_exception_is_value_scrubbed(self, sentry_events):
        """
        GIVEN an exception message containing credentials
        WHEN the capture owner sends it to Sentry
        THEN the final payload contains no credential
        """
        password = "hunter" + "2"
        try:
            raise ValueError(f"failed for https://user:{password}@github.com/acme/repo")
        except ValueError as exc:
            sentry_sdk.capture_exception(exc)

        (event,) = sentry_events
        assert password not in json.dumps(event, default=str)
        assert event["exception"]["values"][-1]["type"] == "ValueError"

    def test_frame_locals_are_not_sent(self, sentry_events):
        """
        GIVEN an exception frame containing a local value
        WHEN the capture owner sends it to Sentry
        THEN the stack frames contain no local variables
        """

        def scan():
            document = "some-scan-payload"  # noqa: F841
            raise RuntimeError("scan failed")

        try:
            scan()
        except RuntimeError as exc:
            sentry_sdk.capture_exception(exc)

        (event,) = sentry_events
        frames = event["exception"]["values"][-1]["stacktrace"]["frames"]
        assert frames
        assert all("vars" not in frame for frame in frames)


class TestSentryCaptureOwnership:
    def test_error_log_is_a_breadcrumb_not_an_event(self, sentry_events):
        """
        GIVEN Sentry logging receives an ERROR record
        WHEN the record is emitted
        THEN it creates no Sentry event
        """
        configure_logging(log_level="DEBUG", log_format="json")
        try:
            raise KeyError("missing-field")
        except KeyError:
            logging.getLogger("t.stdlib").exception("tool_call_failed")

        assert sentry_events == []

    def test_logging_breadcrumb_is_scrubbed(self, sentry_events):
        """
        GIVEN a log record containing sensitive message and extra data
        WHEN another owner captures an exception
        THEN its attached breadcrumb contains only scrubbed data
        """
        configure_logging(log_level="DEBUG", log_format="json")
        logging.getLogger("t.stdlib").error(
            "tool_call_failed ?apikey=RAWKEY123",
            extra={"document": "raw scan payload", "tool": "scan_secrets"},
        )
        sentry_sdk.capture_exception(RuntimeError("capture owner"))

        (event,) = sentry_events
        breadcrumbs = event.get("breadcrumbs", {})
        rendered = json.dumps(breadcrumbs, default=str)
        assert "RAWKEY123" not in rendered
        assert "raw scan payload" not in rendered
        assert "scan_secrets" in rendered

    async def test_mcp_integration_is_the_only_tool_failure_owner(self, sentry_events, monkeypatch):
        """
        GIVEN a real MCP tool that raises an exception
        WHEN it is called through the middleware stack
        THEN MCPIntegration produces one event correlated with its tool log
        """
        mcp = get_mcp_server("Sentry ownership test")
        mcp._fetch_token_scopes_from_api = AsyncMock(return_value=set())
        mcp.get_token_info = AsyncMock(return_value={})

        @mcp.tool(name="failing_tool")
        async def failing_tool():
            raise RuntimeError("tool exploded")

        monkeypatch.setattr("gg_api_core.middleware.get_http_headers", lambda: {"x-request-id": "req-sentry"})
        configure_logging(log_level="DEBUG", log_format="json")
        async with Client(mcp) as client:
            with pytest.raises(ToolError):
                await client.call_tool("failing_tool", {})

        assert len(sentry_events) == 1
        event = sentry_events[0]
        exception_types = [value["type"] for value in event["exception"]["values"]]
        assert exception_types == ["RuntimeError", "ToolError"]

        assert event["tags"]["request_id"] == "req-sentry"

    def test_rendered_traceback_remains_scrubbed(self, sentry_events, capsys):
        """
        GIVEN an exception log containing credentials
        WHEN it is rendered to stderr
        THEN the log keeps the traceback but removes the credentials
        """
        configure_logging(log_level="DEBUG", log_format="json")
        try:
            raise ValueError("failed for https://user:hunter2@github.com/acme/repo")
        except ValueError:
            structlog.get_logger("t").exception("tool_call_failed")

        payload = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
        assert "ValueError" in payload["exception"]
        assert "hunter2" not in payload["exception"]
        assert payload["exception_cls"] == "ValueError"
        assert sentry_events == []
