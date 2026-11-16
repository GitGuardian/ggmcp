"""Sentry capture ownership and payload safety."""

import json
import logging
from unittest.mock import AsyncMock

import httpx
import pytest
import sentry_sdk
import structlog
from fastmcp import Client
from fastmcp.exceptions import ToolError
from fastmcp.exceptions import ValidationError as FastMCPValidationError
from sentry_sdk.transport import Transport

from gg_api_core.client import DownstreamUnauthorizedError
from gg_api_core.logging_config import configure_logging
from gg_api_core.mcp_server import get_mcp_server
from gg_api_core.model_arguments import ToolBodyError
from gg_api_core.redirects import CrossOriginRedirectError
from gg_api_core.sentry_integration import (
    _MAX_SCRUB_DEPTH,
    _scrub_sentry_payload,
    init_sentry,
    is_expected_tool_failure,
)


class _CollectingTransport(Transport):
    """Keep captured Sentry events and transactions in memory."""

    def __init__(self, events: list[dict], transactions: list[dict]):
        super().__init__()
        self._events = events
        self._transactions = transactions

    def capture_envelope(self, envelope) -> None:
        event = envelope.get_event()
        if event is not None:
            self._events.append(event)
        transaction = envelope.get_transaction_event()
        if transaction is not None:
            self._transactions.append(transaction)


def _init_local_sentry(monkeypatch, events: list[dict], transactions: list[dict]) -> None:
    """Initialize the production Sentry configuration with a local transport."""
    real_init = sentry_sdk.init

    def init_with_local_transport(**kwargs):
        return real_init(**kwargs, transport=_CollectingTransport(events, transactions))

    monkeypatch.setattr(sentry_sdk, "init", init_with_local_transport)
    monkeypatch.setenv("SENTRY_DSN", "https://public@localhost/1")
    assert init_sentry() is True


@pytest.fixture
def sentry_transactions(monkeypatch):
    """Initialize production Sentry with full trace sampling and a local transport."""
    transactions: list[dict] = []
    monkeypatch.setenv("SENTRY_TRACES_SAMPLE_RATE", "1.0")
    _init_local_sentry(monkeypatch, [], transactions)
    try:
        yield transactions
    finally:
        sentry_sdk.get_global_scope().set_client(None)


@pytest.fixture
def sentry_capture(monkeypatch):
    """Initialize production Sentry with full trace sampling; collect error events and transactions."""
    events: list[dict] = []
    transactions: list[dict] = []
    monkeypatch.setenv("SENTRY_TRACES_SAMPLE_RATE", "1.0")
    _init_local_sentry(monkeypatch, events, transactions)
    try:
        yield events, transactions
    finally:
        sentry_sdk.get_global_scope().set_client(None)


@pytest.fixture
def sentry_events(monkeypatch):
    """Initialize the production Sentry configuration with a local transport."""
    events: list[dict] = []
    _init_local_sentry(monkeypatch, events, [])
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

    async def test_tool_call_middleware_is_the_only_tool_failure_owner(self, sentry_events, monkeypatch):
        """
        GIVEN a real MCP tool that raises an exception
        WHEN it is called through the middleware stack
        THEN exactly one event is produced, correlated with its tool log
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

    async def test_failed_tool_call_flags_its_mcp_span(self, sentry_transactions):
        """
        GIVEN full trace sampling and a real MCP tool that raises an exception
        WHEN it is called through the middleware stack
        THEN the tool's mcp.server span is marked as an error result with a failed status
        """
        mcp = get_mcp_server("Sentry span test")
        mcp._fetch_token_scopes_from_api = AsyncMock(return_value=set())
        mcp.get_token_info = AsyncMock(return_value={})

        @mcp.tool(name="failing_tool")
        async def failing_tool():
            raise RuntimeError("tool exploded")

        with sentry_sdk.start_transaction(name="tool-failure"):
            async with Client(mcp) as client:
                with pytest.raises(ToolError):
                    await client.call_tool("failing_tool", {})
        sentry_sdk.flush()

        (transaction,) = sentry_transactions
        (span,) = [span for span in transaction["spans"] if span["op"] == "mcp.server"]
        assert span["data"]["mcp.tool.name"] == "failing_tool"
        assert span["data"]["mcp.tool.result.is_error"] is True
        assert span["status"] == "internal_error"

    async def test_successful_tool_call_keeps_its_mcp_span_ok(self, sentry_transactions):
        """
        GIVEN full trace sampling and a real MCP tool that returns normally
        WHEN it is called through the middleware stack
        THEN the tool's mcp.server span is neither flagged nor failed
        """
        mcp = get_mcp_server("Sentry span test")
        mcp._fetch_token_scopes_from_api = AsyncMock(return_value=set())
        mcp.get_token_info = AsyncMock(return_value={})

        @mcp.tool(name="working_tool")
        async def working_tool():
            return "done"

        with sentry_sdk.start_transaction(name="tool-success"):
            async with Client(mcp) as client:
                await client.call_tool("working_tool", {})
        sentry_sdk.flush()

        (transaction,) = sentry_transactions
        (span,) = [span for span in transaction["spans"] if span["op"] == "mcp.server"]
        assert "mcp.tool.result.is_error" not in span["data"]
        assert span.get("status") in (None, "ok")

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


class TestMcpIntegrationActivation:
    def test_mcp_integration_is_active(self, sentry_events):
        """
        GIVEN the installed sentry-sdk and MCP SDK
        WHEN Sentry is initialized
        THEN the MCP integration is active, so tool calls get mcp.server spans
        """
        assert sentry_sdk.get_client().get_integration("mcp") is not None

    def test_inactive_mcp_integration_is_reported(self, monkeypatch, caplog):
        """
        GIVEN a sentry-sdk whose MCP integration cannot hook the installed MCP SDK
        WHEN Sentry is initialized
        THEN a warning says tool calls will have no mcp.server spans
        """
        monkeypatch.setattr(sentry_sdk.client._Client, "get_integration", lambda self, name_or_class: None)
        caplog.set_level(logging.WARNING, logger="gg_api_core.sentry_integration")
        try:
            _init_local_sentry(monkeypatch, [], [])
        finally:
            sentry_sdk.get_global_scope().set_client(None)

        assert "Sentry MCP integration is not active" in caplog.text


def _status_error(status: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://api.gitguardian.com/v1/incidents/secrets/77")
    return httpx.HTTPStatusError(str(status), request=request, response=httpx.Response(status, request=request))


def _caused_by(outer: BaseException, cause: BaseException) -> BaseException:
    outer.__cause__ = cause
    return outer


class TestExpectedToolFailures:
    @pytest.mark.parametrize(
        "exception",
        [
            pytest.param(_caused_by(ToolError("Error calling tool"), _status_error(404)), id="api-404"),
            pytest.param(_caused_by(ToolError("Error calling tool"), _status_error(409)), id="api-409"),
            pytest.param(_caused_by(ToolError("Error calling tool"), _status_error(403)), id="api-403"),
            pytest.param(_caused_by(ToolError("Error calling tool"), _status_error(400)), id="api-400"),
            pytest.param(
                _caused_by(ToolError("x"), _caused_by(DownstreamUnauthorizedError("401"), _status_error(401))),
                id="expired-token",
            ),
            pytest.param(FastMCPValidationError("Invalid arguments for tool 'get_incident'"), id="bad-arguments"),
            pytest.param(ToolError("No honeytoken was created: ..."), id="deliberate-refusal"),
        ],
    )
    def test_a_refusal_the_caller_can_act_on_is_expected(self, exception):
        assert is_expected_tool_failure(exception) is True

    @pytest.mark.parametrize(
        "exception",
        [
            pytest.param(_caused_by(ToolError("Error calling tool"), _status_error(500)), id="api-500"),
            pytest.param(_caused_by(ToolError("Error calling tool"), _status_error(503)), id="api-503"),
            pytest.param(_caused_by(ToolError("Error calling tool"), _status_error(429)), id="rate-limited"),
            pytest.param(_caused_by(ToolError("Error calling tool"), _status_error(408)), id="api-timeout"),
            pytest.param(_caused_by(ToolError("Error calling tool"), RuntimeError("bug")), id="bug"),
            pytest.param(
                _caused_by(ToolError("Error calling tool"), ValueError("dictionary update sequence element #0")),
                id="value-error-bug",
            ),
            pytest.param(
                _caused_by(ToolError("Error calling tool"), httpx.ReadTimeout("timed out")), id="transport-timeout"
            ),
            pytest.param(
                _caused_by(ToolError("Error calling tool"), CrossOriginRedirectError("redirected")),
                id="cross-origin-redirect",
            ),
            pytest.param(_caused_by(ToolBodyError("bad response shape"), ValueError("x")), id="response-parsing"),
        ],
    )
    def test_a_defect_or_an_upstream_failure_is_unexpected(self, exception):
        assert is_expected_tool_failure(exception) is False

    async def test_an_api_refusal_fails_its_span_without_a_sentry_event(self, sentry_capture):
        sentry_events, sentry_transactions = sentry_capture
        """
        GIVEN a real MCP tool whose API call is refused with a 404
        WHEN it is called through the middleware stack
        THEN no Sentry error event is sent, and its span is still failed and marked expected
        """
        mcp = get_mcp_server("Sentry expected failure test")
        mcp._fetch_token_scopes_from_api = AsyncMock(return_value=set())
        mcp.get_token_info = AsyncMock(return_value={})

        @mcp.tool(name="refused_tool")
        async def refused_tool():
            raise _status_error(404)

        with sentry_sdk.start_transaction(name="tool-refused"):
            async with Client(mcp) as client:
                with pytest.raises(ToolError):
                    await client.call_tool("refused_tool", {})
        sentry_sdk.flush()

        assert sentry_events == []
        (span,) = [span for span in sentry_transactions[0]["spans"] if span["op"] == "mcp.server"]
        assert span["status"] == "internal_error"
        assert span["data"]["mcp.tool.failure_kind"] == "expected"

    async def test_a_crash_is_reported_and_marked_unexpected(self, sentry_capture):
        sentry_events, sentry_transactions = sentry_capture
        """
        GIVEN a real MCP tool that crashes
        WHEN it is called through the middleware stack
        THEN one Sentry error event is sent, and its span is failed and marked unexpected
        """
        mcp = get_mcp_server("Sentry unexpected failure test")
        mcp._fetch_token_scopes_from_api = AsyncMock(return_value=set())
        mcp.get_token_info = AsyncMock(return_value={})

        @mcp.tool(name="crashing_tool")
        async def crashing_tool():
            raise KeyError("results")

        with sentry_sdk.start_transaction(name="tool-crash"):
            async with Client(mcp) as client:
                with pytest.raises(ToolError):
                    await client.call_tool("crashing_tool", {})
        sentry_sdk.flush()

        assert len(sentry_events) == 1
        (span,) = [span for span in sentry_transactions[0]["spans"] if span["op"] == "mcp.server"]
        assert span["data"]["mcp.tool.failure_kind"] == "unexpected"
