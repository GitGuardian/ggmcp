import json
import logging

import anyio
import httpx
import pytest
import structlog
from pydantic import BaseModel, ValidationError
from starlette.requests import ClientDisconnect

from gg_api_core.logging_config import configure_logging
from gg_api_core.version import APP_VERSION


def _reconfigure_json():
    configure_logging(log_level="DEBUG", log_format="json")


@pytest.fixture(scope="module")
def _assert_structlog_configuration_restored():
    """Assert the function-scoped logging fixture restores Structlog state."""
    saved_config = structlog.get_config()
    yield saved_config
    assert structlog.get_config() == saved_config


class TestConfigureLogging:
    def test_logs_go_to_stderr_not_stdout(self, capsys):
        _reconfigure_json()
        structlog.get_logger("t").info("hello")
        captured = capsys.readouterr()
        assert captured.out == ""  # stdout is the stdio JSON-RPC channel — must stay clean
        assert "hello" in captured.err

    def test_json_format_renders_with_service(self, capsys):
        _reconfigure_json()
        structlog.get_logger("t").info("event msg", account_id=475789)
        payload = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
        assert payload["event"] == "event msg"
        assert payload["account_id"] == 475789
        assert payload["gg_service"] == "gg-mcp-server"
        assert payload["level"] == "info"
        assert payload["gg_version"] == (APP_VERSION or "unknown")

    def test_structlog_kwargs_are_sanitized(self, capsys):
        _reconfigure_json()
        structlog.get_logger("t").warning("scan", document="RAW", secret_id=42, token="gg_pat_x")
        payload = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
        assert payload["document"] == "[REDACTED]"
        assert payload["token"] == "[REDACTED]"
        assert payload["secret_id"] == 42

    def test_stdlib_extra_is_captured_and_sanitized(self, capsys):
        _reconfigure_json()
        logging.getLogger("t.stdlib").info("m", extra={"account_id": 1, "token": "gg_pat_x", "endpoint": "/v1/x"})
        payload = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
        assert payload["account_id"] == 1
        assert payload["endpoint"] == "/v1/x"
        assert payload["token"] == "[REDACTED]"

    def test_logged_validation_errors_do_not_carry_the_rejected_input(self, capsys):
        _reconfigure_json()

        class Params(BaseModel):
            incident_id: int

        # Built at runtime: the traceback quotes source lines, and this one must not hold the value.
        rejected_input = "-".join(("pasted", "secret"))
        try:
            Params.model_validate({"incident_id": rejected_input})
        except ValidationError:
            logging.getLogger("t.stdlib").exception("tool_call_failed")
        payload = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
        assert "type=int_parsing" in payload["exception"]
        assert "pasted-secret" not in json.dumps(payload)

    def test_logged_http_errors_keep_the_url_path_but_not_its_query(self, capsys):
        _reconfigure_json()
        request = httpx.Request("GET", "https://api.gitguardian.com/v1/incidents-for-mcp?search=pasted-secret&page=1")
        response = httpx.Response(404, request=request)
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError:
            logging.getLogger("t.stdlib").exception("tool_call_failed")
        payload = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
        assert "https://api.gitguardian.com/v1/incidents-for-mcp?[REDACTED]" in payload["exception"]
        assert "pasted-secret" not in json.dumps(payload)


def _log_error_with(logger_name: str, exception: BaseException, message: str = "Stateless session crashed") -> None:
    try:
        raise exception
    except BaseException:
        logging.getLogger(logger_name).exception(message)


class TestClientDisconnectNoise:
    @pytest.mark.parametrize(
        ("logger_name", "exception", "message"),
        [
            pytest.param(
                "mcp.server.streamable_http", ClientDisconnect(), "Error handling POST request", id="body-read"
            ),
            pytest.param(
                "mcp.server.streamable_http_manager",
                anyio.ClosedResourceError(),
                "Stateless session crashed",
                id="closed-stream",
            ),
            pytest.param(
                "mcp.server.streamable_http_manager",
                BaseExceptionGroup("unhandled", [anyio.ClosedResourceError(), anyio.BrokenResourceError()]),
                "Stateless session crashed",
                id="group-of-disconnects",
            ),
        ],
    )
    def test_a_client_disconnect_is_logged_as_a_warning(self, capsys, logger_name, exception, message):
        """
        GIVEN the MCP SDK logging an error because the client hung up
        WHEN the record is emitted
        THEN it goes out as a warning, traceback kept
        """
        configure_logging(log_level="INFO", log_format="json")
        _log_error_with(logger_name, exception, message)

        payload = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
        assert payload["level"] == "warning"
        assert payload["event"] == message
        assert "exception" in payload

    @pytest.mark.parametrize(
        ("logger_name", "exception"),
        [
            pytest.param("mcp.server.streamable_http_manager", RuntimeError("bug"), id="real-error-same-logger"),
            pytest.param(
                "mcp.server.streamable_http_manager",
                BaseExceptionGroup("unhandled", [anyio.ClosedResourceError(), RuntimeError("bug")]),
                id="disconnect-mixed-with-a-real-error",
            ),
            pytest.param("gg_api_core.client", ClientDisconnect(), id="disconnect-from-another-logger"),
        ],
    )
    def test_any_other_error_keeps_its_level(self, capsys, logger_name, exception):
        """
        GIVEN an error that is not only a client disconnect, or one logged elsewhere
        WHEN the record is emitted
        THEN it stays an error
        """
        configure_logging(log_level="INFO", log_format="json")
        _log_error_with(logger_name, exception)

        payload = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
        assert payload["level"] == "error"
