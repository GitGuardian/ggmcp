import json
import logging

import httpx
import pytest
import structlog
from pydantic import BaseModel, ValidationError

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
