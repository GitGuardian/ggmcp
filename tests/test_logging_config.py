import json
import logging

import structlog
from gg_api_core.logging_config import configure_logging


def _reconfigure_json():
    configure_logging(log_level="DEBUG", log_format="json")


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
        # Startup-constant context is on every line.
        assert payload["gg_version"]
        assert payload["gg_environment"]

    def test_gg_version_and_environment_are_emitted(self, capsys):
        configure_logging(log_level="DEBUG", log_format="json", environment="prod-eu", version="9.9.9")
        structlog.get_logger("t").info("m")
        payload = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
        assert payload["gg_version"] == "9.9.9"
        assert payload["gg_environment"] == "prod-eu"

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

    def test_exception_cls_is_added(self, capsys):
        _reconfigure_json()
        try:
            raise ValueError("boom")
        except ValueError:
            structlog.get_logger("t").exception("failed")
        payload = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
        assert payload["exception_cls"] == "ValueError"

    def test_exception_cls_on_stdlib_logger(self, capsys):
        _reconfigure_json()
        try:
            raise KeyError("k")
        except KeyError:
            logging.getLogger("t.stdlib").exception("failed")
        payload = json.loads(capsys.readouterr().err.strip().splitlines()[-1])
        assert payload["exception_cls"] == "KeyError"
