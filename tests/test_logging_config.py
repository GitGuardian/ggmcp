import json
import logging

import pytest
import structlog
from gg_api_core.logging_config import configure_logging


def _reconfigure_json():
    configure_logging(log_level="DEBUG", log_format="json")


@pytest.fixture(scope="module")
def _assert_structlog_configuration_restored():
    """Assert the function-scoped logging fixture restores Structlog state."""
    saved_config = structlog.get_config()
    yield saved_config
    assert structlog.get_config() == saved_config


class TestConfigureLogging:
    def test_configuration_does_not_leak_between_tests(self, _assert_structlog_configuration_restored):
        """
        GIVEN the process-global Structlog configuration before a test
        WHEN configure_logging replaces its processor chain
        THEN the autouse logging fixture restores the original configuration afterward
        """
        _reconfigure_json()

        assert structlog.get_config() != _assert_structlog_configuration_restored

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

    def test_bound_contextvars_reach_rendered_output(self, capsys):
        """
        GIVEN a value bound via structlog.contextvars
        WHEN a line is emitted through the structlog and the stdlib logger
        THEN both rendered payloads carry it

        Guards ``merge_contextvars`` staying in *both* the structlog processor
        chain and the ProcessorFormatter ``foreign_pre_chain``. Dropping it
        from either silently strips ``request_id`` from production logs while
        every contextvars-level unit test still passes.
        """
        _reconfigure_json()
        with structlog.contextvars.bound_contextvars(
            account_id=475789,
            request_id="req-abc",
            token_id="d0ca9877-641f-4c37-8857-c08e0ae148c4",
        ):
            structlog.get_logger("t").info("native")
            # How ToolCallLoggingMiddleware actually emits: stdlib logger + extra.
            logging.getLogger("t.stdlib").info("foreign", extra={"tool": "scan_secrets"})

        native, foreign = (json.loads(line) for line in capsys.readouterr().err.strip().splitlines()[-2:])
        assert native["event"] == "native"
        assert native["account_id"] == 475789
        assert native["request_id"] == "req-abc"
        assert native["token_id"] == "d0ca9877-641f-4c37-8857-c08e0ae148c4"
        assert foreign["event"] == "foreign"
        assert foreign["account_id"] == 475789
        assert foreign["request_id"] == "req-abc"
        assert foreign["token_id"] == "d0ca9877-641f-4c37-8857-c08e0ae148c4"
        assert foreign["tool"] == "scan_secrets"
