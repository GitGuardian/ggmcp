import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from gg_api_core.sanitization import SENSITIVE_DATA_PLACEHOLDER
from gg_api_core.sentry_integration import _before_send_event, _before_send_transaction
from tests.helpers.sentry_mcp_transaction_probe import RAW_DOCUMENT

PROBE_PATH = Path(__file__).parent / "helpers" / "sentry_mcp_transaction_probe.py"


def test_error_event_scrubs_custom_data_without_damaging_stacktrace():
    """
    GIVEN an error event with application data, breadcrumbs, and a stack frame
    WHEN Sentry prepares the event for transport
    THEN secrets are scrubbed while canonical stack information is preserved
    """
    event = {
        "contexts": {"scan": {"document": "raw file content"}},
        "extra": {"account_id": 42, "token": "gg_pat_secret"},
        "breadcrumbs": {
            "values": [
                {
                    "message": "request",
                    "data": {"endpoint": "/v1/scan", "password": "secret"},
                }
            ]
        },
        "exception": {
            "values": [
                {
                    "stacktrace": {
                        "frames": [
                            {
                                "filename": "packages/gg_api_core/src/gg_api_core/client.py",
                                "function": "_request",
                            }
                        ]
                    }
                }
            ]
        },
    }

    outgoing_event = _before_send_event(event, {})

    assert outgoing_event["contexts"]["scan"]["document"] == SENSITIVE_DATA_PLACEHOLDER
    assert outgoing_event["extra"]["token"] == SENSITIVE_DATA_PLACEHOLDER
    assert outgoing_event["extra"]["account_id"] == 42
    assert outgoing_event["breadcrumbs"]["values"][0]["data"]["password"] == SENSITIVE_DATA_PLACEHOLDER
    assert outgoing_event["breadcrumbs"]["values"][0]["data"]["endpoint"] == "/v1/scan"
    frame = outgoing_event["exception"]["values"][0]["stacktrace"]["frames"][0]
    assert frame["filename"] == "packages/gg_api_core/src/gg_api_core/client.py"
    assert frame["function"] == "_request"


def test_real_sentry_transaction_drops_mcp_tool_arguments(tmp_path):
    """
    GIVEN the real Sentry MCP integration with PII disabled and full trace sampling
    WHEN scan_secrets receives raw document content containing a secret-shaped value
    THEN the tool argument does not reach the outgoing transaction envelope
    """
    transaction_path = tmp_path / "transaction.json"
    environment = {key: value for key, value in os.environ.items() if not key.startswith("SENTRY_")}
    environment.update(
        {
            "SENTRY_DSN": "https://public@example.com/1",
            "SENTRY_PROFILES_SAMPLE_RATE": "0",
            "SENTRY_TRACES_SAMPLE_RATE": "1.0",
        }
    )

    completed = subprocess.run(
        [sys.executable, str(PROBE_PATH), str(transaction_path)],
        capture_output=True,
        check=False,
        env=environment,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    transaction = json.loads(transaction_path.read_text())
    serialized_transaction = json.dumps(transaction)
    # The exact raw document the probe sends must not survive to the envelope.
    assert RAW_DOCUMENT not in serialized_transaction

    mcp_spans = [span for span in transaction["spans"] if span["op"] == "mcp.server"]
    assert [span["data"]["mcp.tool.name"] for span in mcp_spans] == ["scan_secrets"]
    assert all(not key.startswith("mcp.request.argument.") for key in mcp_spans[0]["data"])


def test_transaction_scrubs_free_form_fields_and_drops_span_arguments():
    """
    GIVEN a transaction event carrying free-form data, breadcrumbs, and span arguments
    WHEN Sentry prepares the transaction for transport
    THEN free-form fields are redacted and every MCP tool argument is dropped
    """
    event = {
        "contexts": {"scan": {"document": "raw file content"}},
        "extra": {"token": "gg_pat_secret", "account_id": 42},
        "breadcrumbs": {"values": [{"data": {"password": "secret"}}]},
        "spans": [
            {
                "data": {
                    "mcp.tool.name": "revoke_secret",
                    "mcp.request.argument.scope": "secrets:write",
                    "mcp.request.argument.secret_id": "1",
                }
            }
        ],
    }

    outgoing_event = _before_send_transaction(event, {})

    assert outgoing_event["contexts"]["scan"]["document"] == SENSITIVE_DATA_PLACEHOLDER
    assert outgoing_event["extra"]["token"] == SENSITIVE_DATA_PLACEHOLDER
    assert outgoing_event["extra"]["account_id"] == 42
    assert outgoing_event["breadcrumbs"]["values"][0]["data"]["password"] == SENSITIVE_DATA_PLACEHOLDER
    span_data = outgoing_event["spans"][0]["data"]
    assert span_data["mcp.tool.name"] == "revoke_secret"
    assert not any(key.startswith("mcp.request.argument.") for key in span_data)


def test_transaction_drops_query_strings_and_request_bodies():
    """
    GIVEN a transaction carrying a downstream query, an incoming OAuth form body, and query breadcrumbs
    WHEN Sentry prepares the transaction for transport
    THEN query strings and the request body are gone while URL paths stay
    """
    event = {
        "request": {
            "method": "POST",
            "url": "https://mcp.gitguardian.com/token",
            "query_string": "state=oauth-state",
            "data": {"code": "oauth-code", "code_verifier": "oauth-verifier"},
        },
        "breadcrumbs": {
            "values": [
                {
                    "category": "httpx",
                    "data": {"url": "https://api.gitguardian.com/v1/x", "http.query": "search=pasted-secret"},
                }
            ]
        },
        "spans": [
            {
                "op": "http.client",
                "data": {
                    "url": "https://api.gitguardian.com/v1/incidents-for-mcp",
                    "http.query": "search=pasted-secret",
                    "http.fragment": "frag",
                },
            }
        ],
    }

    outgoing = _before_send_transaction(event, {})

    assert outgoing["request"] == {"method": "POST", "url": "https://mcp.gitguardian.com/token"}
    assert outgoing["spans"][0]["data"] == {"url": "https://api.gitguardian.com/v1/incidents-for-mcp"}
    assert outgoing["breadcrumbs"]["values"][0]["data"] == {"url": "https://api.gitguardian.com/v1/x"}
    assert "pasted-secret" not in json.dumps(outgoing)


def test_error_event_keeps_url_paths_but_not_their_queries():
    """
    GIVEN an error whose message names a URL with a query string, on a request with a query and a body
    WHEN Sentry prepares the event for transport
    THEN the message keeps the URL path, and the query, request query string and body are gone
    """
    message = (
        "Client error '404 Not Found' for url "
        "'https://api.gitguardian.com/v1/incidents-for-mcp?search=pasted-secret&page=1'"
    )
    event = {
        "exception": {"values": [{"type": "HTTPStatusError", "value": message}]},
        "request": {"url": "https://mcp.gitguardian.com/mcp", "query_string": "a=b", "data": '{"params": "x"}'},
        "breadcrumbs": {"values": [{"data": {"http.query": "search=pasted-secret"}}]},
    }

    outgoing = _before_send_event(event, {})

    assert outgoing["exception"]["values"][0]["value"] == (
        "Client error '404 Not Found' for url "
        f"'https://api.gitguardian.com/v1/incidents-for-mcp?{SENSITIVE_DATA_PLACEHOLDER}'"
    )
    assert outgoing["request"] == {"url": "https://mcp.gitguardian.com/mcp"}
    assert outgoing["breadcrumbs"]["values"][0]["data"] == {}
    assert "pasted-secret" not in json.dumps(outgoing)


def test_error_event_redacts_the_input_a_validation_error_quotes():
    """
    GIVEN a tool-call validation error whose message quotes the agent's input
    WHEN Sentry prepares the event for transport
    THEN the input is redacted and the rest of the message stays
    """
    message = (
        "1 validation error for call[get_internal_incident]\nparams.incident_id\n"
        "  Input should be a valid integer, unable to parse string as an integer "
        "[type=int_parsing, input_value='pasted-secret', input_type=str]"
    )
    event = {"exception": {"values": [{"type": "ValidationError", "value": message}]}}

    outgoing = _before_send_event(event, {})

    value = outgoing["exception"]["values"][0]["value"]
    assert "pasted-secret" not in value
    assert f"[type=int_parsing, input_value={SENSITIVE_DATA_PLACEHOLDER}, input_type=str]" in value


@pytest.mark.parametrize("before_send", [_before_send_event, _before_send_transaction], ids=["error", "transaction"])
@pytest.mark.parametrize(
    "transaction",
    [
        "http://worker-a:8000/mcp",
        "http://192.0.2.10:9000/mcp",
        "https://mcp.example.test/mcp",
        "http://[2001:db8::1]:8000/mcp",
        "http://worker-b:8000/mcp?page=1#fragment",
    ],
)
def test_mcp_http_transaction_uses_a_stable_route_name(before_send, transaction):
    """Full MCP URLs share one route name while diagnostic metadata and tool spans survive."""
    event = {
        "transaction": transaction,
        "transaction_info": {"source": "url"},
        "request": {"method": "POST", "url": "https://mcp.example.test/mcp"},
        "server_name": "worker-a",
        "contexts": {"trace": {"trace_id": "a" * 32, "data": {"request_id": "req-normalize"}}},
        "spans": [
            {
                "op": "mcp.server",
                "description": "tools/call get_internal_incident",
                "data": {"mcp.tool.name": "get_internal_incident", "mcp.request.argument.incident_id": 77},
            }
        ],
    }

    outgoing = before_send(event, {})

    assert outgoing["transaction"] == "/mcp"
    assert outgoing["transaction_info"]["source"] == "route"
    assert outgoing["request"] == {"method": "POST", "url": "https://mcp.example.test/mcp"}
    assert outgoing["server_name"] == "worker-a"
    assert outgoing["contexts"]["trace"] == {"trace_id": "a" * 32, "data": {"request_id": "req-normalize"}}
    assert outgoing["spans"][0]["description"] == "tools/call get_internal_incident"
    if before_send is _before_send_event:
        assert outgoing["tags"]["request_id"] == "req-normalize"
    else:
        assert outgoing["spans"][0]["data"] == {"mcp.tool.name": "get_internal_incident"}


@pytest.mark.parametrize("before_send", [_before_send_event, _before_send_transaction], ids=["error", "transaction"])
@pytest.mark.parametrize(
    "transaction",
    [
        "/mcp",
        "/register",
        "http://worker-a:8000/register",
        "https://mcp.example.test/token",
        "http://worker-a:8000/mcp/other",
        "http://worker-a:8000/mcp/",
        "tools/call list_internal_incidents",
        "mcp-scrubbing-test",
        "http://[invalid/mcp",
        "https:///mcp",
        "file://worker-a/mcp",
        None,
    ],
)
def test_other_transaction_names_are_preserved(before_send, transaction):
    event = {"transaction": transaction, "transaction_info": {"source": "custom"}}

    outgoing = before_send(event, {})

    assert outgoing["transaction"] == transaction
    assert outgoing["transaction_info"] == {"source": "custom"}


@pytest.mark.parametrize("before_send", [_before_send_event, _before_send_transaction], ids=["error", "transaction"])
def test_missing_transaction_name_is_preserved(before_send):
    assert before_send({}, {}) == {}
