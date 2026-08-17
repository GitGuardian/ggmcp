from gg_api_core.sanitization import SENSITIVE_DATA_PLACEHOLDER
from gg_api_core.sentry_integration import _before_send_event


class TestPrepareSentryEvent:
    def test_tags_event_with_request_id_from_trace_data(self):
        """
        GIVEN an event containing the active MCP span data
        WHEN the event is prepared for Sentry
        THEN its request ID is promoted without replacing existing tags
        """
        event = _before_send_event(
            {
                "contexts": {"trace": {"data": {"request_id": "req-mcp"}}},
                "tags": {"existing": "kept"},
            },
            {},
        )

        assert event["tags"] == {"existing": "kept", "request_id": "req-mcp"}

    def test_leaves_event_untagged_without_request_trace_data(self):
        """
        GIVEN an event without MCP request trace data
        WHEN the event is prepared for Sentry
        THEN no request ID tag is added
        """
        assert _before_send_event({}, {}) == {}


def test_error_event_scrubs_custom_data_without_damaging_stacktrace():
    """
    GIVEN an error event with application data, breadcrumbs, and a stack frame
    WHEN Sentry prepares the event for transport
    THEN secrets are scrubbed while canonical stack information is preserved
    """
    event = {
        "contexts": {"scan": {"document": "raw file content"}},
        "extra": {"account_id": 475789, "token": "gg_pat_secret"},
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
    assert outgoing_event["extra"]["account_id"] == 475789
    assert outgoing_event["breadcrumbs"]["values"][0]["data"]["password"] == SENSITIVE_DATA_PLACEHOLDER
    assert outgoing_event["breadcrumbs"]["values"][0]["data"]["endpoint"] == "/v1/scan"
    frame = outgoing_event["exception"]["values"][0]["stacktrace"]["frames"][0]
    assert frame["filename"] == "packages/gg_api_core/src/gg_api_core/client.py"
    assert frame["function"] == "_request"
