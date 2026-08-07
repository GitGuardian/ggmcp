from gg_api_core.sentry_integration import _prepare_sentry_event


class TestPrepareSentryEvent:
    def test_tags_event_with_request_id_from_trace_data(self):
        """
        GIVEN an event containing the active MCP span data
        WHEN the event is prepared for Sentry
        THEN its request ID is promoted without replacing existing tags
        """
        event = _prepare_sentry_event(
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
        assert _prepare_sentry_event({}, {}) == {}
