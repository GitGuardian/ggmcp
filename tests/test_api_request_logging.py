"""The structured ``api_request`` event replacing httpx's free-text INFO line."""

import asyncio
import logging

import httpx
import pytest
from gg_api_core.client import GitGuardianClient, _path_template
from gg_api_core.log_context import track_downstream_calls
from gg_api_core.logging_config import configure_logging


def _responding_with(handler):
    """Replacement for ``AsyncClient.request`` that answers from ``handler``.

    Builds the response directly rather than delegating to another client, which
    would re-enter the patched method.
    """

    async def request(self, method, url, **kwargs):
        response = handler(httpx.Request(method, url))
        response.request = httpx.Request(method, url)
        return response

    return request


class TestPathTemplate:
    @pytest.mark.parametrize(
        ("endpoint", "expected"),
        [
            ("/incidents/secrets/12345", "/incidents/secrets/{id}"),
            (
                "/honeytokens/d0ca9877-641f-4c37-8857-c08e0ae148c4/revoke",
                "/honeytokens/{id}/revoke",
            ),
            ("/incidents-for-mcp/count", "/incidents-for-mcp/count"),
        ],
    )
    def test_collapses_id_segments(self, endpoint, expected):
        """
        GIVEN an endpoint path containing a numeric or UUID id
        WHEN it is templated
        THEN the id is collapsed to a placeholder
        """
        assert _path_template(endpoint) == expected

    def test_drops_the_query_string(self):
        """
        GIVEN an endpoint carrying filter values in its query string
        WHEN it is templated
        THEN the query string is dropped entirely
        """
        assert _path_template("/incidents/secrets?assignee_email=a@b.com&severity=high") == "/incidents/secrets"


class TestApiRequestEvent:
    async def test_logs_method_path_status_and_duration(self, caplog, monkeypatch):
        """
        GIVEN a successful GitGuardian API call
        WHEN it completes
        THEN one api_request event reports method, templated path, status and duration
        """
        client = GitGuardianClient(gitguardian_url="https://dashboard.gitguardian.com", personal_access_token="tok")

        def handler(request):
            return httpx.Response(200, json={"count": 3}, headers={"x-request-id": "gg-req-7"})

        monkeypatch.setattr(httpx.AsyncClient, "request", _responding_with(handler))

        with caplog.at_level(logging.INFO, logger="gg_api_core.client"):
            await client._request_get("/incidents/secrets/12345")

        rec = next(r for r in caplog.records if r.getMessage() == "api_request")
        assert rec.method == "GET"
        assert rec.path == "/incidents/secrets/{id}"
        assert rec.status == 200
        assert isinstance(rec.duration_ms, int)
        assert rec.gg_request_id == "gg-req-7"

    async def test_list_requests_use_the_same_tracking_path(self, caplog, monkeypatch):
        """
        GIVEN a successful list request
        WHEN it completes
        THEN the shared tracker emits the same api_request event
        """
        client = GitGuardianClient(gitguardian_url="https://dashboard.gitguardian.com", personal_access_token="tok")

        async def get(self, url, **kwargs):
            response = httpx.Response(200, json=[])
            response.request = httpx.Request("GET", url)
            return response

        monkeypatch.setattr(httpx.AsyncClient, "get", get)

        with caplog.at_level(logging.INFO, logger="gg_api_core.client"):
            await client._request_list("/incidents/secrets")

        rec = next(r for r in caplog.records if r.getMessage() == "api_request")
        assert rec.method == "GET"
        assert rec.path == "/incidents/secrets"
        assert rec.status == 200

    async def test_accounts_the_call_against_the_enclosing_tool_call(self, monkeypatch):
        """
        GIVEN a GitGuardian API call made inside a tracked block
        WHEN it completes
        THEN the block's accumulator counts it and its latency
        """
        client = GitGuardianClient(gitguardian_url="https://dashboard.gitguardian.com", personal_access_token="tok")

        def handler(request):
            return httpx.Response(200, json={})

        monkeypatch.setattr(httpx.AsyncClient, "request", _responding_with(handler))

        with track_downstream_calls() as stats:
            await client._request_get("/incidents/secrets/1")

        assert stats.calls == 1
        assert stats.statuses == {200}

    async def test_reports_a_transport_failure_without_a_status(self, caplog, monkeypatch):
        """
        GIVEN an API call that never gets a response
        WHEN it fails
        THEN api_request reports the error class and no status
        """
        client = GitGuardianClient(gitguardian_url="https://dashboard.gitguardian.com", personal_access_token="tok")

        async def failing_request(self, method, url, **kwargs):
            raise httpx.ConnectTimeout("timed out")

        monkeypatch.setattr(httpx.AsyncClient, "request", failing_request)

        with caplog.at_level(logging.INFO, logger="gg_api_core.client"):
            with pytest.raises(httpx.ConnectTimeout):
                await client._request_get("/incidents/secrets")

        rec = next(r for r in caplog.records if r.getMessage() == "api_request")
        assert rec.status is None
        assert rec.error_class == "ConnectTimeout"


class TestRetryAccounting:
    async def test_retry_backoff_counts_as_downstream_time(self, monkeypatch):
        """
        GIVEN an endpoint returning 500 until the retries run out
        WHEN the call finally fails
        THEN the backoff between attempts is counted in downstream time
        """
        client = GitGuardianClient(gitguardian_url="https://dashboard.gitguardian.com", personal_access_token="tok")

        def handler(request):
            return httpx.Response(500, json={"detail": "boom"})

        monkeypatch.setattr(httpx.AsyncClient, "request", _responding_with(handler))
        slept: list[float] = []

        async def fake_sleep(seconds):
            slept.append(seconds)

        monkeypatch.setattr(asyncio, "sleep", fake_sleep)

        with track_downstream_calls() as stats:
            with pytest.raises(httpx.HTTPStatusError):
                await client._request_get("/incidents/secrets")

        assert stats.retries == 3
        assert slept == [1, 2, 4]
        assert stats.wait_ms == sum(slept) * 1000
        assert stats.total_ms >= stats.wait_ms


class TestNoisyLoggerDemotion:
    def test_httpx_is_demoted_above_debug(self):
        """
        GIVEN logging configured at INFO
        WHEN httpx's own logger is consulted
        THEN its per-request INFO line is suppressed
        """
        configure_logging(log_level="INFO", log_format="json")

        assert not logging.getLogger("httpx").isEnabledFor(logging.INFO)

    def test_the_sdk_per_request_line_is_demoted(self):
        """
        GIVEN logging configured at INFO
        WHEN the MCP SDK's low-level server logger is consulted
        THEN its per-message INFO line is suppressed
        """
        configure_logging(log_level="INFO", log_format="json")

        assert not logging.getLogger("mcp.server.lowlevel.server").isEnabledFor(logging.INFO)

    def test_httpx_is_left_alone_at_debug(self):
        """
        GIVEN logging configured at DEBUG
        WHEN httpx's own logger is consulted
        THEN it is not demoted
        """
        configure_logging(log_level="DEBUG", log_format="json")

        assert logging.getLogger("httpx").isEnabledFor(logging.DEBUG)
