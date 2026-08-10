"""Structured events for the OAuth proxy funnel."""

import logging

import httpx
import pytest
from gg_api_core.oauth_proxy_auth import create_oauth_proxy, mark_downstream_unauthorized
from starlette.requests import Request

LOGGER = "gg_api_core.oauth_proxy_auth"


def _request(method="POST", body=b"", query="", headers=None):
    """A Starlette request with a pre-read body."""
    raw_headers = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "method": method,
        "path": "/token",
        "query_string": query.encode(),
        "headers": raw_headers,
    }

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


@pytest.fixture
def proxy():
    return create_oauth_proxy(base_url="https://mcp.example.com")


def _steps(caplog):
    return {r.oauth_step: r for r in caplog.records if r.getMessage() == "oauth_step"}


class TestOAuthFunnelEvents:
    async def test_registration_is_recorded_with_its_status(self, proxy, caplog, monkeypatch):
        """
        GIVEN a client registering via DCR
        WHEN the proxy forwards the registration
        THEN an oauth_step event records the outcome and status
        """
        monkeypatch.setattr(
            httpx.AsyncClient,
            "post",
            _responding(httpx.Response(201, json={"client_id": "c-1"})),
        )

        with caplog.at_level(logging.INFO, logger=LOGGER):
            await proxy._handle_register(_request(body=b"{}", headers={"user-agent": "claude-ai/1.0"}))

        step = _steps(caplog)["register"]
        assert step.outcome == "ok"
        assert step.status == 201
        assert step.user_agent == "claude-ai/1.0"

    async def test_a_rejected_registration_is_recorded_as_an_error(self, proxy, caplog, monkeypatch):
        """
        GIVEN a registration the GitGuardian backend rejects
        WHEN the proxy forwards it
        THEN the event records an error outcome with the upstream status
        """
        monkeypatch.setattr(
            httpx.AsyncClient,
            "post",
            _responding(httpx.Response(400, json={"error": "invalid_redirect_uri"})),
        )

        with caplog.at_level(logging.INFO, logger=LOGGER):
            await proxy._handle_register(_request(body=b"{}"))

        step = _steps(caplog)["register"]
        assert step.outcome == "error"
        assert step.status == 400

    async def test_authorize_records_the_client_and_pkce_method(self, proxy, caplog):
        """
        GIVEN an authorize request using PKCE
        WHEN the proxy redirects to the dashboard
        THEN the event records the client id and the challenge method
        """
        with caplog.at_level(logging.INFO, logger=LOGGER):
            await proxy._handle_authorize(
                _request(method="GET", query="client_id=c-1&code_challenge_method=S256&state=xyz")
            )

        step = _steps(caplog)["authorize"]
        assert step.outcome == "redirected"
        assert step.oauth_client_id == "c-1"
        assert step.pkce == "S256"

    async def test_token_exchange_records_the_grant_type(self, proxy, caplog, monkeypatch):
        """
        GIVEN a successful authorization-code exchange
        WHEN the proxy transforms the response
        THEN the event records grant type, client and a success outcome
        """
        monkeypatch.setattr(
            httpx.AsyncClient,
            "post",
            _responding(httpx.Response(200, json={"key": "gg-pat", "scope": ["scan"]})),
        )

        with caplog.at_level(logging.INFO, logger=LOGGER):
            await proxy._handle_token(_request(body=b"grant_type=authorization_code&client_id=c-1&code=abc"))

        step = _steps(caplog)["token"]
        assert step.outcome == "ok"
        assert step.status == 200
        assert step.grant_type == "authorization_code"
        assert step.oauth_client_id == "c-1"

    async def test_a_token_response_without_an_access_token_is_recorded(self, proxy, caplog, monkeypatch):
        """
        GIVEN an upstream 200 carrying no usable token
        WHEN the proxy handles it
        THEN the event distinguishes this from a plain upstream error
        """
        monkeypatch.setattr(httpx.AsyncClient, "post", _responding(httpx.Response(200, json={})))

        with caplog.at_level(logging.INFO, logger=LOGGER):
            await proxy._handle_token(_request(body=b"grant_type=authorization_code&client_id=c-1"))

        assert _steps(caplog)["token"].outcome == "missing_access_token"

    async def test_a_downstream_401_is_recorded(self, caplog):
        """
        GIVEN a tool call the GitGuardian API rejects as unauthorized
        WHEN the request is flagged for re-authentication
        THEN an oauth_step event records it
        """
        with caplog.at_level(logging.INFO, logger=LOGGER):
            mark_downstream_unauthorized()

        step = _steps(caplog)["downstream_unauthorized"]
        assert step.outcome == "reauth_required"
        assert step.status == 401

    async def test_no_secret_material_appears_in_the_events(self, proxy, caplog, monkeypatch):
        """
        GIVEN a token exchange whose form body carries a code and whose response carries a PAT
        WHEN the exchange is logged
        THEN neither the code nor the token appears in the event
        """
        monkeypatch.setattr(httpx.AsyncClient, "post", _responding(httpx.Response(200, json={"key": "gg-pat-secret"})))

        with caplog.at_level(logging.INFO, logger=LOGGER):
            await proxy._handle_token(_request(body=b"grant_type=authorization_code&code=secret-code&client_id=c-1"))

        rendered = str(_steps(caplog)["token"].__dict__)
        assert "gg-pat-secret" not in rendered
        assert "secret-code" not in rendered


def _responding(response: httpx.Response):
    """Replacement for ``AsyncClient.post`` returning a fixed response."""

    async def post(self, url, **kwargs):
        response.request = httpx.Request("POST", url)
        return response

    return post
