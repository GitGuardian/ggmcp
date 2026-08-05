"""Local OAuth browser and callback lifecycle regression tests.

These tests use a real localhost callback server and a local fake API. The
browser opener is captured rather than launching a real browser, so no real
GitGuardian credentials or external network are involved.
"""

import base64
import hashlib
import json
import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from gg_api_core import oauth
from typing_extensions import override

TEST_TOKEN = "oauth-browser-test-token"
# Token exchange response, as documented at
# https://api.gitguardian.com/docs#tag/OAuth2/operation/public-oauth-token
TOKEN_RESPONSE = {
    "access_token": TEST_TOKEN,
    "token_type": "Bearer",
    "expires_in": None,
    "type": "personal_access_token",
    "name": "browser-flow-token",
    "account_id": 42,
    "expire_at": None,
    "scope": ["scan", "incidents:read"],
    "key": TEST_TOKEN,
    "expire_at_downsized": False,
}
TOKEN_INFO = {
    "id": "token-id",
    "name": "browser-flow-token",
    "workspace_id": 42,
    "type": "personal_access_token",
    "status": "active",
    "created_at": "2026-01-01T00:00:00Z",
    "last_used_at": None,
    "expire_at": None,
    "revoked_at": None,
    "member_id": 7,
    "creator_id": 7,
    "scopes": ["scan", "incidents:read"],
}


class _FakeOAuthApi(BaseHTTPRequestHandler):
    """Serve token exchange and token-info responses for the local flow."""

    token_requests: list[dict[str, Any]] = []
    info_requests: list[dict[str, str | None]] = []

    def do_POST(self) -> None:
        if self.path != "/v1/oauth/token":
            self.send_error(404)
            return
        length = int(self.headers["Content-Length"])
        body = self.rfile.read(length).decode()
        request = {key: values[0] for key, values in parse_qs(body).items()}
        type(self).token_requests.append(request)
        self._send_json(200, TOKEN_RESPONSE)

    def do_GET(self) -> None:
        if self.path != "/v1/api_tokens/self":
            self.send_error(404)
            return
        type(self).info_requests.append(
            {"authorization": self.headers.get("Authorization"), "user_agent": self.headers.get("User-Agent")}
        )
        self._send_json(200, TOKEN_INFO)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @override
    def log_message(self, format: str, *args: Any) -> None:
        pass


@pytest.fixture
def fake_oauth_api() -> Iterator[ThreadingHTTPServer]:
    """Run a local API for token exchange and token introspection."""
    _FakeOAuthApi.token_requests = []
    _FakeOAuthApi.info_requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeOAuthApi)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@pytest.fixture
def token_storage(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[oauth.FileTokenStorage]:
    """Prepare an isolated oauth_process environment and clean it up.

    Provides a temporary token storage, keeps loopback traffic away from any
    configured proxy, and stops every callback server started by the flow.
    """
    storage = oauth.FileTokenStorage(token_file=tmp_path / "tokens.json")
    monkeypatch.setattr(oauth, "FileTokenStorage", lambda: storage)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    callback_servers: list[oauth.CallbackServer] = []

    class CapturedCallbackServer(oauth.CallbackServer):
        @override
        def start(self) -> None:
            super().start()
            callback_servers.append(self)

    monkeypatch.setattr(oauth, "CallbackServer", CapturedCallbackServer)
    try:
        yield storage
    finally:
        # oauth_process cleanup is tracked separately as SI-3956; keep these
        # tests hermetic while that application bug remains open.
        for callback_server in callback_servers:
            callback_server.stop()


def _free_local_port() -> int:
    """Reserve an ephemeral port number for a callback-server test."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class TestCallbackServer:
    """Lifecycle of the real localhost OAuth callback server."""

    @pytest.fixture
    def callback_server(self) -> Iterator[oauth.CallbackServer]:
        """Run a callback server on a free port and verify it stops cleanly."""
        port = _free_local_port()
        server = oauth.CallbackServer(port_range=(port, port))
        server.start()
        try:
            yield server
        finally:
            server.stop()
            assert server.thread is not None
            assert not server.thread.is_alive()

    def test_captures_success_callback(self, callback_server: oauth.CallbackServer) -> None:
        """
        GIVEN a real localhost OAuth callback server
        WHEN a browser redirects with an authorization code and state
        THEN the callback is captured and exposed to the waiting flow
        """
        assert callback_server.port == callback_server.port_range[0]
        response = httpx.get(
            f"http://127.0.0.1:{callback_server.port}",
            params={"code": "authorization-code", "state": "expected-state"},
            timeout=5,
            trust_env=False,
        )
        assert response.status_code == 200
        assert callback_server.wait_for_callback(timeout=5) == "authorization-code"
        assert callback_server.get_state() == "expected-state"

    def test_surfaces_provider_errors(self, callback_server: oauth.CallbackServer) -> None:
        """
        GIVEN a real localhost OAuth callback server
        WHEN the provider redirects with an OAuth error
        THEN the callback wait raises the provider error
        """
        response = httpx.get(
            f"http://127.0.0.1:{callback_server.port}",
            params={"error": "access_denied"},
            timeout=5,
            trust_env=False,
        )
        assert response.status_code == 400
        with pytest.raises(Exception, match="access_denied"):
            callback_server.wait_for_callback(timeout=5)


@pytest.mark.asyncio
async def test_oauth_process_round_trips_browser_callback_pkce_and_persists_token(
    fake_oauth_api: ThreadingHTTPServer,
    token_storage: oauth.FileTokenStorage,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    GIVEN a local fake GitGuardian API and an OAuth client with no saved token
    WHEN the captured browser callback completes the real oauth_process flow
    THEN PKCE/state, token exchange, token introspection, and persistence all succeed
    """
    browser_query: dict[str, list[str]] = {}

    def capture_browser(authorization_url: str) -> bool:
        nonlocal browser_query
        query = parse_qs(urlparse(authorization_url).query)
        browser_query = query
        assert query["response_type"] == ["code"]
        assert query["scope"] == ["scan incidents:read"]
        assert query["code_challenge_method"] == ["S256"]
        assert len(query["code_challenge"][0]) > 40
        response = httpx.get(
            query["redirect_uri"][0],
            params={"code": "authorization-code", "state": query["state"][0]},
            timeout=5,
            trust_env=False,
        )
        assert response.status_code == 200
        return True

    monkeypatch.setattr(oauth.webbrowser, "open", capture_browser)
    api_url = f"http://127.0.0.1:{fake_oauth_api.server_address[1]}/v1"
    client = oauth.GitGuardianOAuthClient(
        api_url=api_url,
        dashboard_url="https://dashboard.example.test",
        scopes=["scan", "incidents:read"],
        token_name="browser-flow-token",
        token_lifetime=7,
    )

    assert await client.oauth_process() == TEST_TOKEN

    token_request = _FakeOAuthApi.token_requests[0]
    assert token_request["grant_type"] == "authorization_code"
    assert token_request["code"] == "authorization-code"
    assert token_request["client_id"]
    assert token_request["code_verifier"]
    expected_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(token_request["code_verifier"].encode()).digest()).decode().rstrip("=")
    )
    assert browser_query["code_challenge"] == [expected_challenge]
    assert token_request["redirect_uri"].startswith("http://localhost:")
    assert token_request["lifetime"] == "7"
    assert len(_FakeOAuthApi.info_requests) == 1
    assert _FakeOAuthApi.info_requests[0]["authorization"] == f"Token {TEST_TOKEN}"
    assert _FakeOAuthApi.info_requests[0]["user_agent"]
    assert token_storage.get_token("https://dashboard.example.test") == TEST_TOKEN


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("callback_query", "expected_status", "expected_error"),
    [
        ({"code": "code", "state": "wrong-state"}, 200, "State mismatch"),
        ({"error": "access_denied"}, 400, "OAuth error"),
    ],
)
async def test_oauth_process_rejects_an_invalid_callback(
    fake_oauth_api: ThreadingHTTPServer,
    token_storage: oauth.FileTokenStorage,
    monkeypatch: pytest.MonkeyPatch,
    callback_query: dict[str, str],
    expected_status: int,
    expected_error: str,
) -> None:
    """
    GIVEN an OAuth flow waiting for a localhost callback
    WHEN the callback returns an invalid state or provider error
    THEN the flow rejects the callback before exchanging an authorization code
    """

    def capture_browser(authorization_url: str) -> bool:
        query = parse_qs(urlparse(authorization_url).query)
        response = httpx.get(query["redirect_uri"][0], params=callback_query, timeout=5, trust_env=False)
        assert response.status_code == expected_status
        return True

    monkeypatch.setattr(oauth.webbrowser, "open", capture_browser)
    client = oauth.GitGuardianOAuthClient(
        api_url=f"http://127.0.0.1:{fake_oauth_api.server_address[1]}/v1",
        dashboard_url="https://dashboard.example.test",
    )

    with pytest.raises(Exception, match=expected_error):
        await client.oauth_process()

    assert _FakeOAuthApi.token_requests == []
