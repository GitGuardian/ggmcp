"""Behavior of the local (stdio) server: PAT-from-env auth, startup scope
caching, 401 self-healing, and local git introspection.

The server is exercised through an in-memory FastMCP client, which runs the
same lifespan, middleware and tools as a stdio session; the raw stdio framing
itself is covered by test_stdio_transport.py. As in the remote suite, only
the outbound GitGuardian API is faked with respx.
"""

from pathlib import Path
from typing import Any, Iterator

import httpx
import pytest
from fastmcp import Client

from gg_api_core import client as client_module
from gg_api_core import oauth, utils
from gg_api_core.log_context import clear_caller_identity_cache
from gg_mcp_server.server import build_server
from tests.e2e.harness import (
    assert_authenticated_request,
)

# Token the local server reads from GITGUARDIAN_PERSONAL_ACCESS_TOKEN.
STDIO_PAT = "stdio-env-pat"

INCIDENT = {"id": 77, "status": "TRIGGERED"}


@pytest.fixture
def stdio_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Environment of a local stdio run authenticated by the PAT env var.

    FileTokenStorage is redirected explicitly because its macOS path does not
    honor XDG_CONFIG_HOME. A 401 self-healing test must never touch the
    developer's real token file.
    """
    storage_class = oauth.FileTokenStorage
    token_file = tmp_path / "tokens" / "mcp_oauth_tokens.json"

    def isolated_token_storage() -> Any:
        return storage_class(token_file=token_file)

    monkeypatch.setattr(oauth, "FileTokenStorage", isolated_token_storage)
    monkeypatch.delenv("MCP_PORT", raising=False)
    monkeypatch.delenv("MULTI_TENANCY_ENABLED", raising=False)
    monkeypatch.delenv("MCP_OAUTH_PROXY_ENABLED", raising=False)
    monkeypatch.delenv("GITGUARDIAN_API_URL", raising=False)
    monkeypatch.setenv("GITGUARDIAN_URL", "https://dashboard.gitguardian.com")
    monkeypatch.setenv("GITGUARDIAN_PERSONAL_ACCESS_TOKEN", STDIO_PAT)
    monkeypatch.setenv("ENABLE_LOCAL_OAUTH", "false")


@pytest.fixture(autouse=True)
def reset_client_singleton() -> Iterator[None]:
    """Single-tenant mode caches one client and one caller identity per process; isolate each test."""
    utils._client_singleton = None
    clear_caller_identity_cache()
    yield
    utils._client_singleton = None
    clear_caller_identity_cache()


class TestPatEnvAuthentication:
    """Authentication-source and identity behavior for local stdio sessions."""

    async def test_default_oauth_mode_still_uses_the_env_token_without_a_browser_flow(
        self,
        stdio_env: None,
        monkeypatch: pytest.MonkeyPatch,
        gg_api: Any,
        mock_token_scopes: Any,
    ) -> None:
        """
        GIVEN the default local setup (ENABLE_LOCAL_OAUTH unset) with a PAT env var
        WHEN a tool is called
        THEN the server runs in LOCAL_OAUTH_FLOW mode but the client picks the
             env token, so no interactive flow is ever needed
        """

        async def unexpected_oauth_flow(*_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("interactive OAuth must not start while an env PAT exists")

        monkeypatch.delenv("ENABLE_LOCAL_OAUTH")
        monkeypatch.setattr(client_module, "_run_oauth_flow", unexpected_oauth_flow)
        route = gg_api.get("/incidents/secrets/77").respond(200, json=INCIDENT)

        server = build_server()
        assert server.authentication_mode.value == "LOCAL_OAUTH_FLOW"
        async with Client(server) as client:
            result = await client.call_tool("get_incident", {"params": {"incident_id": 77}})

        assert result.structured_content == {"incident": INCIDENT}
        assert route.calls.last.request.headers["Authorization"] == f"Token {STDIO_PAT}"

    async def test_stored_oauth_token_is_used_without_starting_a_browser_flow(
        self,
        stdio_env: None,
        monkeypatch: pytest.MonkeyPatch,
        gg_api: Any,
        mock_token_scopes: Any,
    ) -> None:
        """
        GIVEN no PAT environment variable but a stored OAuth token
        WHEN a local OAuth-mode stdio session starts
        THEN it reuses the stored token without opening an interactive flow
        """
        stored_pat = "stdio-stored-oauth-pat"
        monkeypatch.delenv("GITGUARDIAN_PERSONAL_ACCESS_TOKEN")
        monkeypatch.delenv("ENABLE_LOCAL_OAUTH")
        oauth.FileTokenStorage().save_token(
            "https://dashboard.gitguardian.com",
            {"access_token": stored_pat},
        )

        async def unexpected_oauth_flow(*_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("interactive OAuth must not start when a stored token exists")

        monkeypatch.setattr(client_module, "_run_oauth_flow", unexpected_oauth_flow)
        scope_route = mock_token_scopes()
        incident_route = gg_api.get("/incidents/secrets/77").respond(200, json=INCIDENT)

        server = build_server()
        assert server.authentication_mode.value == "LOCAL_OAUTH_FLOW"
        async with Client(server) as client:
            result = await client.call_tool("get_incident", {"params": {"incident_id": 77}})

        assert result.structured_content == {"incident": INCIDENT}
        assert_authenticated_request(scope_route, stored_pat)
        assert_authenticated_request(incident_route, stored_pat)


class TestStartupScopeCache:
    """Startup scope discovery, caching, catalog pruning, and recovery."""

    async def test_scopes_are_fetched_once_at_startup_and_reused(
        self,
        stdio_env: None,
        gg_api: Any,
        mock_token_scopes: Any,
    ) -> None:
        """
        GIVEN a stdio server (single token for its whole lifetime)
        WHEN the session starts and tools/list is requested twice
        THEN the scopes are fetched from the API exactly once, at startup
        """
        scope_route = mock_token_scopes()

        async with Client(build_server()) as client:
            await client.list_tools()
            calls_after_first_list = scope_route.call_count
            await client.list_tools()
            await client.list_tools()

        # Unlike the remote server, which re-fetches scopes per tools/list.
        assert scope_route.call_count == calls_after_first_list
        assert_authenticated_request(scope_route, STDIO_PAT)
        assert "(transport=stdio)" in scope_route.calls.last.request.headers["User-Agent"]


class TestSingleTenantSelfHealing:
    """Retry boundaries for authentication failures in single-tenant stdio."""

    async def test_an_invalid_token_response_is_retried_once_and_succeeds(
        self,
        stdio_env: None,
        gg_api: Any,
        mock_token_scopes: Any,
    ) -> None:
        """
        GIVEN the API rejecting the token once with GitGuardian's invalid-key 401
        WHEN a tool is called
        THEN the stdio client retries once and the tool call succeeds
        """
        seen_authorization: list[str] = []

        def invalid_then_success(request: httpx.Request) -> httpx.Response:
            seen_authorization.append(request.headers["Authorization"])
            if len(seen_authorization) == 1:
                return httpx.Response(401, json={"detail": "Invalid API key."})
            return httpx.Response(200, json=INCIDENT)

        route = gg_api.get("/incidents/secrets/77").mock(side_effect=invalid_then_success)

        async with Client(build_server()) as client:
            result = await client.call_tool("get_incident", {"params": {"incident_id": 77}})

        assert route.call_count == 2
        assert seen_authorization == [f"Token {STDIO_PAT}", f"Token {STDIO_PAT}"]
        assert result.structured_content == {"incident": INCIDENT}
