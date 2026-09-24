"""Behavior of the local (stdio) server: PAT-from-env auth, startup scope
caching, 401 self-healing, and transport-agnostic git source resolution.

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
from gg_mcp_server.server import build_server
from mcp.types import TextContent

from tests.e2e.harness import (
    EXPECTED_FULL_TOOL_CATALOG,
    EXPECTED_SCAN_ONLY_TOOL_CATALOG,
    assert_authenticated_request,
    token_info,
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
    """Single-tenant mode caches one client per process; isolate each test."""
    utils._client_singleton = None
    yield
    utils._client_singleton = None


class TestPatEnvAuthentication:
    """Authentication-source and identity behavior for local stdio sessions."""

    async def test_the_env_token_wins_over_stored_oauth_with_the_stdio_marker(
        self,
        stdio_env: None,
        monkeypatch: pytest.MonkeyPatch,
        gg_api: Any,
        mock_token_scopes: Any,
    ) -> None:
        """
        GIVEN both an env PAT and a different stored OAuth token
        WHEN a tool is called
        THEN the env PAT wins and reaches every API request with a User-Agent
             marking the stdio transport
        """
        oauth.FileTokenStorage().save_token(
            "https://dashboard.gitguardian.com",
            {"access_token": "decoy-stored-token"},
        )

        async def unexpected_oauth_flow(*_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("interactive OAuth must not start while an env PAT exists")

        monkeypatch.setattr(client_module, "_run_oauth_flow", unexpected_oauth_flow)
        scope_route = mock_token_scopes()
        route = gg_api.get("/incidents/secrets/77").respond(200, json=INCIDENT)

        server = build_server()
        assert server.authentication_mode.value == "PERSONAL_ACCESS_TOKEN_ENV_VAR"
        async with Client(server) as client:
            result = await client.call_tool("get_incident", {"params": {"incident_id": 77}})

        assert result.structured_content == {"incident": INCIDENT}
        assert_authenticated_request(scope_route, STDIO_PAT)
        assert_authenticated_request(route, STDIO_PAT)
        assert "(transport=stdio)" in route.calls.last.request.headers["User-Agent"]

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

    async def test_get_authenticated_user_info_reports_the_env_var_mode(
        self,
        stdio_env: None,
        gg_api: Any,
        mock_token_scopes: Any,
    ) -> None:
        """
        GIVEN a stdio server authenticated by the PAT env var
        WHEN get_authenticated_user_info is called
        THEN it reports the PERSONAL_ACCESS_TOKEN_ENV_VAR mode and the scopes
        """
        mock_token_scopes(scopes=["scan", "incidents:read"])

        async with Client(build_server()) as client:
            result = await client.call_tool("get_authenticated_user_info", {})

        output = result.structured_content
        assert output is not None
        assert output["authentication_mode"] == "PERSONAL_ACCESS_TOKEN_ENV_VAR"
        assert set(output["available_scopes"]) == {"scan", "incidents:read"}

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
            assert scope_route.call_count == 1
            await client.list_tools()
            await client.list_tools()

        # Unlike the remote server, which re-fetches scopes per tools/list.
        assert scope_route.call_count == 1
        assert_authenticated_request(scope_route, STDIO_PAT)
        assert "(transport=stdio)" in scope_route.calls.last.request.headers["User-Agent"]

    async def test_scan_only_token_prunes_the_catalog_at_startup(
        self,
        stdio_env: None,
        gg_api: Any,
        mock_token_scopes: Any,
    ) -> None:
        """
        GIVEN a scan-only token in the environment
        WHEN the session starts
        THEN only scan-gated and ungated tools are listed
        """
        mock_token_scopes(scopes=["scan"])

        async with Client(build_server()) as client:
            names = {tool.name for tool in await client.list_tools()}

        assert names == EXPECTED_SCAN_ONLY_TOOL_CATALOG

    async def test_full_scope_token_exposes_the_exact_stdio_catalog(
        self,
        stdio_env: None,
        gg_api: Any,
        mock_token_scopes: Any,
    ) -> None:
        """
        GIVEN a stdio token holding every supported GitGuardian scope
        WHEN the session lists tools
        THEN the complete production catalog is visible with no missing extras
        """
        mock_token_scopes()

        async with Client(build_server()) as client:
            names = {tool.name for tool in await client.list_tools()}

        assert names == EXPECTED_FULL_TOOL_CATALOG

    async def test_startup_scope_fetch_failure_degrades_instead_of_crashing(
        self,
        stdio_env: None,
        gg_api: Any,
        no_retry_delay: None,
    ) -> None:
        """
        GIVEN the API failing while the server starts
        WHEN the session opens anyway and the API later recovers
        THEN startup survives and the next tools/list re-fetches the scopes
        """
        failed_startup_route = gg_api.get("/api_tokens/self").respond(500, text="boom")

        async with Client(build_server()) as client:
            assert failed_startup_route.called
            # Startup swallowed the failure; the cache is empty, so the next
            # listing fetches live and sees the recovered API.
            recovered = gg_api.get("/api_tokens/self").respond(200, json=token_info())
            names = {tool.name for tool in await client.list_tools()}

        assert recovered.called
        assert "list_incidents" in names


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

    async def test_a_persistently_invalid_token_is_retried_only_once(
        self,
        stdio_env: None,
        gg_api: Any,
        mock_token_scopes: Any,
    ) -> None:
        """
        GIVEN the API rejecting both the original and reacquired token
        WHEN a tool is called
        THEN self-healing stops after one refresh attempt and returns an error
        """
        route = gg_api.get("/incidents/secrets/77").respond(401, json={"detail": "Invalid API key."})

        async with Client(build_server()) as client:
            result = await client.call_tool(
                "get_incident",
                {"params": {"incident_id": 77}},
                raise_on_error=False,
            )

        assert route.call_count == 2
        assert result.is_error is True
        error_content = result.content[0]
        assert isinstance(error_content, TextContent)
        assert "401" in error_content.text

    async def test_a_forbidden_token_is_not_refreshed(
        self,
        stdio_env: None,
        gg_api: Any,
        mock_token_scopes: Any,
    ) -> None:
        """
        GIVEN a valid token lacking permission for an API operation
        WHEN the API returns 403
        THEN the client surfaces the denial without attempting token refresh
        """
        route = gg_api.get("/incidents/secrets/77").respond(403, json={"detail": "Forbidden."})

        async with Client(build_server()) as client:
            result = await client.call_tool(
                "get_incident",
                {"params": {"incident_id": 77}},
                raise_on_error=False,
            )

        assert route.call_count == 1
        assert result.is_error is True
        error_content = result.content[0]
        assert isinstance(error_content, TextContent)
        assert "403" in error_content.text


class TestLocalGitIntrospection:
    """GitGuardian source resolution is transport-agnostic for stdio.

    The local (stdio) server no longer shells out to git; it resolves the
    repository name solely from ``remote_url`` exactly like the hosted (HTTP)
    server, so both transports share one code path.
    """

    async def test_find_current_source_id_resolves_from_remote_url(
        self,
        stdio_env: None,
        gg_api: Any,
        mock_token_scopes: Any,
    ) -> None:
        """
        GIVEN a stdio server and a remote_url supplied by the agent
        WHEN find_current_source_id is called with that remote_url
        THEN the workspace sources are searched by the bare repository name and
             the matching source id is returned (same as on the hosted server)
        """
        route = gg_api.get("/sources").respond(200, json=[{"id": 99, "name": "widget-factory"}])

        async with Client(build_server()) as client:
            result = await client.call_tool(
                "find_current_source_id",
                {"remote_url": "git@github.com:acme/widget-factory.git"},
            )

        assert dict(route.calls.last.request.url.params) == {"search": "widget-factory", "per_page": "50"}
        assert result.structured_content is not None
        output = result.structured_content["result"]
        assert output["source_id"] == 99
        assert output["repository_name"] == "widget-factory"

    async def test_find_current_source_id_without_remote_url_returns_the_suggestion(
        self,
        stdio_env: None,
        gg_api: Any,
        mock_token_scopes: Any,
    ) -> None:
        """
        GIVEN a stdio server and no remote_url
        WHEN find_current_source_id is called without arguments
        THEN it returns the same run-git-yourself suggestion as the hosted server
             and does not touch the API
        """
        async with Client(build_server()) as client:
            result = await client.call_tool("find_current_source_id", {})

        assert result.structured_content is not None
        output = result.structured_content["result"]
        assert "git config --get remote.origin.url" in output["suggestion"]
        assert output["message"] == "The repository could not be detected server-side."
        assert not [call for call in gg_api.calls if call.request.url.path == "/v1/sources"]

    async def test_find_current_source_id_reports_when_no_source_matches(
        self,
        stdio_env: None,
        gg_api: Any,
        mock_token_scopes: Any,
    ) -> None:
        """
        GIVEN a remote_url for a repository that has no matching GitGuardian source
        WHEN find_current_source_id searches for its repository name
        THEN it returns a useful not-found error rather than a source id
        """
        route = gg_api.get("/sources").respond(200, json=[])

        async with Client(build_server()) as client:
            result = await client.call_tool(
                "find_current_source_id",
                {"remote_url": "git@github.com:acme/unmonitored-repository.git"},
            )

        assert route.call_count == 1
        assert dict(route.calls.last.request.url.params) == {
            "search": "unmonitored-repository",
            "per_page": "50",
        }
        assert result.structured_content is not None
        output = result.structured_content["result"]
        assert output["repository_name"] == "unmonitored-repository"
        assert output["error"] == "Repository 'unmonitored-repository' not found in GitGuardian"
        assert "source_id" not in output
