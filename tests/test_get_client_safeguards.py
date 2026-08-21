"""Tests for get_client() to ensure proper tenant isolation and token acquisition."""

import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp.exceptions import ValidationError
from gg_api_core.client import GitGuardianClient
from gg_api_core.client_identity import ClientIdentity, set_client_identity
from gg_api_core.settings import get_settings
from gg_api_core.utils import _build_user_agent, _get_caller_user_agent, get_client
from mcp.server.session import ServerSession

# Prefix every outgoing User-Agent carries, regardless of transport.
UA_PREFIX = GitGuardianClient.DEFAULT_USER_AGENT


class TestMcpPortSetting:
    """Tests for Settings.mcp_port."""

    def test_returns_none_when_not_set(self):
        """
        GIVEN MCP_PORT is not set
        WHEN get_settings().mcp_port is read
        THEN it returns None
        """
        with patch.dict(os.environ, {}, clear=True):
            assert get_settings().mcp_port is None

    def test_returns_port_when_set(self):
        """
        GIVEN MCP_PORT is set
        WHEN get_settings().mcp_port is read
        THEN it returns the port value
        """
        with patch.dict(os.environ, {"MCP_PORT": "8080"}, clear=True):
            assert get_settings().mcp_port == "8080"


class TestIsMultiTenant:
    """Tests for Settings.is_multi_tenant."""

    def test_returns_false_by_default(self):
        """
        GIVEN no env vars are set
        WHEN get_settings().is_multi_tenant is read
        THEN it returns False (single-tenant is the default)
        """
        with patch.dict(os.environ, {}, clear=True):
            assert get_settings().is_multi_tenant is False

    def test_returns_true_when_enabled(self):
        """
        GIVEN MULTI_TENANCY_ENABLED=true
        WHEN get_settings().is_multi_tenant is read
        THEN it returns True
        """
        with patch.dict(os.environ, {"MULTI_TENANCY_ENABLED": "true"}, clear=True):
            assert get_settings().is_multi_tenant is True

    def test_returns_false_when_disabled(self):
        """
        GIVEN MULTI_TENANCY_ENABLED=false
        WHEN get_settings().is_multi_tenant is read
        THEN it returns False
        """
        with patch.dict(os.environ, {"MULTI_TENANCY_ENABLED": "false"}, clear=True):
            assert get_settings().is_multi_tenant is False

    def test_case_insensitive(self):
        """
        GIVEN MULTI_TENANCY_ENABLED=TRUE (uppercase)
        WHEN get_settings().is_multi_tenant is read
        THEN it returns True
        """
        with patch.dict(os.environ, {"MULTI_TENANCY_ENABLED": "TRUE"}, clear=True):
            assert get_settings().is_multi_tenant is True


class TestGetClientExplicitPAT:
    """Tests for get_client() when PAT is explicitly provided."""

    @patch("gg_api_core.utils.GitGuardianClient")
    async def test_explicit_pat_creates_new_client(self, mock_client_class):
        """
        GIVEN a PAT is explicitly provided
        WHEN get_client is called
        THEN it creates a new client with that PAT (no singleton)
        """
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        result = await get_client(personal_access_token="explicit-token")

        mock_client_class.assert_called_once()
        call_kwargs = mock_client_class.call_args.kwargs
        assert call_kwargs["personal_access_token"] == "explicit-token"
        # The client receives the live UA builder (not a frozen string), so the
        # user agent reflects the session's handshake on every request.
        assert call_kwargs["user_agent"] is _build_user_agent
        assert result == mock_client

    @patch("gg_api_core.utils.GitGuardianClient")
    async def test_explicit_pat_ignores_multi_tenant_mode(self, mock_client_class):
        """
        GIVEN a PAT is explicitly provided AND multi-tenant mode is enabled
        WHEN get_client is called
        THEN it uses the explicit PAT, not the headers
        """
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        with patch.dict(os.environ, {"MULTI_TENANCY_ENABLED": "true", "MCP_PORT": "8080"}, clear=True):
            result = await get_client(personal_access_token="explicit-token")

        # MCP_PORT is set, so the transport marker is http (no caller header here)
        mock_client_class.assert_called_once_with(
            personal_access_token="explicit-token",
            user_agent=_build_user_agent,
        )
        assert result == mock_client


class TestGetClientMultiTenantMode:
    """Tests for get_client() in multi-tenant mode (explicit opt-in)."""

    async def test_multi_tenant_requires_mcp_port(self):
        """
        GIVEN MULTI_TENANCY_ENABLED=true but MCP_PORT is not set
        WHEN get_client is called
        THEN it raises ValidationError
        """
        with patch.dict(os.environ, {"MULTI_TENANCY_ENABLED": "true"}, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                await get_client()

        assert "MCP_PORT" in str(exc_info.value)
        assert "MULTI_TENANCY_ENABLED" in str(exc_info.value)

    @patch("gg_api_core.utils.get_http_headers")
    @patch("gg_api_core.utils.GitGuardianClient")
    async def test_multi_tenant_extracts_token_from_headers(self, mock_client_class, mock_get_headers):
        """
        GIVEN MULTI_TENANCY_ENABLED=true and MCP_PORT is set
        AND Authorization header is present
        WHEN get_client is called
        THEN it extracts token and user-agent from headers and creates new client
        """
        mock_get_headers.return_value = {"authorization": "Bearer request-token"}
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        with patch.dict(os.environ, {"MULTI_TENANCY_ENABLED": "true", "MCP_PORT": "8080"}, clear=True):
            result = await get_client()

        # No user-agent header on the request, so only the transport marker is added
        mock_client_class.assert_called_once_with(
            personal_access_token="request-token",
            user_agent=_build_user_agent,
        )
        assert result == mock_client

    @patch("gg_api_core.utils.get_http_headers")
    @patch("gg_api_core.utils.GitGuardianClient")
    async def test_multi_tenant_forwards_caller_user_agent(self, mock_client_class, mock_get_headers):
        """
        GIVEN MULTI_TENANCY_ENABLED=true and MCP_PORT is set
        AND request has both Authorization and User-Agent headers
        WHEN get_client is called
        THEN the caller's User-Agent is preserved as client=... in the UA string
        """
        mock_get_headers.return_value = {
            "authorization": "Bearer request-token",
            "user-agent": "GitGuardian-In-App-Agent",
        }
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        with patch.dict(os.environ, {"MULTI_TENANCY_ENABLED": "true", "MCP_PORT": "8080"}, clear=True):
            result = await get_client()

        mock_client_class.assert_called_once_with(
            personal_access_token="request-token",
            user_agent=_build_user_agent,
        )
        assert result == mock_client

    @patch("gg_api_core.utils.get_http_headers")
    @patch("gg_api_core.utils.GitGuardianClient")
    async def test_multi_tenant_creates_new_client_per_request(self, mock_client_class, mock_get_headers):
        """
        GIVEN multi-tenant mode is enabled
        WHEN get_client is called multiple times with different tokens
        THEN it creates a new client each time (no singleton)
        """
        # get_http_headers is called twice per get_client():
        # once for user-agent extraction, once for authorization extraction
        mock_get_headers.side_effect = [
            {"authorization": "Bearer token1", "user-agent": "Agent1"},
            {"authorization": "Bearer token1", "user-agent": "Agent1"},
            {"authorization": "Bearer token2", "user-agent": "Agent2"},
            {"authorization": "Bearer token2", "user-agent": "Agent2"},
        ]
        mock_client1 = MagicMock()
        mock_client2 = MagicMock()
        mock_client_class.side_effect = [mock_client1, mock_client2]

        with patch.dict(os.environ, {"MULTI_TENANCY_ENABLED": "true", "MCP_PORT": "8080"}, clear=True):
            result1 = await get_client()
            result2 = await get_client()

        assert mock_client_class.call_count == 2
        assert result1 == mock_client1
        assert result2 == mock_client2

    @patch("gg_api_core.utils.get_http_headers")
    async def test_multi_tenant_raises_on_missing_auth_header(self, mock_get_headers):
        """
        GIVEN multi-tenant mode is enabled
        AND Authorization header is missing
        WHEN get_client is called
        THEN it raises ValidationError
        """
        mock_get_headers.return_value = {"content-type": "application/json"}

        with patch.dict(os.environ, {"MULTI_TENANCY_ENABLED": "true", "MCP_PORT": "8080"}, clear=True):
            with pytest.raises(ValidationError) as exc_info:
                await get_client()

        assert "Missing Authorization header" in str(exc_info.value)


class TestGetClientSingleTenantMode:
    """Tests for get_client() in single-tenant mode (the default)."""

    @patch("gg_api_core.utils.GitGuardianClient")
    async def test_single_tenant_uses_env_pat(self, mock_client_class):
        """
        GIVEN GITGUARDIAN_PERSONAL_ACCESS_TOKEN is set
        WHEN get_client is called
        THEN it uses the PAT from env var and enables token refresh
        """
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        # Reset singleton
        import gg_api_core.utils

        gg_api_core.utils._client_singleton = None

        with patch.dict(os.environ, {"GITGUARDIAN_PERSONAL_ACCESS_TOKEN": "env-token"}, clear=True):
            result = await get_client()

        mock_client_class.assert_called_once()
        call_kwargs = mock_client_class.call_args.kwargs
        assert call_kwargs["personal_access_token"] == "env-token"
        assert call_kwargs["allow_token_refresh"] is True  # Token refresh enabled for single-tenant
        assert result == mock_client

    @patch("gg_api_core.utils.GitGuardianClient")
    async def test_single_tenant_uses_singleton(self, mock_client_class):
        """
        GIVEN single-tenant mode (default)
        WHEN get_client is called multiple times
        THEN it uses the singleton pattern
        """
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        # Reset singleton
        import gg_api_core.utils

        gg_api_core.utils._client_singleton = None

        with patch.dict(os.environ, {"GITGUARDIAN_PERSONAL_ACCESS_TOKEN": "env-token"}, clear=True):
            result1 = await get_client()
            result2 = await get_client()

        # Should only create client once
        mock_client_class.assert_called_once()
        assert result1 == result2

    @patch("gg_api_core.client._get_stored_oauth_token")
    @patch("gg_api_core.utils.GitGuardianClient")
    async def test_single_tenant_uses_stored_oauth_token(self, mock_client_class, mock_get_stored):
        """
        GIVEN no env PAT but stored OAuth token exists
        WHEN get_client is called
        THEN it uses the stored OAuth token and enables token refresh
        """
        mock_get_stored.return_value = "stored-oauth-token"
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        # Reset singleton
        import gg_api_core.utils

        gg_api_core.utils._client_singleton = None

        with patch.dict(os.environ, {}, clear=True):
            result = await get_client()

        mock_client_class.assert_called_once()
        call_kwargs = mock_client_class.call_args.kwargs
        assert call_kwargs["personal_access_token"] == "stored-oauth-token"
        assert call_kwargs["allow_token_refresh"] is True  # Token refresh enabled for single-tenant
        assert result == mock_client

    @patch("gg_api_core.client._run_oauth_flow", new_callable=AsyncMock)
    @patch("gg_api_core.client._get_stored_oauth_token")
    @patch("gg_api_core.utils.GitGuardianClient")
    async def test_single_tenant_triggers_oauth_when_enabled(self, mock_client_class, mock_get_stored, mock_oauth):
        """
        GIVEN no env PAT, no stored token, but ENABLE_LOCAL_OAUTH=true
        WHEN get_client is called
        THEN it triggers the OAuth flow and enables token refresh
        """
        mock_get_stored.return_value = None
        # Mock needs to be an async function since _run_oauth_flow is now async
        mock_oauth.return_value = "oauth-token"
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client

        # Reset singleton
        import gg_api_core.utils

        gg_api_core.utils._client_singleton = None

        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "true"}, clear=True):
            result = await get_client()

        mock_oauth.assert_called_once()
        mock_client_class.assert_called_once()
        call_kwargs = mock_client_class.call_args.kwargs
        assert call_kwargs["personal_access_token"] == "oauth-token"
        assert call_kwargs["allow_token_refresh"] is True  # Token refresh enabled for single-tenant
        assert result == mock_client

    @patch("gg_api_core.client._get_stored_oauth_token")
    async def test_single_tenant_raises_when_no_token_source(self, mock_get_stored):
        """
        GIVEN no env PAT, no stored token, and OAuth disabled
        WHEN get_client is called
        THEN it raises RuntimeError with helpful message
        """
        mock_get_stored.return_value = None

        # Reset singleton
        import gg_api_core.utils

        gg_api_core.utils._client_singleton = None

        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "false"}, clear=True):
            with pytest.raises(RuntimeError) as exc_info:
                await get_client()

        assert "No API token available" in str(exc_info.value)
        assert "GITGUARDIAN_PERSONAL_ACCESS_TOKEN" in str(exc_info.value)
        assert "ENABLE_LOCAL_OAUTH" in str(exc_info.value)


class TestAccountIsolation:
    """Tests specifically verifying account isolation guarantees."""

    @patch("gg_api_core.utils.get_http_headers")
    @patch("gg_api_core.utils.GitGuardianClient")
    async def test_multi_tenant_never_uses_singleton(self, mock_client_class, mock_get_headers):
        """
        GIVEN multi-tenant mode is enabled
        WHEN get_client is called multiple times
        THEN it NEVER uses the singleton (account isolation)
        """
        # Reset singleton to ensure clean state
        import gg_api_core.utils

        gg_api_core.utils._client_singleton = None

        mock_get_headers.return_value = {"authorization": "Bearer token"}
        mock_client_class.return_value = MagicMock()

        with patch.dict(os.environ, {"MULTI_TENANCY_ENABLED": "true", "MCP_PORT": "8080"}, clear=True):
            await get_client()
            await get_client()
            await get_client()

        # Should create a new client for each call
        assert mock_client_class.call_count == 3
        # Singleton should remain None
        assert gg_api_core.utils._client_singleton is None


class TestCallerUserAgentExtraction:
    """Tests for _get_caller_user_agent() and automatic user-agent forwarding."""

    @patch("gg_api_core.utils.get_http_headers")
    def test_extracts_user_agent_from_headers(self, mock_get_headers):
        """
        GIVEN an HTTP request with a User-Agent header
        WHEN _get_caller_user_agent is called
        THEN it returns the user-agent string
        """
        mock_get_headers.return_value = {"user-agent": "GitGuardian-In-App-Agent"}

        result = _get_caller_user_agent()

        assert result == "GitGuardian-In-App-Agent"

    @patch("gg_api_core.utils.get_http_headers")
    def test_returns_none_when_no_user_agent(self, mock_get_headers):
        """
        GIVEN an HTTP request without a User-Agent header
        WHEN _get_caller_user_agent is called
        THEN it returns None
        """
        mock_get_headers.return_value = {"authorization": "Bearer token"}

        result = _get_caller_user_agent()

        assert result is None

    @patch("gg_api_core.utils.get_http_headers")
    def test_returns_none_when_no_http_context(self, mock_get_headers):
        """
        GIVEN no active HTTP request (e.g. stdio transport)
        WHEN _get_caller_user_agent is called
        THEN it returns None
        """
        mock_get_headers.return_value = {}

        result = _get_caller_user_agent()

        assert result is None

    @patch("gg_api_core.utils.get_http_headers")
    @patch("gg_api_core.utils.GitGuardianClient")
    async def test_get_client_auto_extracts_user_agent(self, mock_client_class, mock_get_headers):
        """
        GIVEN an HTTP request with User-Agent header
        WHEN get_client() is called without explicit user_agent (as tool handlers do)
        THEN the caller's User-Agent is preserved as client=... in the built UA
        """
        mock_get_headers.return_value = {
            "authorization": "Bearer request-token",
            "user-agent": "GitGuardian-In-App-Agent",
        }
        mock_client_class.return_value = MagicMock()

        with patch.dict(os.environ, {"MULTI_TENANCY_ENABLED": "true", "MCP_PORT": "8080"}, clear=True):
            await get_client()

        mock_client_class.assert_called_once_with(
            personal_access_token="request-token",
            user_agent=_build_user_agent,
        )

    @patch("gg_api_core.utils.get_http_headers")
    @patch("gg_api_core.utils.GitGuardianClient")
    async def test_explicit_user_agent_takes_precedence(self, mock_client_class, mock_get_headers):
        """
        GIVEN an HTTP request with User-Agent header
        WHEN get_client() is called with an explicit user_agent
        THEN the explicit user_agent is used, not the one from headers
        """
        mock_get_headers.return_value = {"user-agent": "GitGuardian-In-App-Agent"}
        mock_client_class.return_value = MagicMock()

        await get_client(personal_access_token="explicit-token", user_agent="Custom-Agent")

        mock_client_class.assert_called_once()
        call_kwargs = mock_client_class.call_args.kwargs
        assert call_kwargs["personal_access_token"] == "explicit-token"
        assert call_kwargs["user_agent"]() == "Custom-Agent"


def _mock_mcp_context(client_name=None, client_version=None, protocol_version=None):
    """A FastMCP context whose session has stored the given handshake identity."""
    return SimpleNamespace(session=_mock_session(client_name, client_version, protocol_version))


class _FakeSession(ServerSession):
    """Weakref-able stand-in for a ServerSession (SimpleNamespace is not weakref-able)."""

    def __init__(self):
        pass


def _mock_session(client_name=None, client_version=None, protocol_version=None):
    """A session that has gone through initialize: identity already derived and stored."""
    info = SimpleNamespace(name=client_name, version=client_version) if client_name else None
    params = SimpleNamespace(clientInfo=info, protocolVersion=protocol_version)
    identity = ClientIdentity.from_params(params.clientInfo, params.protocolVersion)
    session = _FakeSession()
    set_client_identity(identity, session)
    return session


class TestMcpHandshakeUserAgent:
    """Tests for the client= and mcp= User-Agent fields built from the MCP handshake."""

    @patch("gg_api_core.client_identity.get_context")
    def test_stdio_includes_client_and_protocol_from_handshake(self, mock_get_context):
        """
        GIVEN a stdio session whose initialize handshake carried clientInfo and protocolVersion
        WHEN _build_user_agent is called
        THEN the UA carries transport=stdio plus client= and mcp= fields
        """
        mock_get_context.return_value = _mock_mcp_context("claude-code", "2.0.14", "2025-06-18")

        with patch.dict(os.environ, {}, clear=True):
            ua = _build_user_agent()

        assert ua == f"{UA_PREFIX} (transport=stdio; client=claude-code/2.0.14; mcp=2025-06-18)"

    @patch("gg_api_core.client_identity.get_context")
    def test_client_name_without_version(self, mock_get_context):
        """
        GIVEN a handshake with a client name but no version
        WHEN _build_user_agent is called
        THEN client= carries the bare name
        """
        mock_get_context.return_value = _mock_mcp_context("cursor")

        with patch.dict(os.environ, {}, clear=True):
            ua = _build_user_agent()

        assert "client=cursor" in ua
        assert "mcp=" not in ua

    @patch("gg_api_core.utils.get_http_headers")
    @patch("gg_api_core.client_identity.get_context")
    def test_handshake_identity_preferred_over_http_user_agent(self, mock_get_context, mock_get_headers):
        """
        GIVEN both a handshake clientInfo and an HTTP User-Agent header
        WHEN _build_user_agent is called
        THEN the structured handshake identity wins
        """
        mock_get_context.return_value = _mock_mcp_context("claude-code", "2.0.14")
        mock_get_headers.return_value = {"user-agent": "SomeBrowser/99"}

        with patch.dict(os.environ, {"MCP_PORT": "8080"}, clear=True):
            ua = _build_user_agent()

        assert "client=claude-code/2.0.14" in ua
        assert "SomeBrowser" not in ua

    @patch("gg_api_core.utils.get_http_headers")
    @patch("gg_api_core.client_identity.get_context")
    def test_falls_back_to_http_user_agent_without_handshake(self, mock_get_context, mock_get_headers):
        """
        GIVEN no usable handshake data (e.g. before initialization)
        WHEN _build_user_agent is called on an HTTP request
        THEN the caller's HTTP User-Agent is used as client=
        """
        mock_get_context.side_effect = RuntimeError("no active request")
        mock_get_headers.return_value = {"user-agent": "GitGuardian-In-App-Agent"}

        with patch.dict(os.environ, {"MCP_PORT": "8080"}, clear=True):
            ua = _build_user_agent()

        assert ua == f"{UA_PREFIX} (transport=http; client=GitGuardian-In-App-Agent)"

    @patch("gg_api_core.client_identity.get_context")
    def test_client_controlled_values_are_sanitized(self, mock_get_context):
        """
        GIVEN handshake values containing comment delimiters, control chars, and non-ASCII
        WHEN _build_user_agent is called
        THEN the unsafe characters are stripped from the UA
        """
        mock_get_context.return_value = _mock_mcp_context("Evil) (Agent;", "1.0\x07é", "2025-06-18\n")

        with patch.dict(os.environ, {}, clear=True):
            ua = _build_user_agent()

        assert "client=Evil Agent/1.0" in ua
        assert "mcp=2025-06-18" in ua
        assert "\x07" not in ua
        assert "é" not in ua

    @patch("gg_api_core.client_identity.get_context")
    def test_client_cannot_forge_a_field_inside_the_comment(self, mock_get_context):
        """
        GIVEN a handshake client name shaped like an extra UA field
        WHEN _build_user_agent is called
        THEN the separators are stripped, so only the real mcp= field is present
        """
        mock_get_context.return_value = _mock_mcp_context("foo, mcp=2099", "1.0", "2025-06-18")

        with patch.dict(os.environ, {}, clear=True):
            ua = _build_user_agent()

        assert ua.count("mcp=") == 1
        assert "mcp=2025-06-18" in ua
        assert "2099" in ua.split("client=")[1].split(";")[0]

    @patch("gg_api_core.client_identity.get_context")
    def test_client_field_length_is_capped(self, mock_get_context):
        """
        GIVEN a handshake client name far longer than the field cap
        WHEN _build_user_agent is called
        THEN the client= value is truncated to 64 characters
        """
        mock_get_context.return_value = _mock_mcp_context("a" * 200, "1.0")

        with patch.dict(os.environ, {}, clear=True):
            ua = _build_user_agent()

        client_field = ua.split("client=")[1].split(";")[0].rstrip(")")
        assert client_field == "a" * 64

    @patch("gg_api_core.utils.acquire_single_tenant_token", new_callable=AsyncMock)
    @patch("gg_api_core.utils.GitGuardianClient")
    async def test_singleton_receives_callable_user_agent(self, mock_client_class, mock_acquire):
        """
        GIVEN single-tenant mode (the long-lived singleton client)
        WHEN get_client creates the singleton
        THEN it receives _build_user_agent itself, so the UA is evaluated per request
        """
        mock_acquire.return_value = "env-token"
        mock_client_class.return_value = MagicMock()

        import gg_api_core.utils

        gg_api_core.utils._client_singleton = None

        with patch.dict(os.environ, {"GITGUARDIAN_PERSONAL_ACCESS_TOKEN": "env-token"}, clear=True):
            await get_client()

        assert mock_client_class.call_args.kwargs["user_agent"] is _build_user_agent

    @patch("gg_api_core.client_identity.get_context")
    @patch("gg_api_core.utils.acquire_single_tenant_token", new_callable=AsyncMock)
    async def test_singleton_user_agent_reflects_the_live_handshake(self, mock_acquire, mock_get_context):
        """
        GIVEN one long-lived singleton client created in single-tenant mode
        WHEN its user agent is evaluated across two different initialize handshakes
        THEN each evaluation reflects the handshake of that moment, not the first one
        """
        mock_acquire.return_value = "env-token"

        import gg_api_core.utils

        gg_api_core.utils._client_singleton = None
        with patch.dict(os.environ, {"GITGUARDIAN_PERSONAL_ACCESS_TOKEN": "env-token"}, clear=True):
            client = await get_client()

        mock_get_context.side_effect = [
            _mock_mcp_context("claude-code", "2.0.14", "2025-06-18"),
            _mock_mcp_context("cursor", "1.4.2", "2025-06-18"),
        ]

        assert client._user_agent() == f"{UA_PREFIX} (transport=stdio; client=claude-code/2.0.14; mcp=2025-06-18)"
        assert client._user_agent() == f"{UA_PREFIX} (transport=stdio; client=cursor/1.4.2; mcp=2025-06-18)"
