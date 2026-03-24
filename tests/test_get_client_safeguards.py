"""Tests for get_client() to ensure proper tenant isolation and token acquisition."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp.exceptions import ValidationError
from gg_api_core.utils import _get_caller_user_agent, get_client, get_mcp_port_or_none, is_multi_tenant_mode


class TestGetMcpPortOrNone:
    """Tests for get_mcp_port_or_none() helper."""

    def test_returns_none_when_not_set(self):
        """
        GIVEN MCP_PORT is not set
        WHEN get_mcp_port_or_none is called
        THEN it returns None
        """
        with patch.dict(os.environ, {}, clear=True):
            assert get_mcp_port_or_none() is None

    def test_returns_port_when_set(self):
        """
        GIVEN MCP_PORT is set
        WHEN get_mcp_port_or_none is called
        THEN it returns the port value
        """
        with patch.dict(os.environ, {"MCP_PORT": "8080"}, clear=True):
            assert get_mcp_port_or_none() == "8080"


class TestIsMultiTenantMode:
    """Tests for is_multi_tenant_mode() helper function."""

    def test_returns_false_by_default(self):
        """
        GIVEN no env vars are set
        WHEN is_multi_tenant_mode is called
        THEN it returns False (single-tenant is the default)
        """
        with patch.dict(os.environ, {}, clear=True):
            assert is_multi_tenant_mode() is False

    def test_returns_true_when_enabled(self):
        """
        GIVEN MULTI_TENANCY_ENABLED=true
        WHEN is_multi_tenant_mode is called
        THEN it returns True
        """
        with patch.dict(os.environ, {"MULTI_TENANCY_ENABLED": "true"}, clear=True):
            assert is_multi_tenant_mode() is True

    def test_returns_false_when_disabled(self):
        """
        GIVEN MULTI_TENANCY_ENABLED=false
        WHEN is_multi_tenant_mode is called
        THEN it returns False
        """
        with patch.dict(os.environ, {"MULTI_TENANCY_ENABLED": "false"}, clear=True):
            assert is_multi_tenant_mode() is False

    def test_case_insensitive(self):
        """
        GIVEN MULTI_TENANCY_ENABLED=TRUE (uppercase)
        WHEN is_multi_tenant_mode is called
        THEN it returns True
        """
        with patch.dict(os.environ, {"MULTI_TENANCY_ENABLED": "TRUE"}, clear=True):
            assert is_multi_tenant_mode() is True


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

        mock_client_class.assert_called_once_with(personal_access_token="explicit-token", user_agent=None)
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

        mock_client_class.assert_called_once_with(personal_access_token="explicit-token", user_agent=None)
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

        mock_client_class.assert_called_once_with(personal_access_token="request-token", user_agent=None)
        assert result == mock_client

    @patch("gg_api_core.utils.get_http_headers")
    @patch("gg_api_core.utils.GitGuardianClient")
    async def test_multi_tenant_forwards_caller_user_agent(self, mock_client_class, mock_get_headers):
        """
        GIVEN MULTI_TENANCY_ENABLED=true and MCP_PORT is set
        AND request has both Authorization and User-Agent headers
        WHEN get_client is called
        THEN the caller's User-Agent is forwarded to GitGuardianClient
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
            user_agent="GitGuardian-In-App-Agent",
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
    def test_returns_none_on_exception(self, mock_get_headers):
        """
        GIVEN get_http_headers raises an exception
        WHEN _get_caller_user_agent is called
        THEN it returns None (graceful degradation)
        """
        mock_get_headers.side_effect = RuntimeError("Unexpected error")

        result = _get_caller_user_agent()

        assert result is None

    @patch("gg_api_core.utils.get_http_headers")
    @patch("gg_api_core.utils.GitGuardianClient")
    async def test_get_client_auto_extracts_user_agent(self, mock_client_class, mock_get_headers):
        """
        GIVEN an HTTP request with User-Agent header
        WHEN get_client() is called without explicit user_agent (as tool handlers do)
        THEN the caller's User-Agent is automatically forwarded to GitGuardianClient
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
            user_agent="GitGuardian-In-App-Agent",
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

        mock_client_class.assert_called_once_with(
            personal_access_token="explicit-token",
            user_agent="Custom-Agent",
        )
