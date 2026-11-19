"""Tests for get_client() to ensure proper tenant isolation and token acquisition."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp.exceptions import ValidationError

from gg_api_core.client import GitGuardianClient
from gg_api_core.utils import get_client

# Prefix every outgoing User-Agent carries, regardless of transport.
UA_PREFIX = GitGuardianClient.DEFAULT_USER_AGENT


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
            user_agent=f"{UA_PREFIX} (transport=http; client=GitGuardian-In-App-Agent)",
        )
        assert result == mock_client

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
