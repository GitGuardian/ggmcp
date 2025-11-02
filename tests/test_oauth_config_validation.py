"""Test OAuth configuration validation."""

import os
from unittest.mock import patch

import pytest
from gg_api_core.client import GitGuardianClient


class TestOAuthConfigValidation:
    """Test that OAuth configuration is properly validated."""

    def test_raises_error_when_both_mcp_port_and_oauth_enabled(self):
        """Test that an error is raised when both MCP_PORT and ENABLE_LOCAL_OAUTH are set."""
        with patch.dict(os.environ, {"MCP_PORT": "8080", "ENABLE_LOCAL_OAUTH": "true"}):
            with pytest.raises(
                ValueError,
                match=r"Invalid configuration: Cannot use ENABLE_LOCAL_OAUTH=true with MCP_PORT set",
            ):
                GitGuardianClient()

    def test_allows_mcp_port_without_oauth(self):
        """Test that MCP_PORT can be set without ENABLE_LOCAL_OAUTH."""
        with patch.dict(os.environ, {"MCP_PORT": "8080", "ENABLE_LOCAL_OAUTH": "false"}, clear=False):
            # Should not raise
            client = GitGuardianClient()
            assert client is not None

    def test_allows_oauth_without_mcp_port(self):
        """Test that ENABLE_LOCAL_OAUTH can be set without MCP_PORT."""
        with patch.dict(os.environ, {"MCP_PORT": "", "ENABLE_LOCAL_OAUTH": "true"}, clear=False):
            # Should not raise during initialization
            client = GitGuardianClient()
            assert client is not None

    def test_allows_neither_set(self):
        """Test that neither being set is valid (test/default mode)."""
        with patch.dict(os.environ, {"MCP_PORT": "", "ENABLE_LOCAL_OAUTH": "false"}, clear=False):
            # Should not raise
            client = GitGuardianClient()
            assert client is not None

    @pytest.mark.asyncio
    async def test_oauth_disabled_raises_helpful_error(self):
        """Test that attempting OAuth when disabled raises a helpful error."""
        with patch.dict(os.environ, {"ENABLE_LOCAL_OAUTH": "false"}, clear=False):
            client = GitGuardianClient()

            with pytest.raises(RuntimeError):
                # This should raise because OAuth is disabled and no PAT is provided
                await client._ensure_api_token()

    def test_case_insensitive_enable_local_oauth(self):
        """Test that ENABLE_LOCAL_OAUTH is case-insensitive for 'true' value."""
        with patch.dict(os.environ, {"MCP_PORT": "8080", "ENABLE_LOCAL_OAUTH": "TRUE"}):
            with pytest.raises(ValueError, match=r"Invalid configuration"):
                GitGuardianClient()

        with patch.dict(os.environ, {"MCP_PORT": "8080", "ENABLE_LOCAL_OAUTH": "True"}):
            with pytest.raises(ValueError, match=r"Invalid configuration"):
                GitGuardianClient()

    def test_empty_string_is_not_true(self):
        """Test that empty ENABLE_LOCAL_OAUTH is treated as false."""
        with patch.dict(os.environ, {"MCP_PORT": "8080", "ENABLE_LOCAL_OAUTH": ""}, clear=False):
            # Should not raise - empty string is treated as false
            client = GitGuardianClient()
            assert client is not None

    def test_unset_defaults_to_true_and_conflicts_with_mcp_port(self):
        """Test that unset ENABLE_LOCAL_OAUTH defaults to true, which conflicts with MCP_PORT."""
        env = os.environ.copy()
        env.pop("ENABLE_LOCAL_OAUTH", None)
        with patch.dict(os.environ, env, clear=True):
            os.environ["MCP_PORT"] = "8080"
            # Should raise - unset defaults to true, which conflicts with MCP_PORT
            with pytest.raises(ValueError, match=r"Invalid configuration"):
                GitGuardianClient()
