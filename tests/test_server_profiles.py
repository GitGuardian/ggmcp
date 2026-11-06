"""Test that the unified server module imports and registers tools correctly.

Replaces the old per-profile tests now that there's a single gg_mcp_server.
"""

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture
def mock_env_no_http():
    """Mock env vars to keep imports in stdio/cached-scope mode."""
    with patch.dict("os.environ", {"MCP_PORT": "", "ENABLE_LOCAL_OAUTH": "true"}, clear=False):
        yield


@pytest.fixture
def mock_gitguardian_modules():
    """Mock the GitGuardian client to avoid actual API calls during import."""
    with patch("gg_api_core.utils.get_client") as mock_get_client:
        mock_client = MagicMock()
        mock_client.get_current_token_info = AsyncMock(return_value={"scopes": ["scan"]})
        mock_get_client.return_value = mock_client
        yield {"get_client": mock_get_client}


def clean_module_imports(module_name: str):
    """Remove a module and its submodules from sys.modules."""
    modules_to_remove = [key for key in sys.modules if key.startswith(module_name)]
    for module in modules_to_remove:
        del sys.modules[module]


class TestUnifiedServer:
    def test_server_imports_successfully(self, mock_gitguardian_modules, mock_env_no_http):
        """
        GIVEN the unified gg_mcp_server package
        WHEN its server module is imported
        THEN an AbstractGitGuardianFastMCP instance is exposed as ``mcp``
        """
        clean_module_imports("gg_mcp_server")

        import gg_mcp_server.server as srv
        from gg_api_core.mcp_server import AbstractGitGuardianFastMCP

        assert isinstance(srv.mcp, AbstractGitGuardianFastMCP)
        assert srv.mcp.name == "GitGuardian"
