"""Test that the unified server module imports and registers tools correctly.

Replaces the old per-profile tests now that there's a single ggmcp.
"""

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture
def mock_env_no_http():
    """Mock env vars to keep imports in stdio/cached-scope mode."""
    with patch.dict("os.environ", {"MCP_AUTH_MODE": "local-oauth"}, clear=False):
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
        GIVEN the unified ggmcp package
        WHEN its server is built
        THEN it exposes a configured AbstractGitGuardianFastMCP instance
        """
        clean_module_imports("ggmcp")

        from gg_api_core.mcp_server import AbstractGitGuardianFastMCP
        from ggmcp.server import build_server

        server = build_server()

        assert isinstance(server, AbstractGitGuardianFastMCP)
        assert server.name == "GitGuardian"

    @pytest.mark.asyncio
    async def test_secops_specific_tools_are_registered(self, mock_gitguardian_modules, mock_env_no_http):
        """
        GIVEN a token holding both read and write scopes
        WHEN the unified server lists tools
        THEN both developer-flavour and secops-flavour tools are present
        """
        clean_module_imports("ggmcp")

        from ggmcp.server import build_server

        server = build_server()
        server._fetch_token_scopes_from_api = AsyncMock()
        server._token_scopes = {
            "scan",
            "incidents:read",
            "incidents:write",
            "sources:read",
            "honeytokens:read",
            "honeytokens:write",
        }

        tools = await server.list_tools()
        tool_names = {tool.name for tool in tools}

        assert "list_incidents" in tool_names
        assert "assign_incident" in tool_names
        assert "create_code_fix_request" in tool_names

    @pytest.mark.asyncio
    async def test_write_tools_hidden_without_write_scope(self, mock_gitguardian_modules, mock_env_no_http):
        """
        GIVEN a token holding only read scopes
        WHEN the unified server lists tools
        THEN write tools are filtered out and read tools remain
        """
        clean_module_imports("ggmcp")

        from ggmcp.server import build_server

        server = build_server()
        server._fetch_token_scopes_from_api = AsyncMock()
        server._token_scopes = {"scan", "incidents:read", "sources:read"}

        tools = await server.list_tools()
        tool_names = {tool.name for tool in tools}

        assert "list_incidents" in tool_names
        assert "assign_incident" not in tool_names
        assert "create_code_fix_request" not in tool_names
