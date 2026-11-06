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

    @pytest.mark.asyncio
    async def test_write_tools_are_listed_with_write_scope(self, mock_gitguardian_modules, mock_env_no_http):
        """
        GIVEN a token holding both read and write scopes
        WHEN the server lists tools
        THEN both read and write tools are present
        """
        clean_module_imports("gg_mcp_server")

        import gg_mcp_server.server as srv

        srv.mcp._fetch_token_scopes_from_api = AsyncMock()
        srv.mcp._token_scopes = {
            "scan",
            "incidents:read",
            "incidents:write",
            "sources:read",
            "honeytokens:read",
            "honeytokens:write",
        }

        tools = await srv.mcp.list_tools()
        tool_names = {tool.name for tool in tools}

        assert "list_incidents" in tool_names
        assert "assign_incident" in tool_names
        assert "manage_private_incident" in tool_names

    @pytest.mark.asyncio
    async def test_write_tools_hidden_without_write_scope(self, mock_gitguardian_modules, mock_env_no_http):
        """
        GIVEN a token holding only read scopes
        WHEN the unified server lists tools
        THEN write tools are filtered out and read tools remain
        """
        clean_module_imports("gg_mcp_server")

        import gg_mcp_server.server as srv

        srv.mcp._fetch_token_scopes_from_api = AsyncMock()
        srv.mcp._token_scopes = {"scan", "incidents:read", "sources:read"}

        tools = await srv.mcp.list_tools()
        tool_names = {tool.name for tool in tools}

        assert "list_incidents" in tool_names
        assert "assign_incident" not in tool_names
        assert "manage_private_incident" not in tool_names


class TestDeprecatedCommands:
    @pytest.mark.parametrize("command", ["developer-mcp-server", "secops-mcp-server"])
    def test_deprecated_command_still_starts_the_server(self, command):
        """
        GIVEN a client configuration that still launches a deprecated command
        WHEN the installed console script is resolved
        THEN it points at the deprecated alias of the server entry point
        """
        from importlib.metadata import entry_points

        (entry,) = [ep for ep in entry_points(group="console_scripts") if ep.name == command]
        assert entry.value == "gg_mcp_server.run:run_deprecated_alias"

    def test_deprecated_alias_warns_then_runs_the_server(self, monkeypatch):
        """
        GIVEN the deprecated alias entry point
        WHEN it is invoked
        THEN it emits a DeprecationWarning naming the command and runs the server
        """
        import gg_mcp_server.run as run

        calls = []
        monkeypatch.setattr(run, "run_mcp_server", lambda: calls.append("ran"))
        monkeypatch.setattr(sys, "argv", ["/usr/local/bin/developer-mcp-server"])

        with pytest.warns(DeprecationWarning, match="developer-mcp-server is deprecated"):
            run.run_deprecated_alias()

        assert calls == ["ran"]
