"""Protocol events exercised through a real FastMCP client."""

import logging

import pytest
from fastmcp import Client, FastMCP
from gg_api_core.middleware import RequestLoggingContextMiddleware, ScopeFilteringMiddleware

from tests.test_middleware import FakeServer


class FakeScopedServer(FakeServer):
    """A FakeServer that also answers the scope-filtering surface."""

    def __init__(self, scopes, tool_scopes):
        super().__init__()
        self._scopes = scopes
        self._tool_scopes = tool_scopes

    async def get_scopes(self):
        return self._scopes


@pytest.fixture
def server():
    mcp = FastMCP("lifecycle")
    mcp.add_middleware(RequestLoggingContextMiddleware(FakeServer()))

    @mcp.tool
    async def visible_tool() -> str:
        return "ok"

    @mcp.resource("data://sample")
    async def sample_resource() -> str:
        return "sample"

    @mcp.prompt
    async def sample_prompt() -> str:
        return "prompt"

    return mcp


def _events(caplog, name):
    return [r for r in caplog.records if r.getMessage() == name]


class TestProtocolLifecycleEvents:
    async def test_every_dispatched_protocol_method_is_recorded(self, server, caplog):
        """
        GIVEN a client that connects and exercises the list and read methods
        WHEN the session runs
        THEN each method produces an mcp_request line
        """
        with caplog.at_level(logging.INFO, logger="gg_api_core.middleware"):
            async with Client(server) as client:
                await client.list_tools()
                await client.list_resources()
                await client.list_prompts()

        methods = [r.mcp_method for r in _events(caplog, "mcp_request")]
        assert "initialize" in methods
        assert "tools/list" in methods
        assert "resources/list" in methods
        assert "prompts/list" in methods

    async def test_ping_is_not_dispatched_through_middleware(self, server, caplog):
        """
        GIVEN a client that pings
        WHEN the ping is answered
        THEN no mcp_request line is emitted
        """
        with caplog.at_level(logging.INFO, logger="gg_api_core.middleware"):
            async with Client(server) as client:
                caplog.clear()
                await client.ping()

        assert _events(caplog, "mcp_request") == []

    async def test_tool_calls_are_not_double_logged(self, server, caplog):
        """
        GIVEN a tool call
        WHEN it is handled
        THEN no mcp_request line is emitted for it
        """
        with caplog.at_level(logging.INFO, logger="gg_api_core.middleware"):
            async with Client(server) as client:
                await client.call_tool("visible_tool", {})

        methods = [r.mcp_method for r in _events(caplog, "mcp_request")]
        assert "tools/call" not in methods

    async def test_initialize_records_the_client_and_protocol_version(self, server, caplog):
        """
        GIVEN a client connecting
        WHEN the handshake completes
        THEN mcp_initialize names the client and the protocol revision
        """
        with caplog.at_level(logging.INFO, logger="gg_api_core.middleware"):
            async with Client(server):
                pass

        (rec,) = _events(caplog, "mcp_initialize")
        assert rec.client_name
        assert rec.protocol_version


class TestListToolsCounts:
    async def test_reports_exposed_and_hidden_counts_in_one_event(self, caplog):
        """
        GIVEN a token whose scopes hide one of two tools
        WHEN tools are listed
        THEN a single list_tools event carries both counts and the hidden names
        """
        mcp = FastMCP("scoped")
        fake = FakeScopedServer(scopes={"scan"}, tool_scopes={"needs_incidents": {"incidents:read"}})
        mcp.add_middleware(ScopeFilteringMiddleware(fake))

        @mcp.tool
        async def scan_tool() -> str:
            return "ok"

        @mcp.tool(name="needs_incidents")
        async def needs_incidents() -> str:
            return "ok"

        with caplog.at_level(logging.DEBUG, logger="gg_api_core.middleware"):
            async with Client(mcp) as client:
                tools = await client.list_tools()

        assert [t.name for t in tools] == ["scan_tool"]
        (rec,) = _events(caplog, "list_tools")
        assert rec.tools_exposed == 1
        assert rec.tools_hidden == 1
        assert rec.hidden_tools == ["needs_incidents"]

    async def test_per_tool_removal_lines_are_debug_only(self, caplog):
        """
        GIVEN a hidden tool
        WHEN tools are listed at INFO
        THEN no per-tool removal line is emitted
        """
        mcp = FastMCP("scoped")
        fake = FakeScopedServer(scopes={"scan"}, tool_scopes={"needs_incidents": {"incidents:read"}})
        mcp.add_middleware(ScopeFilteringMiddleware(fake))

        @mcp.tool(name="needs_incidents")
        async def needs_incidents() -> str:
            return "ok"

        with caplog.at_level(logging.INFO, logger="gg_api_core.middleware"):
            async with Client(mcp) as client:
                await client.list_tools()

        assert not [r for r in caplog.records if "Removing tool" in r.getMessage()]
