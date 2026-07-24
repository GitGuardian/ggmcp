"""FastMCP middleware for GitGuardian MCP servers."""

import logging
import time
from collections.abc import Sequence
from typing import TYPE_CHECKING

import mcp.types as mt
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import Tool, ToolResult

from gg_api_core.client import DownstreamUnauthorizedError
from gg_api_core.oauth_proxy_auth import mark_downstream_unauthorized

if TYPE_CHECKING:
    from gg_api_core.mcp_server import AbstractGitGuardianFastMCP

logger = logging.getLogger(__name__)


class DownstreamUnauthorizedMiddleware(Middleware):
    """Flag the request when a tool surfaces a downstream 401.

    The exception still propagates so FastMCP serializes a JSON-RPC error
    body for clients that ignore the HTTP status. The ASGI middleware
    rewrites the status to 401 based on the flag set here.
    """

    async def on_message(self, context, call_next):
        try:
            return await call_next(context)
        except DownstreamUnauthorizedError:
            mark_downstream_unauthorized()
            raise


class ScopeFilteringMiddleware(Middleware):
    """Middleware to filter tools based on token scopes."""

    def __init__(self, mcp_server: "AbstractGitGuardianFastMCP"):
        self._mcp_server = mcp_server

    async def on_list_tools(
        self,
        context,
        call_next,
    ) -> Sequence[Tool]:
        """Filter tools based on the user's API token scopes."""
        # Get all tools from the next middleware/handler
        all_tools = await call_next(context)

        # Filter tools by scopes
        scopes = await self._mcp_server.get_scopes()
        filtered_tools: list[Tool] = []
        for tool in all_tools:
            tool_name = tool.name
            required_scopes = self._mcp_server._tool_scopes.get(tool_name, set())

            if not required_scopes or required_scopes.issubset(scopes):
                filtered_tools.append(tool)
            else:
                missing_scopes = required_scopes - scopes
                logger.info(f"Removing tool '{tool_name}' due to missing scopes: {', '.join(missing_scopes)}")

        return filtered_tools


class ToolCallLoggingMiddleware(Middleware):
    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        tool = context.message.name
        arguments = context.message.arguments
        start = time.perf_counter()
        try:
            result = await call_next(context)
        except Exception:
            logger.exception(
                "tool_call_failed",
                extra={"tool": tool, "arguments": arguments, "elapsed_ms": round((time.perf_counter() - start) * 1000)},
            )
            raise
        logger.info(
            "tool_call",
            extra={
                "tool": tool,
                "arguments": arguments,
                "status": "ok",
                "elapsed_ms": round((time.perf_counter() - start) * 1000),
            },
        )
        return result
