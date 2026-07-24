"""FastMCP middleware for GitGuardian MCP servers."""

import logging
import time
import uuid
from collections.abc import Sequence
from typing import TYPE_CHECKING

import mcp.types as mt
import structlog
from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import Tool, ToolResult

from gg_api_core.client import DownstreamUnauthorizedError
from gg_api_core.oauth_proxy_auth import mark_downstream_unauthorized

if TYPE_CHECKING:
    from gg_api_core.mcp_server import AbstractGitGuardianFastMCP

logger = logging.getLogger(__name__)


def _resolve_request_id() -> str:
    """Trace id for the request: the inbound X-Request-ID when present, else a fresh uuid4.

    Reusing an upstream-supplied X-Request-ID lets a request be traced across
    services; the uuid4 fallback guarantees stdio requests (no HTTP headers)
    and header-less HTTP requests still get a unique id.
    """
    try:
        request_id = get_http_headers().get("x-request-id")
    except Exception:
        request_id = None
    return request_id or str(uuid.uuid4())


class RequestLoggingContextMiddleware(Middleware):
    """Bind per-request context so every log line of a request shares it.

    Binds ``request_id`` (a trace id) on every request, and ``account_id``
    (the authenticated workspace) only when the server already caches its
    token info — single-tenant modes. HTTP bearer / OAuth-proxy modes do not
    cache it, so we skip the bind there rather than add a token-info API call
    to the per-message hot path. ``merge_contextvars`` (first in the logging
    chain) then flows these onto both structlog and stdlib log lines.
    """

    def __init__(self, mcp_server: "AbstractGitGuardianFastMCP"):
        self._mcp_server = mcp_server

    async def _resolve_account_id(self) -> int | str | None:
        if not getattr(self._mcp_server, "caches_token_info", False):
            return None
        try:
            token_info = await self._mcp_server.get_token_info()
            return token_info.get("workspace_id")
        except Exception:
            return None

    async def on_message(self, context, call_next):
        fields: dict[str, object] = {"request_id": _resolve_request_id()}
        account_id = await self._resolve_account_id()
        if account_id is not None:
            fields["account_id"] = account_id

        with structlog.contextvars.bound_contextvars(**fields):
            return await call_next(context)


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
