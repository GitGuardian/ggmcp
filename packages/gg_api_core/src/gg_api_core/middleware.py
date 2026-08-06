"""FastMCP middleware for GitGuardian MCP servers."""

import logging
import re
import time
import uuid
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

import mcp.types as mt
import structlog
from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import Tool, ToolResult
from typing_extensions import override

from gg_api_core.client import DownstreamUnauthorizedError
from gg_api_core.log_context import (
    classify_failure,
    derive_client_identity,
    resolve_caller_identity,
    track_downstream_calls,
)
from gg_api_core.oauth_proxy_auth import mark_downstream_unauthorized
from gg_api_core.settings import get_settings
from gg_api_core.urls import derive_public_api_url

if TYPE_CHECKING:
    from gg_api_core.mcp_server import AbstractGitGuardianFastMCP

logger = logging.getLogger(__name__)

# Shape of an X-Request-ID we are willing to adopt from the caller.
_SAFE_REQUEST_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")

# Handled by ToolCallLoggingMiddleware, which emits a richer line for it.
_TOOL_CALL_METHOD = "tools/call"


def _resolve_request_id() -> str:
    """Return the inbound X-Request-ID or create one for this MCP message."""
    inbound = get_http_headers().get("x-request-id", "")
    return inbound if _SAFE_REQUEST_ID.fullmatch(inbound) else str(uuid.uuid4())


def _resolve_session_id(context: MiddlewareContext[Any]) -> str | None:
    """Return FastMCP's session ID when available."""
    fastmcp_context = context.fastmcp_context
    if fastmcp_context is None:
        return None
    try:
        return fastmcp_context.session_id
    except RuntimeError:
        # Raised when no session exists, e.g. a server-initiated message.
        return None


class RequestLoggingContextMiddleware(Middleware):
    """Bind identity and correlation fields for one MCP message."""

    def __init__(self, mcp_server: "AbstractGitGuardianFastMCP"):
        self._mcp_server = mcp_server

    @override
    async def on_message(self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]) -> Any:
        bindings: dict[str, Any] = {
            "authentication_mode": self._mcp_server.authentication_mode.value,
            "request_id": _resolve_request_id(),
        }

        session_id = _resolve_session_id(context)
        if session_id:
            bindings["mcp_session_id"] = session_id

        user_agent = get_http_headers().get("user-agent")
        if user_agent:
            bindings["user_agent"] = user_agent

        with structlog.contextvars.bound_contextvars(**bindings):
            with structlog.contextvars.bound_contextvars(**await self._caller_identity()):
                return await self._traced(context, call_next)

    async def _traced(self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]) -> Any:
        """Emit one protocol event per non-tool MCP message."""
        method = context.method
        if method == _TOOL_CALL_METHOD:
            return await call_next(context)

        start = time.perf_counter()
        try:
            result = await call_next(context)
        except Exception as exc:
            logger.warning(
                "mcp_request_failed",
                extra={
                    "mcp_method": method,
                    "status": "error",
                    "duration_ms": round((time.perf_counter() - start) * 1000),
                    **classify_failure(exc),
                },
            )
            raise

        logger.info(
            "mcp_request",
            extra={
                "mcp_method": method,
                "status": "ok",
                "duration_ms": round((time.perf_counter() - start) * 1000),
            },
        )
        return result

    async def _caller_identity(self) -> dict[str, Any]:
        """Return caller identifiers without failing the MCP message."""
        return await resolve_caller_identity(
            self._mcp_server.get_token_info,
            token=self._current_token(),
            api_url=derive_public_api_url(get_settings().gitguardian_url),
        )

    def _current_token(self) -> str | None:
        """The bearer token for this request, used only as a cache key."""
        try:
            return self._mcp_server.get_personal_access_token()
        except Exception:
            # Modes that resolve the token lazily inside the client, and
            # requests with no usable bearer token at all.
            return None

    @override
    async def on_initialize(
        self,
        context: MiddlewareContext[mt.InitializeRequest],
        call_next: CallNext[mt.InitializeRequest, mt.InitializeResult | None],
    ) -> mt.InitializeResult | None:
        """Record client and protocol metadata from initialization."""
        params = getattr(context.message, "params", context.message)
        client_identity = derive_client_identity(
            getattr(params, "clientInfo", None),
            getattr(params, "protocolVersion", None),
        )
        with structlog.contextvars.bound_contextvars(**client_identity):
            logger.info("mcp_initialize", extra=client_identity)
            return await call_next(context)


class DownstreamUnauthorizedMiddleware(Middleware):
    """Flag the request when a tool surfaces a downstream 401.

    The exception still propagates so FastMCP serializes a JSON-RPC error
    body for clients that ignore the HTTP status. The ASGI middleware
    rewrites the status to 401 based on the flag set here.
    """

    @override
    async def on_message(self, context: MiddlewareContext[Any], call_next: CallNext[Any, Any]) -> Any:
        try:
            return await call_next(context)
        except DownstreamUnauthorizedError:
            mark_downstream_unauthorized()
            raise


class ScopeFilteringMiddleware(Middleware):
    """Middleware to filter tools based on token scopes."""

    def __init__(self, mcp_server: "AbstractGitGuardianFastMCP"):
        self._mcp_server = mcp_server

    @override
    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        """Filter tools based on the user's API token scopes."""
        # Get all tools from the next middleware/handler
        all_tools = await call_next(context)

        # Filter tools by scopes
        scopes = await self._mcp_server.get_scopes()
        filtered_tools: list[Tool] = []
        hidden: list[str] = []
        for tool in all_tools:
            tool_name = tool.name
            required_scopes = self._mcp_server._tool_scopes.get(tool_name, set())

            if not required_scopes or required_scopes.issubset(scopes):
                filtered_tools.append(tool)
            else:
                hidden.append(tool_name)
                missing_scopes = required_scopes - scopes
                logger.debug(f"Removing tool '{tool_name}' due to missing scopes: {', '.join(missing_scopes)}")

        logger.info(
            "list_tools",
            extra={
                "tools_exposed": len(filtered_tools),
                "tools_hidden": len(hidden),
                "hidden_tools": sorted(hidden),
            },
        )
        return filtered_tools


def _result_shape(result: Any) -> dict[str, Any]:
    """Return the result's text size, block count, and list length."""
    content = getattr(result, "content", None) or []
    result_bytes = 0
    for block in content:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            result_bytes += len(text.encode("utf-8"))

    shape: dict[str, Any] = {"result_blocks": len(content), "result_bytes": result_bytes}

    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        for key in ("data", "result"):
            value = structured.get(key)
            if isinstance(value, list):
                shape["result_items"] = len(value)
                break

    return shape


class ToolCallLoggingMiddleware(Middleware):
    """Log one structured event per tool invocation."""

    @override
    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        tool = context.message.name
        arguments = context.message.arguments or {}

        start = time.perf_counter()
        with track_downstream_calls() as downstream:
            try:
                result = await call_next(context)
            except Exception as exc:
                logger.exception(
                    "tool_call_failed",
                    extra={
                        "tool": tool,
                        "arguments": arguments,
                        "status": "error",
                        "duration_ms": round((time.perf_counter() - start) * 1000),
                        **classify_failure(exc),
                        **downstream.as_log_fields(),
                    },
                )
                raise

            logger.info(
                "tool_call",
                extra={
                    "tool": tool,
                    "arguments": arguments,
                    "status": "ok",
                    "duration_ms": round((time.perf_counter() - start) * 1000),
                    **_result_shape(result),
                    **downstream.as_log_fields(),
                },
            )
        return result
