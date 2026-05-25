"""ASGI application for the unified MCP server over HTTP/SSE.

This SSE transport requires sticky sessions for horizontal scaling since
session state is maintained in-memory per worker. For stateless operation,
use ``http_app.py`` instead which uses StreamableHTTP with JSON responses.
"""

import logging

from fastmcp.server.http import create_sse_app
from gg_api_core.sentry_integration import init_sentry

from gg_mcp_server.server import mcp

logger = logging.getLogger(__name__)

init_sentry()

sse_app = create_sse_app(
    server=mcp,
    message_path="/messages/",
    sse_path="/sse",
)

# Backward-compatible alias.
app = sse_app

logger.info("MCP SSE application initialized for HTTP/SSE transport")
