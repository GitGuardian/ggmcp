"""ASGI application for MCP server over HTTP/SSE.

This module exports the ASGI application for use with ASGI servers like gunicorn + uvicorn.
It imports the configured MCP server and exposes its SSE application.

This module is specifically for production deployment with gunicorn.
For local development, use the run_http_with_uvicorn() function instead.

Note: This SSE transport requires sticky sessions for horizontal scaling since
session state is maintained in-memory per worker. For stateless operation,
use http_app.py instead which uses StreamableHTTP with JSON responses.
"""

import logging

from fastmcp.server.http import create_sse_app
from gg_api_core.sentry_integration import init_sentry

from secops_mcp_server.server import mcp

logger = logging.getLogger(__name__)

# Initialize Sentry for production deployment
init_sentry()

app = create_sse_app(
    server=mcp,
    message_path="/messages/",
    sse_path="/sse",
)

logger.info("MCP SSE application initialized for HTTP/SSE transport")
