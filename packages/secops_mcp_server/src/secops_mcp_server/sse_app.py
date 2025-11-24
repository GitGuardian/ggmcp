"""ASGI application for MCP server over HTTP/SSE.

This module exports the ASGI application for use with ASGI servers like gunicorn + uvicorn.
It imports the configured MCP server and exposes its SSE application.

This module is specifically for production deployment with gunicorn.
For local development, use the run_http_with_uvicorn() function instead.
"""

import logging

from gg_api_core.sentry_integration import init_sentry

from secops_mcp_server.server import mcp

logger = logging.getLogger(__name__)

# Initialize Sentry for production deployment
init_sentry()

# Export the ASGI application
# This will be used by gunicorn as: secops_mcp_server.sse_app:app
app = mcp.sse_app()

logger.info("MCP SSE application initialized for HTTP/SSE transport")
