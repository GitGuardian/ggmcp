"""ASGI application for the unified MCP server over StreamableHTTP.

This module exports the ASGI application for use with ASGI servers like gunicorn + uvicorn.
It imports the configured MCP server and exposes its StreamableHTTP application.

This module is specifically for production deployment with gunicorn.
For local development, use the run_http_with_uvicorn() function instead.
"""

import logging

from fastmcp.server.http import create_streamable_http_app
from gg_api_core.sentry_integration import init_sentry

from gg_mcp_server.server import mcp

logger = logging.getLogger(__name__)

init_sentry()

# StreamableHTTP with json_response=True and stateless_http=True allows
# horizontal scaling without sticky sessions since no session state is
# maintained between requests.
http_app = create_streamable_http_app(
    server=mcp,
    streamable_http_path="/mcp",
    auth=mcp.auth,
    json_response=True,
    stateless_http=True,
)

# Backward-compatible alias for callers (e.g. gunicorn configs) that imported
# the SecOps server's ``app`` attribute.
app = http_app

logger.info("MCP application initialized for StreamableHTTP transport (stateless JSON mode)")
