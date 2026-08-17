"""ASGI application for the unified MCP server over StreamableHTTP.

This module exports the ASGI application for use with ASGI servers like gunicorn + uvicorn.
It imports the configured MCP server and exposes its StreamableHTTP application.

This module is specifically for production deployment with gunicorn.
For local development, use the run_http_with_uvicorn() function instead.
"""

import logging

from gg_mcp_server.server import build_http_app, get_server

logger = logging.getLogger(__name__)

mcp = get_server()

http_app = build_http_app(mcp)

# Backward-compatible alias for callers (e.g. gunicorn configs) that imported
# the SecOps server's ``app`` attribute.
app = http_app

logger.info("MCP application initialized for StreamableHTTP transport (stateless JSON mode)")
