"""GitGuardian MCP server (unified developer + SecOps surface).

Permissions are governed by the access token's OAuth scopes; tools the
current token cannot satisfy are filtered out at list-tools time.
"""

import logging
from functools import cache

from fastmcp.server.http import create_streamable_http_app
from gg_api_core.logging_config import configure_logging_from_settings
from gg_api_core.mcp_server import (
    AbstractGitGuardianFastMCP,
    get_mcp_server,
    register_common_tools,
)
from gg_api_core.sentry_integration import init_sentry
from gg_api_core.settings import get_settings
from starlette.applications import Starlette

from gg_mcp_server.add_health_check import add_health_check
from gg_mcp_server.register_tools import GITGUARDIAN_INSTRUCTIONS, register_tools

logger = logging.getLogger(__name__)


def build_server() -> AbstractGitGuardianFastMCP:
    """Compose the GitGuardian MCP server: auth mode, tools, health check.

    Pure composition, no process-level side effects (Sentry, logging), so
    tests can build fresh instances of the exact production server.
    """
    mcp = get_mcp_server(
        "GitGuardian",
        instructions=GITGUARDIAN_INSTRUCTIONS,
    )
    register_tools(mcp)
    register_common_tools(mcp)
    add_health_check(mcp)
    return mcp


def build_http_app(mcp: AbstractGitGuardianFastMCP) -> Starlette:
    """Wrap the server in its production StreamableHTTP ASGI app.

    json_response=True and stateless_http=True allow horizontal scaling
    without sticky sessions since no session state is maintained between
    requests.
    """
    return create_streamable_http_app(
        server=mcp,
        streamable_http_path="/mcp",
        auth=mcp.auth,
        json_response=True,
        stateless_http=True,
    )


@cache
def get_server() -> AbstractGitGuardianFastMCP:
    """Build (once) and return the configured GitGuardian MCP server.

    Sentry is initialized here, before the server is constructed, and that
    order is load-bearing: Sentry's ``MCPIntegration`` instruments tool calls
    by patching the lowlevel ``Server`` decorators when ``sentry_sdk.init()``
    runs, and FastMCP consumes those decorators in its constructor. A server
    built before Sentry init never emits ``mcp.server`` spans (SI-3929).
    """
    init_sentry()
    configure_logging_from_settings(get_settings())
    mcp = build_server()
    logger.info("GitGuardian MCP server instance created and configured")
    return mcp


def __getattr__(name: str) -> AbstractGitGuardianFastMCP:
    # Backward compatibility: ``from gg_mcp_server.server import mcp`` still
    # works, but builds the server lazily on first access (PEP 562).
    if name == "mcp":
        return get_server()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
