"""GitGuardian MCP server (unified developer + SecOps surface).

Permissions are governed by the access token's OAuth scopes; tools the
current token cannot satisfy are filtered out at list-tools time.
"""

import logging
from functools import cache

from gg_api_core.logging_config import configure_logging_from_settings
from gg_api_core.mcp_server import (
    AbstractGitGuardianFastMCP,
    get_mcp_server,
    register_common_tools,
)
from gg_api_core.sentry_integration import init_sentry
from gg_api_core.settings import get_settings

from gg_mcp_server.add_health_check import add_health_check
from gg_mcp_server.register_tools import GITGUARDIAN_INSTRUCTIONS, register_tools

logger = logging.getLogger(__name__)


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
    mcp = get_mcp_server(
        "GitGuardian",
        instructions=GITGUARDIAN_INSTRUCTIONS,
    )
    register_tools(mcp)
    register_common_tools(mcp)
    add_health_check(mcp)
    logger.info("GitGuardian MCP server instance created and configured")
    return mcp


def __getattr__(name: str) -> AbstractGitGuardianFastMCP:
    # Backward compatibility: ``from gg_mcp_server.server import mcp`` still
    # works, but builds the server lazily on first access (PEP 562).
    if name == "mcp":
        return get_server()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
