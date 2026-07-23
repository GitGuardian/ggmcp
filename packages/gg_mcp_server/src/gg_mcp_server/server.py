"""GitGuardian MCP server (unified developer + SecOps surface).

Permissions are governed by the access token's OAuth scopes; tools the
current token cannot satisfy are filtered out at list-tools time.
"""

import logging

from gg_api_core.logging_config import configure_logging_from_settings
from gg_api_core.mcp_server import get_mcp_server, register_common_tools
from gg_api_core.settings import get_settings

from gg_mcp_server.add_health_check import add_health_check
from gg_mcp_server.register_tools import GITGUARDIAN_INSTRUCTIONS, register_tools

configure_logging_from_settings(get_settings())

logger = logging.getLogger(__name__)

mcp = get_mcp_server(
    "GitGuardian",
    instructions=GITGUARDIAN_INSTRUCTIONS,
)

register_tools(mcp)
register_common_tools(mcp)
add_health_check(mcp)

logger.info("GitGuardian MCP server instance created and configured")
