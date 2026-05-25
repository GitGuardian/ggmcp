"""Deprecated compatibility shim — use ``gg_mcp_server.register_tools`` instead."""

import warnings

from gg_mcp_server.register_tools import GITGUARDIAN_INSTRUCTIONS, register_tools

DEVELOPER_INSTRUCTIONS = GITGUARDIAN_INSTRUCTIONS
register_developer_tools = register_tools

warnings.warn(
    "developer_mcp_server.register_tools is deprecated; use gg_mcp_server.register_tools instead.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["DEVELOPER_INSTRUCTIONS", "register_developer_tools"]
