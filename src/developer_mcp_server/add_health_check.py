"""Deprecated compatibility shim — use ``gg_mcp_server.add_health_check`` instead."""

import warnings

from gg_mcp_server.add_health_check import add_health_check

warnings.warn(
    "developer_mcp_server.add_health_check is deprecated; use gg_mcp_server.add_health_check instead.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["add_health_check"]
