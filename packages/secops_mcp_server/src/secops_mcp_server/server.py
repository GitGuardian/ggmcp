"""Deprecated compatibility shim — use ``gg_mcp_server.server`` instead."""

import warnings

from gg_mcp_server.server import mcp

warnings.warn(
    "secops_mcp_server.server is deprecated and will be removed in a future release; "
    "import gg_mcp_server.server instead.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["mcp"]
