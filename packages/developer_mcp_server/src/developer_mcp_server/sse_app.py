"""Deprecated compatibility shim — use ``gg_mcp_server.sse_app`` instead."""

import warnings

from gg_mcp_server.sse_app import sse_app

warnings.warn(
    "developer_mcp_server.sse_app is deprecated; use gg_mcp_server.sse_app instead.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["sse_app"]
