"""Current MCP tool name, propagated to downstream API calls."""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

__all__ = [
    "current_tool_name",
    "track_current_tool",
]

_current_tool: ContextVar[str | None] = ContextVar("gg_current_tool", default=None)

# The name arrives from the client's tools/call message, so it is untrusted
# text until it has resolved to a registered tool. Registered names are plain
# identifiers, so anything else is dropped here, at the point the value enters
# the process, rather than at each place that later reads it.
_TOOL_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")


@contextmanager
def track_current_tool(tool_name: str) -> Iterator[None]:
    """Expose the executing tool's name to downstream API calls."""
    token = _current_tool.set(tool_name if _TOOL_NAME.fullmatch(tool_name) else None)
    try:
        yield
    finally:
        _current_tool.reset(token)


def current_tool_name() -> str | None:
    """The MCP tool the in-flight request is executing, if any.

    Safe to put in an outgoing header: validated by :func:`track_current_tool`.
    """
    return _current_tool.get()
