"""Request-local MCP identity for outgoing GitGuardian API headers."""

import re
from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar

from fastmcp.server.dependencies import get_context, get_http_headers

from gg_api_core.settings import get_settings
from gg_api_core.version import APP_VERSION

DEFAULT_USER_AGENT = f"GitGuardian-MCP-Server/{APP_VERSION}" if APP_VERSION else "GitGuardian-MCP-Server"
_current_tool: ContextVar[str | None] = ContextVar("gg_api_tool", default=None)


def _ua_field(value: str) -> str:
    """Bound untrusted comment fields and remove delimiters and non-ASCII text."""
    return re.sub(r"[^\x20-\x7e]|[();=,]", "", value).strip()[:64]


def build_request_headers(user_agent: str | None = None) -> dict[str, str]:
    """Read live SDK context even when the API client is a long-lived singleton."""
    if user_agent is None:
        transport = "http" if get_settings().mcp_port else "stdio"
        fields = [f"transport={transport}"]
        try:
            params = get_context().session.client_params
        except RuntimeError:
            params = None
        caller = get_http_headers(include={"user-agent"}).get("user-agent", "")
        if params is not None:
            info = params.client_info
            if info.name:
                caller = f"{info.name}/{info.version}" if info.version else info.name
        if client := _ua_field(caller):
            fields.append(f"client={client}")
        if params is not None and (protocol := _ua_field(params.protocol_version)):
            fields.append(f"mcp={protocol}")
        user_agent = f"{DEFAULT_USER_AGENT} ({'; '.join(fields)})"

    headers = {"User-Agent": user_agent}
    tool = _current_tool.get()
    if tool is not None and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", tool):
        headers["X-GG-MCP-Tool"] = tool
    return headers


@contextmanager
def track_tool_call(name: str) -> Generator[None, None, None]:
    """Keep tool attribution isolated to this call and reset it on every exit."""
    token = _current_tool.set(name)
    try:
        yield
    finally:
        _current_tool.reset(token)
