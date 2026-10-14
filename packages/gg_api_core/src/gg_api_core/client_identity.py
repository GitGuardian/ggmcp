"""MCP client identity, captured once from the initialize handshake."""

from __future__ import annotations

import weakref
from dataclasses import dataclass
from typing import Any

from fastmcp.server.dependencies import get_context
from mcp.server.session import ServerSession
from mcp.types import Implementation

__all__ = [
    "ClientIdentity",
    "current_client_identity",
    "set_client_identity",
]


@dataclass(frozen=True)
class ClientIdentity:
    name: str
    version: str
    protocol_version: str

    @classmethod
    def from_params(
        cls,
        client_info: Implementation,
        protocol_version: str | int | None = None,
    ) -> ClientIdentity:
        return cls(
            name=client_info.name,
            version=client_info.version,
            protocol_version=str(protocol_version) if protocol_version is not None else "",
        )

    @property
    def label(self) -> str | None:
        """``<name>/<version>``, or the bare name when no version was sent."""
        if not self.name:
            return None
        return f"{self.name}/{self.version}" if self.version else self.name

    def log_fields(self) -> dict[str, Any]:
        """The subset present, under the field names logs use."""
        fields = {
            "client_name": self.name,
            "client_version": self.version,
            "protocol_version": self.protocol_version,
        }
        return {key: value for key, value in fields.items() if value}


_identity_by_session: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


def set_client_identity(identity: ClientIdentity | None, session: ServerSession) -> None:
    if identity is None:
        _identity_by_session.pop(session, None)
        return
    _identity_by_session[session] = identity


def current_client_identity() -> ClientIdentity | None:
    try:
        session = get_context().session
    except RuntimeError:
        return None
    return _identity_by_session.get(session)
