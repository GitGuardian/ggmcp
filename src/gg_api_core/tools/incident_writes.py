"""How the incident write tools turn the API's answer into a result.

The API answers a change the incident already has with a 409. A 409 also answers
changes the incident's state does not allow, such as resolving an ignored incident,
so the tools read the incident back: when it is in the requested state, the call
succeeds with changed=False; otherwise the refusal stands.
"""

from collections.abc import Awaitable, Callable
from typing import Any, Literal

import httpx
from fastmcp.exceptions import ToolError

from gg_api_core.client import GitGuardianClient

IncidentKind = Literal["internal", "public"]

CHANGED_DESCRIPTION = (
    "False when the incident was already in the requested state, so nothing changed; the incident was read back to "
    "check"
)


def uncertain_write_error(error: Exception, check: str) -> ToolError | None:
    """The error for a write whose outcome is unknown, or None when the API answered.

    A write that timed out, lost its connection, or got a server error may have been
    applied before it failed. Writes are never retried, so the agent is told how to
    check rather than to try again blindly.
    """
    if isinstance(error, httpx.HTTPStatusError) and error.response.status_code < 500:
        return None
    if not isinstance(error, (httpx.HTTPStatusError, httpx.RequestError)):
        return None
    reason = str(error) or type(error).__name__
    return ToolError(f"{reason} The change may or may not have been applied. {check} before trying again.")


def check_advice(kind: IncidentKind) -> str:
    """How to see whether a change to an incident of this kind was applied."""
    tool = "get_public_incident" if kind == "public" else "get_internal_incident"
    return f"Read the incident with {tool} to check"


def incident_reader(
    client: GitGuardianClient, kind: IncidentKind, incident_id: int
) -> Callable[[], Awaitable[dict[str, Any]]]:
    """A call that reads the incident as it is now."""
    if kind == "public":
        return lambda: client.get_public_incident(incident_id)
    return lambda: client.get_incident(incident_id=incident_id, with_occurrences=0)


async def apply_or_confirm(
    call: Awaitable[dict[str, Any]],
    read_current: Callable[[], Awaitable[dict[str, Any]]],
    in_requested_state: Callable[[dict[str, Any]], bool],
    check: str,
) -> tuple[dict[str, Any], bool]:
    """Make the change, and say whether it changed anything.

    Returns the incident and True after a change, or the incident as read back and
    False when the API refused the change as a conflict and the incident already
    has it. A failure that leaves the outcome unknown says how to check it; any other
    failure raises a ToolError. Both are raised inside the except block, so that a
    rejected token still asks the client to authenticate again.
    """
    try:
        return await call, True
    except ToolError:
        raise
    except Exception as e:
        if isinstance(e, httpx.HTTPStatusError) and e.response.status_code == 409:
            conflict = e
        else:
            raise uncertain_write_error(e, check) or ToolError(str(e))

    try:
        current = await read_current()
    except Exception as e:
        raise ToolError(f"{conflict} Reading the incident back to check its state also failed: {e}")
    if in_requested_state(current):
        return current, False
    raise ToolError(str(conflict))
