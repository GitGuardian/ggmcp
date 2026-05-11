"""GitGuardian API scope definitions and server profiles."""

from enum import Enum

# All available GitGuardian API scopes as per documentation
# https://docs.gitguardian.com/api-docs/authentication#scopes
MINIMAL_SCOPES = [
    "scan",  # Core scanning functionality
    "incidents:read",  # Read incidents
    "sources:read",  # Read source repositories
]

HONEYTOKEN_SCOPES = [
    "honeytokens:read",
    "honeytokens:write",
]

ALL_SCOPES = [
    *MINIMAL_SCOPES,
    *HONEYTOKEN_SCOPES,
    "incidents:write",
    "incidents:share",
    "audit_logs:read",
    "api_tokens:write",
    "api_tokens:read",
    "ip_allowlist:read",
    "ip_allowlist:write",
    "sources:write",
    "custom_tags:read",
    "custom_tags:write",
    "members:read",
    "secrets:write",
    "secrets:read",
]

ALL_READ_SCOPES = [
    *MINIMAL_SCOPES,
    "honeytokens:read",
    "members:read",
    "audit_logs:read",
    "api_tokens:read",
    "ip_allowlist:read",
    "custom_tags:read",
    "secrets:read",
]


class ServerProfile(str, Enum):
    """Which gg-mcp server profile is running.

    The profile caps which scopes the OAuth flow may request. Set by each
    server entry-point (e.g. ``developer_mcp_server/server.py``) via the
    ``SERVER_PROFILE`` env var, then read through :class:`Settings`.
    """

    DEVELOPER = "developer"
    SECOPS = "secops"

    def max_scopes(self, *, restricted: bool) -> list[str]:
        """Return the largest scope set this profile may request.

        Args:
            restricted: True for non-local self-hosted instances, which
                are capped to :data:`MINIMAL_SCOPES` regardless of profile.
        """
        if restricted:
            return MINIMAL_SCOPES
        if self is ServerProfile.DEVELOPER:
            return [*ALL_READ_SCOPES, "honeytokens:write"]
        return ALL_SCOPES


def validate_scopes(scopes_str: str) -> list[str]:
    """Parse and validate a comma-separated list of scopes.

    Args:
        scopes_str: Comma-separated string of scopes.

    Returns:
        List of valid scopes (in the order they were requested).

    Raises:
        ValueError: If any requested scope is not in :data:`ALL_SCOPES`.
    """
    if not scopes_str:
        return []

    requested = [scope.strip() for scope in scopes_str.split(",") if scope.strip()]
    invalid = [scope for scope in requested if scope not in ALL_SCOPES]
    if invalid:
        raise ValueError(f"Invalid scopes provided: {', '.join(invalid)}. Valid scopes are: {', '.join(ALL_SCOPES)}")
    return requested
