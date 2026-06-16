"""GitGuardian API scope definitions."""

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

# Self-hosted releases are delayed compared to SaaS, so an API scope available in SaaS may not be already available
# in self-hosted. This variable allows to reflect this difference.
# Moreover, some scopes are not allowed on self-hosted (ex: IP allowlist ones)
SCOPES_SUPPORTED_IN_SELF_HOSTED = set(ALL_SCOPES) - {
    "ip_allowlist:read",
    "ip_allowlist:write",
}


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
