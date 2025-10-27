"""GitGuardian API scope definitions for different server types."""

from gg_api_core.host import is_self_hosted_instance

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
    "write:secret",
    "read:secret"
]

ALL_READ_SCOPES = [
    *MINIMAL_SCOPES,
    "honeytokens:read",
    "members:read"
    "audit_logs:read",
    "api_tokens:read",
    "ip_allowlist:read",
    "custom_tags:read",
    "read:secret"
]


def get_developer_scopes(gitguardian_url: str = None) -> list[str]:
    """
    Get developer scopes appropriate for the GitGuardian instance type.
    
    Args:
        gitguardian_url: GitGuardian URL to check instance type
        
    Returns:
        list[str]: List of appropriate scopes
    """
    return get_secops_scopes(gitguardian_url=gitguardian_url)


def get_secops_scopes(gitguardian_url: str = None) -> list[str]:
    """
    Get SecOps scopes appropriate for the GitGuardian instance type.
    
    Args:
        gitguardian_url: GitGuardian URL to check instance type
        
    Returns:
        list[str]: List of appropriate scopes
    """
    if not is_self_hosted_instance(gitguardian_url):
        # For SaaS, request comprehensive SecOps scopes
        return ALL_SCOPES
    else:
        # For self-hosted, use conservative scopes that are most likely available
        # Avoid honeytokens as it may not be activated
        return MINIMAL_SCOPES


def validate_scopes(scopes_str: str) -> list[str]:
    """
    Validate and filter user-provided scopes against ALL_SCOPES.

    Args:
        scopes_str: Comma-separated string of scopes

    Returns:
        list[str]: List of valid scopes

    Raises:
        ValueError: If any invalid scopes are provided
    """
    if not scopes_str:
        return []

    # Parse the scopes string
    requested_scopes = [scope.strip() for scope in scopes_str.split(",") if scope.strip()]

    # Check for invalid scopes
    invalid_scopes = [scope for scope in requested_scopes if scope not in ALL_SCOPES]

    if invalid_scopes:
        raise ValueError(
            f"Invalid scopes provided: {', '.join(invalid_scopes)}. "
            f"Valid scopes are: {', '.join(ALL_SCOPES)}"
        )

    return requested_scopes


# Legacy constants for backward compatibility
DEVELOPER_SCOPES = get_developer_scopes()
SECOPS_SCOPES = get_secops_scopes()
