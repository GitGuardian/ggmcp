"""GitGuardian API scope definitions for different server types."""

import os
from urllib.parse import urlparse

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
        return [
            *MINIMAL_SCOPES,
            *HONEYTOKEN_SCOPES,
        ]
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


def is_self_hosted_instance(gitguardian_url: str = None) -> bool:
    """
    Determine if we're connecting to a self-hosted GitGuardian instance.

    Args:
        gitguardian_url: GitGuardian URL to check, defaults to GITGUARDIAN_URL env var

    Returns:
        bool: True if self-hosted, False if SaaS
    """
    if not gitguardian_url:
        gitguardian_url = os.environ.get("GITGUARDIAN_URL", "https://dashboard.gitguardian.com")

    try:
        parsed = urlparse(gitguardian_url)
        hostname = parsed.netloc.lower()

        # SaaS instances
        saas_hostnames = [
            "dashboard.gitguardian.com",
            "api.gitguardian.com",
            "dashboard.eu1.gitguardian.com",
            "api.eu1.gitguardian.com"
        ]

        return hostname not in saas_hostnames
    except:
        # If parsing fails, assume self-hosted to be safe
        return True


# Legacy constants for backward compatibility
DEVELOPER_SCOPES = get_developer_scopes()
SECOPS_SCOPES = get_secops_scopes()
