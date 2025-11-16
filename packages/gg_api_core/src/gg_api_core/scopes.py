"""GitGuardian API scope definitions for different server types."""

import os

from gg_api_core.host import is_local_instance, is_self_hosted_instance

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


def get_developer_scopes(gitguardian_url: str | None = None) -> list[str]:
    """
    Get developer scopes appropriate for the GitGuardian instance type.

    Args:
        gitguardian_url: GitGuardian URL to check instance type

    Returns:
        list[str]: List of appropriate scopes
    """
    if is_self_hosted_instance(gitguardian_url) and not is_local_instance(gitguardian_url):
        # For non-local self-hosted instances, return minimal scopes
        return MINIMAL_SCOPES
    else:
        return [
            *ALL_READ_SCOPES,
            "honeytokens:write",
        ]


def get_secops_scopes(gitguardian_url: str | None = None) -> list[str]:
    """
    Get SecOps scopes appropriate for the GitGuardian instance type.

    Args:
        gitguardian_url: GitGuardian URL to check instance type

    Returns:
        list[str]: List of appropriate scopes
    """
    if is_self_hosted_instance(gitguardian_url) and not is_local_instance(gitguardian_url):
        # For non-local self-hosted instances, return minimal scopes
        return MINIMAL_SCOPES
    else:
        return ALL_SCOPES


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
            f"Invalid scopes provided: {', '.join(invalid_scopes)}. Valid scopes are: {', '.join(ALL_SCOPES)}"
        )

    return requested_scopes


def get_scopes_from_env_var() -> list[str]:
    # Support GITGUARDIAN_REQUESTED_SCOPES for backward compatibility from previous versions
    scopes_str = os.environ.get("GITGUARDIAN_SCOPES") or os.environ.get("GITGUARDIAN_REQUESTED_SCOPES")
    if not scopes_str:
        return []
    return validate_scopes(scopes_str)


DEVELOPER_SCOPES = get_developer_scopes()
SECOPS_SCOPES = get_secops_scopes()


def set_secops_scopes():
    # Filter the GITGUARDIAN_SCOPES env variable to only include secops scopes. If empty, use default secops scopes.
    # Write again the result on the env variable
    scopes_from_env_var = set(get_scopes_from_env_var())
    scopes = set(SECOPS_SCOPES) & scopes_from_env_var if scopes_from_env_var else set(SECOPS_SCOPES)
    os.environ["GITGUARDIAN_SCOPES"] = ",".join(scopes)


def set_developer_scopes():
    # Filter the GITGUARDIAN_SCOPES env variable to only include secops scopes. If empty, use default secops scopes.
    # Write again the result on the env variable
    scopes_from_env_var = set(get_scopes_from_env_var())
    scopes = set(DEVELOPER_SCOPES) & scopes_from_env_var if scopes_from_env_var else set(DEVELOPER_SCOPES)
    os.environ["GITGUARDIAN_SCOPES"] = ",".join(scopes)
