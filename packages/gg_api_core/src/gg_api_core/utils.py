import logging
import os
import re
from urllib.parse import urljoin as urllib_urljoin

from fastmcp.server.dependencies import get_http_headers
from mcp.server.fastmcp.exceptions import ValidationError

from .client import GitGuardianClient, acquire_single_tenant_token

# Setup logger
logger = logging.getLogger(__name__)


def urljoin(base: str, url: str) -> str:
    """Join a base URL and a possibly relative URL to form an absolute URL."""
    return urllib_urljoin(base, url)


# Singleton client instance - only used in single-tenant mode
_client_singleton: GitGuardianClient | None = None


def get_mcp_port_or_none() -> str | None:
    """Get MCP_PORT environment variable value or None.

    Single source of truth for MCP_PORT access.
    """
    return os.environ.get("MCP_PORT")


def is_multi_tenant_mode() -> bool:
    """Check if multi-tenant mode is enabled (explicit opt-in).

    Multi-tenant mode requires explicit opt-in via MULTI_TENANCY_ENABLED=true.
    When enabled, MCP_PORT must also be set (raises error if not).

    Returns:
        True if MULTI_TENANCY_ENABLED=true
        False otherwise (single-tenant is the default)
    """
    return os.environ.get("MULTI_TENANCY_ENABLED", "").lower() == "true"


async def get_client(personal_access_token: str | None = None) -> GitGuardianClient:
    """Get GitGuardian client for the current context.

    **Single-tenant is the DEFAULT** (local stdio usage).
    Multi-tenant requires explicit opt-in via MULTI_TENANCY_ENABLED=true.

    Authentication modes (in order of precedence):

    1. **Explicit PAT provided** → Use it directly, no caching
       - For programmatic usage where caller manages the token

    2. **Multi-tenant mode** (MULTI_TENANCY_ENABLED=true) → Per-request from headers
       - Requires MCP_PORT to be set
       - Token MUST come from Authorization header
       - No caching (new client per request)

    3. **Single-tenant mode** (DEFAULT) → Singleton pattern, token sources:
       a. GITGUARDIAN_PERSONAL_ACCESS_TOKEN env var
       b. Stored OAuth token from previous authentication flow
       c. ENABLE_LOCAL_OAUTH=true → trigger interactive OAuth flow
       - Same identity for entire server lifetime

    Args:
        personal_access_token: Optional PAT for explicit authentication.

    Returns:
        GitGuardianClient: Client instance configured with appropriate authentication

    Raises:
        ValidationError: In multi-tenant mode, if MCP_PORT not set or Authorization header missing
        RuntimeError: In single-tenant mode, if no token source is available
    """
    # 1. Explicit PAT provided - caller manages the token (no caching, no automatic refresh)
    if personal_access_token:
        logger.debug("Creating client with explicitly provided token")
        return GitGuardianClient(personal_access_token=personal_access_token)

    # 2. Multi-tenant mode (explicit opt-in via MULTI_TENANCY_ENABLED=true) : no caching, no automatic refresh
    if is_multi_tenant_mode():
        mcp_port = get_mcp_port_or_none()
        if not mcp_port:
            raise ValidationError(
                "MULTI_TENANCY_ENABLED=true requires MCP_PORT to be set. "
                "Multi-tenant mode only works with HTTP transport."
            )
        logger.debug("Multi-tenant mode: extracting token from request headers")
        token = _get_token_from_request_headers()
        return GitGuardianClient(personal_access_token=token)

    # 3. Single-tenant mode (DEFAULT) - use singleton pattern to cache the PAT
    global _client_singleton
    if _client_singleton is not None:
        return _client_singleton

    # Acquire token for single-tenant mode
    token = await acquire_single_tenant_token()
    # Enable token refresh for self-healing on 401 errors
    _client_singleton = GitGuardianClient(
        personal_access_token=token,
        allow_token_refresh=True,
    )
    return _client_singleton


def _get_token_from_request_headers() -> str:
    """Extract personal access token from HTTP request headers.

    Used in multi-tenant mode where each request must provide its own token.

    Returns:
        The extracted token

    Raises:
        ValidationError: If headers are missing or invalid
    """
    try:
        headers = get_http_headers()
    except Exception as e:
        raise ValidationError(
            f"Failed to retrieve HTTP headers in multi-tenant mode. "
            f"Ensure the HTTP transport is properly configured. Error: {e}"
        )

    if not headers:
        raise ValidationError(
            "No HTTP headers available in multi-tenant mode. "
            "Requests must include Authorization header with a valid PAT."
        )

    auth_header = headers.get("authorization") or headers.get("Authorization")
    if not auth_header:
        raise ValidationError(
            "Missing Authorization header in multi-tenant mode. "
            "Each request must include 'Authorization: Bearer <PAT>' header."
        )

    token = _extract_token_from_auth_header(auth_header)
    if not token:
        raise ValidationError("Invalid Authorization header format. Expected: 'Bearer <token>' or 'Token <token>'")

    return token


def _extract_token_from_auth_header(auth_header: str) -> str | None:
    """Extract token from Authorization header.

    Supports formats:
    - Bearer <token>
    - Token <token>
    - <token> (raw)
    """
    auth_header = auth_header.strip()

    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()

    if auth_header.lower().startswith("token "):
        return auth_header[6:].strip()

    if auth_header:
        return auth_header

    return None


def parse_repo_url(remote_url: str) -> str | None:
    """Parse repository name from git remote URL.

    Supports multiple Git hosting platforms:
    - GitHub (Cloud)
    - GitLab (Cloud & Self-hosted)
    - Bitbucket (Cloud & Data Center)
    - Azure DevOps

    Args:
        remote_url: Git remote URL (HTTPS or SSH format)

    Returns:
        Repository name in format that matches the hosting platform:
        - GitHub/GitLab/Bitbucket: "org/repo"
        - Azure DevOps: "org/project/repo"
        - Bitbucket DC: "PROJECT/repo"
        Returns None if URL format is not recognized

    Examples:
        >>> parse_repo_url("https://github.com/GitGuardian/ggmcp.git")
        'GitGuardian/ggmcp'
        >>> parse_repo_url("git@gitlab.company.com:team/project.git")
        'team/project'
        >>> parse_repo_url("https://dev.azure.com/org/proj/_git/repo")
        'org/proj/repo'
        >>> parse_repo_url("GitGuardian/ggmcp")
        'GitGuardian/ggmcp'
    """
    # Remove .git suffix if present
    repo_path = remote_url.replace(".git", "")

    repository_name = remote_url

    # Azure DevOps patterns
    # HTTPS: https://dev.azure.com/organization/project/_git/repo
    # HTTPS (old): https://organization.visualstudio.com/project/_git/repo
    # SSH: git@ssh.dev.azure.com:v3/organization/project/repo
    if "dev.azure.com" in repo_path or "visualstudio.com" in repo_path:
        if "ssh.dev.azure.com:v3/" in repo_path:
            # SSH format: git@ssh.dev.azure.com:v3/organization/project/repo
            match = re.search(r":v3/([^/]+)/([^/]+)/(.+)$", repo_path)
            if match:
                org, project, repo = match.groups()
                repository_name = f"{org}/{project}/{repo}"
        elif "_git/" in repo_path:
            # HTTPS format: https://dev.azure.com/org/project/_git/repo or
            # https://org.visualstudio.com/project/_git/repo
            match = re.search(r"/_git/(.+)$", repo_path)
            if match:
                repo = match.group(1)
                # Try to extract org and project
                # For dev.azure.com: https://dev.azure.com/org/project/_git/repo
                org_match = re.search(r"dev\.azure\.com/([^/]+)/([^/]+)", repo_path)
                if org_match:
                    org, project = org_match.groups()
                    repository_name = f"{org}/{project}/{repo}"
                else:
                    # For visualstudio.com: https://org.visualstudio.com/project/_git/repo
                    org_match = re.search(r"https?://([^.]+)\.visualstudio\.com/([^/]+)", repo_path)
                    if org_match:
                        org, project = org_match.groups()
                        repository_name = f"{org}/{project}/{repo}"
                    else:
                        repository_name = repo

    # Bitbucket Data Center/Server patterns
    # HTTPS: https://bitbucket.company.com/scm/project/repo
    # HTTPS: https://bitbucket.company.com/projects/PROJECT/repos/repo
    # SSH: ssh://git@bitbucket.company.com:7999/project/repo.git
    # SSH: git@bitbucket.company.com:project/repo.git
    elif (
        "/scm/" in repo_path
        or "/projects/" in repo_path
        or ("bitbucket" in repo_path and ("ssh://" in remote_url or "@" in remote_url))
    ):
        # Bitbucket Data Center /scm/ format
        if "/scm/" in repo_path:
            match = re.search(r"/scm/([^/]+)/(.+)$", repo_path)
            if match:
                project, repo = match.groups()
                repository_name = f"{project}/{repo}"
        # Bitbucket Data Center /projects/ format
        elif "/projects/" in repo_path:
            match = re.search(r"/projects/([^/]+)/repos/(.+?)(?:/|$)", repo_path)
            if match:
                project, repo = match.groups()
                repository_name = f"{project}/{repo}"
        # SSH format with port: ssh://git@bitbucket.company.com:7999/project/repo
        elif "ssh://" in remote_url:
            match = re.search(r"://[^@]+@[^/]+/([^/]+)/(.+)$", repo_path)
            if match:
                project, repo = match.groups()
                repository_name = f"{project}/{repo}"
        # SSH format without port: git@bitbucket.company.com:project/repo
        elif "@" in repo_path and "bitbucket" in repo_path:
            match = re.search(r":([^/]+)/(.+)$", repo_path)
            if match:
                project, repo = match.groups()
                repository_name = f"{project}/{repo}"

    # GitHub, GitLab Cloud/Self-hosted, Bitbucket Cloud patterns
    # SSH: git@github.com:org/repo or git@gitlab.com:org/repo or git@bitbucket.org:workspace/repo
    # HTTPS: https://github.com/org/repo or https://gitlab.com/org/repo or https://bitbucket.org/workspace/repo
    elif "@" in repo_path and "://" not in remote_url:
        # SSH format: git@host:org/repo
        # Handle ports in format: git@host:port:org/repo or ssh://git@host:port/org/repo
        if repo_path.count(":") > 1:
            # Format with port number: git@host:7999:org/repo (uncommon but possible)
            match = re.search(r":[0-9]+:([^/]+/.+)$", repo_path)
            if match:
                repository_name = match.group(1)
            else:
                # Try without port assumption
                match = re.search(r":([^:]+/.+)$", repo_path)
                if match:
                    repository_name = match.group(1)
        else:
            # Standard SSH format: git@host:org/repo
            match = re.search(r":([^/]+/.+)$", repo_path)
            if match:
                repository_name = match.group(1)

    # HTTPS format for GitHub, GitLab, Bitbucket Cloud
    elif "://" in repo_path:
        # HTTPS format: https://host/org/repo
        match = re.search(r"://[^/]+/(.+)$", repo_path)
        if match:
            repository_name = match.group(1)

    return repository_name
