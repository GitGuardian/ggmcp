import logging
import re
from collections.abc import Callable
from urllib.parse import urljoin as urllib_urljoin

from fastmcp.exceptions import ValidationError
from fastmcp.server.dependencies import get_http_headers

from .client import DEFAULT_USER_AGENT, GitGuardianClient, acquire_single_tenant_token
from .log_context import current_client_identity
from .settings import get_settings

# Setup logger
logger = logging.getLogger(__name__)


def urljoin(base: str, url: str) -> str:
    """Join a base URL and a possibly relative URL to form an absolute URL."""
    return urllib_urljoin(base, url)


# Singleton client instance - only used in single-tenant mode
_client_singleton: GitGuardianClient | None = None


async def get_client(personal_access_token: str | None = None, user_agent: str | None = None) -> GitGuardianClient:
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
        user_agent: Optional explicit User-Agent. If not provided, one is built
            per request via :func:`_build_user_agent` (server identity +
            transport marker, plus the client's identity from the MCP handshake
            or HTTP headers). The client evaluates it per request so a
            long-lived singleton reflects the session's handshake, not
            whichever call created it first.

    Returns:
        GitGuardianClient: Client instance configured with appropriate authentication

    Raises:
        ValidationError: In multi-tenant mode, if MCP_PORT not set or Authorization header missing
        RuntimeError: In single-tenant mode, if no token source is available
    """
    # The User-Agent is always a callable evaluated per request: the long-lived
    # single-tenant singleton would otherwise freeze whatever handshake was known
    # when the first call created it. An explicit override is wrapped into a
    # constant callable; otherwise the live handshake-derived builder is used.
    # All three modes below are therefore uniform: they pass the same source.
    ua_source: Callable[[], str] = (lambda: user_agent) if user_agent else _build_user_agent

    # 1. Explicit PAT provided - caller manages the token (no caching, no automatic refresh)
    if personal_access_token:
        logger.debug("Creating client with explicitly provided token")
        return GitGuardianClient(
            personal_access_token=personal_access_token,
            user_agent=ua_source,
        )

    # 2. Multi-tenant mode (explicit opt-in via MULTI_TENANCY_ENABLED=true) : no caching, no automatic refresh
    settings = get_settings()
    if settings.is_multi_tenant:
        if not settings.mcp_port:
            raise ValidationError(
                "MULTI_TENANCY_ENABLED=true requires MCP_PORT to be set. "
                "Multi-tenant mode only works with HTTP transport."
            )
        logger.debug("Multi-tenant mode: extracting token from request headers")
        token = _get_token_from_request_headers()
        return GitGuardianClient(personal_access_token=token, user_agent=ua_source)

    # 3. Single-tenant mode (DEFAULT) - use singleton pattern to cache the PAT
    global _client_singleton
    if _client_singleton is not None:
        return _client_singleton

    # Acquire token for single-tenant mode
    token = await acquire_single_tenant_token()
    # Enable token refresh for self-healing on 401 errors.
    _client_singleton = GitGuardianClient(
        personal_access_token=token,
        allow_token_refresh=True,
        user_agent=ua_source,
    )
    return _client_singleton


def _get_caller_user_agent() -> str | None:
    """The caller's own User-Agent, for callers that reached us over HTTP.

    ``get_http_headers`` returns an empty mapping outside an HTTP request
    rather than raising, so stdio simply yields None.
    """
    return get_http_headers(include={"user-agent"}).get("user-agent")


# Comment fields are client-controlled text: keep printable ASCII, drop the
# characters that delimit User-Agent comments or a field inside one (so a
# client cannot forge its own `key=value` pair), and bound the length.
_UA_FIELD_DISALLOWED = re.compile(r"[^\x20-\x7e]|[();=,]")
_UA_FIELD_MAX_LENGTH = 64


def _sanitize_ua_field(value: str) -> str | None:
    """Make a client-controlled string safe to embed in a User-Agent comment."""
    cleaned = _UA_FIELD_DISALLOWED.sub("", value).strip()
    return cleaned[:_UA_FIELD_MAX_LENGTH] or None


def _build_user_agent() -> str:
    """Build the User-Agent sent on outgoing GitGuardian API calls.

    The string always starts with ``GitGuardian-MCP-Server/<version>`` so that
    monitoring filtering on that substring keeps matching every MCP request,
    regardless of transport. A ``transport=stdio|http`` marker tells local
    (stdio) installs apart from the hosted HTTP server. The calling client is
    identified as ``client=<name>/<version>`` from the MCP handshake's
    ``clientInfo`` (available on every transport), falling back to the raw
    HTTP User-Agent for callers that reached us over HTTP. The negotiated MCP
    protocol revision is appended as ``mcp=...`` to track spec adoption.

    Examples:
        - stdio:  ``GitGuardian-MCP-Server/0.7.0 (transport=stdio; client=claude-code/2.0.14; mcp=2025-06-18)``
        - hosted: ``GitGuardian-MCP-Server/0.7.0 (transport=http; client=cursor/1.4.2; mcp=2025-06-18)``
    """
    transport = "http" if get_settings().mcp_port else "stdio"
    parts = [f"transport={transport}"]

    identity = current_client_identity()
    client = (identity.label if identity else None) or _get_caller_user_agent()
    protocol = identity.protocol_version if identity else None
    if client and (sanitized_client := _sanitize_ua_field(client)):
        parts.append(f"client={sanitized_client}")
    if protocol and (sanitized_protocol := _sanitize_ua_field(protocol)):
        parts.append(f"mcp={sanitized_protocol}")

    return f"{DEFAULT_USER_AGENT} ({'; '.join(parts)})"


def _get_token_from_request_headers() -> str:
    """Extract personal access token from HTTP request headers.

    Used in multi-tenant mode where each request must provide its own token.

    Returns:
        The extracted token

    Raises:
        ValidationError: If headers are missing or invalid
    """
    try:
        headers = get_http_headers(include={"authorization"})
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

    auth_header = headers.get("authorization")
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
