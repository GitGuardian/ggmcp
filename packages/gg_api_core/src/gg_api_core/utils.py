import logging
import os
import re
from urllib.parse import urljoin as urllib_urljoin

from fastmcp.server.dependencies import get_http_headers
from mcp.server.fastmcp.exceptions import ValidationError

from .client import GitGuardianClient

# Setup logger
logger = logging.getLogger(__name__)


def urljoin(base: str, url: str) -> str:
    """Join a base URL and a possibly relative URL to form an absolute URL."""
    return urllib_urljoin(base, url)


# Singleton client instance
_client_singleton = None


def get_client(personal_access_token: str | None = None) -> GitGuardianClient:
    """Get the GitGuardian client instance.

    Authentication behavior depends on transport mode:
    
    **stdio mode** (no MCP_PORT): Uses singleton pattern with cached client.
    - Token comes from: OAuth flow OR GITGUARDIAN_PERSONAL_ACCESS_TOKEN env var
    - Single identity for entire server lifetime
    
    **HTTP mode** (MCP_PORT set): Per-request authentication.
    - Token MUST come from Authorization header in each request
    - Multi-tenant: different users can authenticate per-request
    - No caching (new client per request)

    Args:
        personal_access_token: Optional PAT for explicit authentication.
            In HTTP mode, this is extracted from request headers.

    Returns:
        GitGuardianClient: Client instance configured with appropriate authentication
        
    Raises:
        ValidationError: In HTTP mode, if Authorization header is missing/invalid
    """
    mcp_port = os.environ.get("MCP_PORT")

    logger.debug(
        f"get_client() called: mcp_port={mcp_port}, personal_access_token={'provided' if personal_access_token else 'None'}"
    )

    # In HTTP mode, get token from Authorization header or raise
    if mcp_port and not personal_access_token:
        logger.debug("HTTP mode detected: extracting token from request headers")
        try:
            personal_access_token = get_personal_access_token_from_request()
            logger.debug("Successfully extracted token from HTTP request headers")
        except ValidationError as e:
            logger.error(f"Failed to extract token from HTTP headers: {e}")
            raise 

    # If a PAT is provided (explicitly or from headers), create per-request client (no caching)
    if personal_access_token:
        logger.debug("Creating GitGuardian client with provided token")
        return get_gitguardian_client(personal_access_token=personal_access_token)

    # stdio mode: Use singleton pattern (OAuth or env var token)
    logger.debug("stdio mode: Using singleton client")
    global _client_singleton
    if _client_singleton is None:
        logger.info("Creating singleton client instance")
        _client_singleton = get_gitguardian_client()
    return _client_singleton


def get_personal_access_token_from_request():
    """Extract personal access token from HTTP request headers.

    Raises:
        ValidationError: If headers are missing or invalid
    """
    try:
        headers = get_http_headers()
        logger.debug(f"Retrieved HTTP headers: {list(headers.keys()) if headers else 'None'}")
    except Exception as e:
        logger.error(f"Failed to get HTTP headers: {e}")
        raise ValidationError(f"Failed to retrieve HTTP headers: {e}")

    if not headers:
        logger.error("No HTTP headers available in current context")
        raise ValidationError("No HTTP headers available - Authorization header required in HTTP mode")

    auth_header = headers.get("authorization") or headers.get("Authorization")
    if not auth_header:
        logger.error(f"Missing Authorization header. Available headers: {list(headers.keys())}")
        raise ValidationError("Missing Authorization header - required in HTTP mode")

    token = _extract_token_from_auth_header(auth_header)
    if not token:
        logger.error("Failed to extract token from Authorization header")
        raise ValidationError("Invalid Authorization header format")

    logger.debug("Successfully extracted token from Authorization header")
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


# Initialize GitGuardian client
def get_gitguardian_client(server_name: str | None = None, personal_access_token: str | None = None) -> GitGuardianClient:
    """Get or initialize the GitGuardian client.

    Uses OAuth authentication flow by default, or a provided Personal Access Token.

    Args:
        server_name: Name of the MCP server for server-specific token storage
        personal_access_token: Optional Personal Access Token to use for authentication

    Returns:
        GitGuardianClient: Initialized client instance
    """
    logger.debug("Attempting to initialize GitGuardian client")
    try:
        # Store server_name as an attribute after initialization since it's not in the constructor anymore
        client = GitGuardianClient(personal_access_token=personal_access_token)
        client.server_name = server_name  # type: ignore[attr-defined]
        return client
    except Exception as e:
        logger.exception(f"Failed to initialize GitGuardian client: {str(e)}")
        raise
