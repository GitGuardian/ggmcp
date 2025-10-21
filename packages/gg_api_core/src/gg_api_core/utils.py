import logging
import os
import re
from urllib.parse import urljoin as urllib_urljoin

from .client import GitGuardianClient

# Setup logger
logger = logging.getLogger(__name__)


def urljoin(base: str, url: str) -> str:
    """Join a base URL and a possibly relative URL to form an absolute URL."""
    return urllib_urljoin(base, url)


# Singleton client instance
_client_singleton = None


def get_client() -> GitGuardianClient:
    """Get the cached GitGuardian client instance (singleton pattern).

    This function maintains a single client instance across all tool calls,
    preserving caching and memoization benefits.

    Returns:
        GitGuardianClient: The cached client instance
    """
    global _client_singleton
    if _client_singleton is None:
        _client_singleton = get_gitguardian_client()
    return _client_singleton


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
    """
    # Remove .git suffix if present
    repo_path = remote_url.replace(".git", "")

    repository_name = None

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
    elif "/scm/" in repo_path or "/projects/" in repo_path or (
        "bitbucket" in repo_path and ("ssh://" in remote_url or "@" in remote_url)
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
def get_gitguardian_client(server_name: str = None) -> GitGuardianClient:
    """Get or initialize the GitGuardian client.

    Uses OAuth authentication flow.

    Args:
        server_name: Name of the MCP server for server-specific token storage
    """
    logger.debug("Attempting to initialize GitGuardian client")

    api_url = os.environ.get("GITGUARDIAN_URL")

    if api_url:
        logger.debug(f"GITGUARDIAN_URL environment variable is set: {api_url}")
    else:
        logger.debug("GITGUARDIAN_URL not set, will use default")

    # OAuth-based authentication (only supported method)
    logger.debug("Using OAuth authentication")
    try:
        # Store server_name as an attribute after initialization since it's not in the constructor anymore
        client = GitGuardianClient(api_url=api_url)
        client.server_name = server_name
        logger.debug("GitGuardian client initialized using OAuth authentication")
        return client
    except Exception as e:
        logger.exception(f"Failed to initialize GitGuardian client with OAuth auth: {str(e)}")
        raise
