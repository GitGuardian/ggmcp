import logging
import os
from urllib.parse import urljoin as urllib_urljoin

from .client import GitGuardianClient

# Setup logger
logger = logging.getLogger(__name__)


def urljoin(base: str, url: str) -> str:
    """Join a base URL and a possibly relative URL to form an absolute URL."""
    return urllib_urljoin(base, url)


# Initialize GitGuardian client
def get_gitguardian_client(server_name: str = None) -> GitGuardianClient:
    """Get or initialize the GitGuardian client.

    Uses OAuth authentication method exclusively.
    The OAuth flow will be triggered when needed.

    Args:
        server_name: Name of the MCP server for server-specific token storage
    """
    logger.debug("Attempting to initialize GitGuardian client")

    api_url = os.environ.get("GITGUARDIAN_API_URL")

    if api_url:
        logger.debug(f"GITGUARDIAN_API_URL environment variable is set: {api_url}")
    else:
        logger.debug("GITGUARDIAN_API_URL not set, will use default")

    # OAuth-based authentication (only supported method)
    logger.debug("Using OAuth authentication")
    try:
        # Store server_name as an attribute after initialization since it's not in the constructor anymore
        client = GitGuardianClient(api_url=api_url, use_oauth=True)
        client.server_name = server_name
        logger.debug("GitGuardian client initialized using OAuth authentication")
        return client
    except Exception as e:
        logger.exception(f"Failed to initialize GitGuardian client with OAuth auth: {str(e)}")
        raise
