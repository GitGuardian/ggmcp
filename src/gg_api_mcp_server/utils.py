import logging
import os
from urllib.parse import urljoin as urllib_urljoin

from gg_api_mcp_server.client import GitGuardianClient

# Setup logger
logger = logging.getLogger(__name__)


def urljoin(base: str, url: str) -> str:
    """Join a base URL and a possibly relative URL to form an absolute URL."""
    return urllib_urljoin(base, url)


# Initialize GitGuardian client
def get_gitguardian_client() -> GitGuardianClient:
    """Get or initialize the GitGuardian client.

    The authentication method is determined by the GITGUARDIAN_AUTH_METHOD environment variable.
    Supported methods: 'token' (default), 'web' (OAuth).

    For token auth, the GITGUARDIAN_API_KEY environment variable must be set.
    For web auth, the OAuth flow will be triggered.
    """
    logger.info("Attempting to initialize GitGuardian client")

    auth_method = os.environ.get("GITGUARDIAN_AUTH_METHOD", "token").lower()
    api_url = os.environ.get("GITGUARDIAN_API_URL")

    if api_url:
        logger.info(f"GITGUARDIAN_API_URL environment variable is set: {api_url}")
    else:
        logger.info("GITGUARDIAN_API_URL not set, will use default")

    # Token-based authentication (default)
    if auth_method == "token":
        api_key = os.environ.get("GITGUARDIAN_API_KEY")

        # Log environment variable status
        if api_key:
            logger.info("GITGUARDIAN_API_KEY environment variable is set")
            # Only show first 4 chars for logging
            key_preview = api_key[:4] + "..." if len(api_key) > 4 else "***"
            logger.debug(f"API key starts with: {key_preview}")
        else:
            logger.error("GITGUARDIAN_API_KEY environment variable is not set")
            raise ValueError("GITGUARDIAN_API_KEY environment variable must be set for token authentication")

        try:
            client = GitGuardianClient(api_key=api_key, api_url=api_url)
            logger.info("GitGuardian client initialized successfully using token authentication")
            return client
        except Exception as e:
            logger.exception(f"Failed to initialize GitGuardian client with token auth: {str(e)}")
            raise

    # OAuth-based authentication
    elif auth_method == "web":
        logger.info("Using web-based OAuth authentication")
        try:
            client = GitGuardianClient(api_key=None, api_url=api_url, use_oauth=True)
            logger.info("GitGuardian client initialized successfully using OAuth authentication")
            return client
        except Exception as e:
            logger.exception(f"Failed to initialize GitGuardian client with OAuth auth: {str(e)}")
            raise

    # Unsupported authentication method
    else:
        logger.error(f"Unsupported authentication method: {auth_method}")
        raise ValueError(f"Unsupported authentication method: {auth_method}. Supported methods: 'token', 'web'")
