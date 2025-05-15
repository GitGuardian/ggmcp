import logging
import os

from gg_api_mcp_server.client import GitGuardianClient

# Setup logger
logger = logging.getLogger(__name__)


# Initialize GitGuardian client
def get_gitguardian_client() -> GitGuardianClient:
    """Get or initialize the GitGuardian client."""
    logger.info("Attempting to initialize GitGuardian client")

    api_key = os.environ.get("GITGUARDIAN_API_KEY")
    api_url = os.environ.get("GITGUARDIAN_API_URL")

    # Log environment variable status
    if api_key:
        logger.info("GITGUARDIAN_API_KEY environment variable is set")
        # Only show first 4 chars for logging
        key_preview = api_key[:4] + "..." if len(api_key) > 4 else "***"
        logger.debug(f"API key starts with: {key_preview}")
    else:
        logger.error("GITGUARDIAN_API_KEY environment variable is not set")
        raise ValueError("GITGUARDIAN_API_KEY environment variable must be set")

    if api_url:
        logger.info(f"GITGUARDIAN_API_URL environment variable is set: {api_url}")
    else:
        logger.info("GITGUARDIAN_API_URL not set, will use default")

    try:
        client = GitGuardianClient(api_key=api_key, api_url=api_url)
        logger.info("GitGuardian client initialized successfully")
        return client
    except Exception as e:
        logger.exception(f"Failed to initialize GitGuardian client: {str(e)}")
        raise
