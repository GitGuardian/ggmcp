"""GitGuardian URL helpers.

Maps a GitGuardian dashboard URL (or already-normalized API URL) to its
public API URL, so callers can derive ``GITGUARDIAN_API_URL`` from
``GITGUARDIAN_URL`` without instantiating a :class:`GitGuardianClient`.
"""

import logging
from urllib.parse import urlparse

from .host import is_self_hosted_instance

logger = logging.getLogger(__name__)


def derive_public_api_url(gitguardian_url: str) -> str:
    """Normalize a GitGuardian dashboard or API URL to its public API URL.

    Handles:
        * SaaS dashboard URL → corresponding ``api.*`` host with ``/v1`` suffix
        * SaaS API URL → ensures ``/v1`` suffix
        * Self-hosted / localhost base URL → appends ``/exposed/v1``
          (or ``/v1`` if the path already starts with ``/exposed``)
    """
    api_url = gitguardian_url.rstrip("/")

    try:
        parsed = urlparse(api_url)
        # localhost is always treated as self-hosted, regardless of SAAS_HOSTNAMES
        is_localhost = parsed.netloc.startswith("localhost") or parsed.netloc.startswith("127.0.0.1")

        # SaaS path
        if not is_localhost and not is_self_hosted_instance(api_url):
            if "dashboard" in parsed.netloc:
                api_netloc = parsed.netloc.replace("dashboard", "api")
                normalized = f"{parsed.scheme}://{api_netloc}/v1"
                logger.debug(f"Normalized SaaS dashboard URL: {api_url} -> {normalized}")
                return normalized
            if not parsed.path.endswith("/v1"):
                normalized = f"{api_url}/v1"
                logger.debug(f"Normalized SaaS API URL: {api_url} -> {normalized}")
                return normalized
            return api_url

        # Self-hosted / localhost path
        path = parsed.path.lower()
        if path.endswith("/v1") or path.endswith("/exposed/v1"):
            return api_url

        if not path or path == "/" or not path.startswith("/exposed"):
            normalized = f"{api_url}/exposed/v1"
            logger.info(f"Normalized self-hosted base URL: {api_url} -> {normalized}")
            return normalized

        # path starts with /exposed but lacks /v1
        normalized = f"{api_url}/v1"
        logger.info(f"Normalized self-hosted API URL: {api_url} -> {normalized}")
        return normalized

    except Exception as e:
        logger.warning(f"Failed to parse API URL '{api_url}': {e}; using as provided")
        return api_url
