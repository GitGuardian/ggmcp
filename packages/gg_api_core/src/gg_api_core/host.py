import os
from urllib.parse import urlparse

SAAS_HOSTNAMES = [
    "dashboard.gitguardian.com",
    "api.gitguardian.com",
    "dashboard.eu1.gitguardian.com",
    "api.eu1.gitguardian.com",
    "dashboard.staging.gitguardian.tech",
    "dashboard.preprod.gitguardian.com",
]

LOCAL_HOSTNAMES = ["localhost", "127.0.0.1"]


def _is_local_hostname(parsed_hostname: str | None) -> bool:
    """Check if hostname (without port) is a local hostname."""
    if parsed_hostname is None:
        return False
    return parsed_hostname.lower() in LOCAL_HOSTNAMES


def is_self_hosted_instance(gitguardian_url: str | None = None) -> bool:
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
        # For local hostnames, ignore the port
        if _is_local_hostname(parsed.hostname):
            return False
        # For SaaS, check the full netloc (includes port)
        netloc = parsed.netloc.lower()
        return netloc not in SAAS_HOSTNAMES
    except Exception:
        # If parsing fails, assume self-hosted to be safe
        return True


def is_local_instance(gitguardian_url: str | None = None) -> bool:
    if not gitguardian_url:
        return False

    parsed = urlparse(gitguardian_url)
    return _is_local_hostname(parsed.hostname)


def has_exposed_prefix_for_api(gitguardian_url):
    return is_self_hosted_instance(gitguardian_url) or is_local_instance(gitguardian_url)
