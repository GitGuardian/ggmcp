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

LOCAL_HOSTNAMES = ["localhost", "127.0.0.1", "localhost:3000", "127.0.0.1:3000"]


def is_self_hosted_instance(gitguardian_url: str = None) -> bool:
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
        hostname = parsed.netloc.lower()
        return hostname not in [*SAAS_HOSTNAMES, *LOCAL_HOSTNAMES]
    except Exception:
        # If parsing fails, assume self-hosted to be safe
        return True


def is_local_instance(gitguardian_url: str = None) -> bool:
    if not gitguardian_url:
        return False

    parsed = urlparse(gitguardian_url)
    hostname = parsed.netloc.lower()
    return hostname in LOCAL_HOSTNAMES


def has_exposed_prefix_for_api(gitguardian_url):
    return is_self_hosted_instance(gitguardian_url) or is_local_instance(gitguardian_url)
