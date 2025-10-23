import os
from urllib.parse import urlparse

SAAS_HOSTNAMES = [
            "dashboard.gitguardian.com",
            "api.gitguardian.com",
            "dashboard.eu1.gitguardian.com",
            "api.eu1.gitguardian.com",
            "dashboard.staging.gitguardian.tech",
            "dashboard.preprod.gitguardian.com"
        ]


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
        return hostname not in SAAS_HOSTNAMES
    except:
        # If parsing fails, assume self-hosted to be safe
        return True
