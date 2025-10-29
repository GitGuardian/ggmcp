#!/usr/bin/env python3
"""
Script to manually test and run the GitGuardian OAuth authentication flow.

This script helps test the OAuth integration by:
1. Loading configuration from environment variables
2. Initializing the OAuth client
3. Running the OAuth flow
4. Displaying token information

Usage:
    python scripts/run_oauth_flow.py

Environment Variables:
    GITGUARDIAN_URL: GitGuardian instance URL (default: https://dashboard.gitguardian.com)
    GITGUARDIAN_CLIENT_ID: OAuth client ID (default: ggshield_oauth)
    GITGUARDIAN_SCOPES: Space-separated list of OAuth scopes
    GITGUARDIAN_TOKEN_NAME: Name for the OAuth token (default: "MCP OAuth Test Token")
    GITGUARDIAN_TOKEN_LIFETIME: Token lifetime in days, or "never" for no expiration (default: 30)
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

# Add the package to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "packages" / "gg_api_core" / "src"))

from gg_api_core.oauth import GitGuardianOAuthClient
from gg_api_core.scopes import get_scopes_from_env_var, ALL_SCOPES

os.environ["GITGUARDIAN_SCOPES"] = ",".join(ALL_SCOPES)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def normalize_api_url(url: str) -> str:
    """
    Normalize a dashboard URL to an API URL.

    Args:
        url: Dashboard URL or API URL

    Returns:
        Normalized API URL
    """
    from urllib.parse import urlparse

    url = url.rstrip("/")
    parsed = urlparse(url)

    # Check if localhost or 127.0.0.1
    is_localhost = parsed.netloc.startswith("localhost") or parsed.netloc.startswith("127.0.0.1")

    # SaaS URLs
    if "api.gitguardian.com" in parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}/v1" if not url.endswith("/v1") else url
    elif "dashboard.gitguardian.com" in parsed.netloc:
        return "https://api.gitguardian.com/v1"
    elif "api.eu1.gitguardian.com" in parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}/v1" if not url.endswith("/v1") else url
    elif "dashboard.eu1.gitguardian.com" in parsed.netloc:
        return "https://api.eu1.gitguardian.com/v1"

    # Self-hosted or localhost
    if is_localhost:
        # For localhost, use /exposed/v1
        if not parsed.path or parsed.path == "/":
            return f"{parsed.scheme}://{parsed.netloc}/exposed/v1"
        elif not parsed.path.endswith("/v1"):
            return f"{url}/v1"
    else:
        # For other self-hosted instances
        if not parsed.path or parsed.path == "/":
            return f"{url}/exposed/v1"
        elif not parsed.path.endswith("/v1"):
            return f"{url}/v1"

    return url


def get_dashboard_url(api_url: str) -> str:
    """
    Derive dashboard URL from API URL.

    Args:
        api_url: API URL

    Returns:
        Dashboard URL
    """
    from urllib.parse import urlparse

    parsed = urlparse(api_url)

    # SaaS URLs
    if api_url == "https://api.gitguardian.com/v1":
        return "https://dashboard.gitguardian.com"
    elif api_url == "https://api.eu1.gitguardian.com/v1":
        return "https://dashboard.eu1.gitguardian.com"

    # For localhost or self-hosted
    if parsed.netloc.startswith("localhost") or parsed.netloc.startswith("127.0.0.1"):
        return f"{parsed.scheme}://{parsed.netloc}"

    # For other self-hosted, replace api. with dashboard. if present
    hostname = parsed.netloc
    if hostname.startswith("api."):
        hostname = "dashboard." + hostname[4:]

    return f"{parsed.scheme}://{hostname}"


async def run_oauth_flow():
    """Run the OAuth authentication flow."""

    print("\n" + "=" * 70)
    print("GitGuardian OAuth Flow Test Script")
    print("=" * 70)

    # Load configuration from environment
    raw_url = os.environ.get("GITGUARDIAN_URL", "https://dashboard.gitguardian.com")
    api_url = normalize_api_url(raw_url)
    dashboard_url = get_dashboard_url(api_url)

    # Get scopes from environment or use defaults
    scopes = get_scopes_from_env_var()

    # Get token name
    token_name = os.environ.get("GITGUARDIAN_TOKEN_NAME", "MCP OAuth Test Token")

    # Get token lifetime
    token_lifetime_str = os.environ.get("GITGUARDIAN_TOKEN_LIFETIME", "30")
    if token_lifetime_str.lower() == "never":
        token_lifetime = -1
    else:
        try:
            token_lifetime = int(token_lifetime_str)
        except ValueError:
            logger.warning(f"Invalid token lifetime '{token_lifetime_str}', using default 30 days")
            token_lifetime = 30

    # Display configuration
    print(f"\nConfiguration:")
    print(f"  API URL:          {api_url}")
    print(f"  Dashboard URL:    {dashboard_url}")
    print(f"  Token Name:       {token_name}")
    print(f"  Scopes:           {', '.join(scopes)}")

    if token_lifetime == -1:
        print(f"  Token Lifetime:   Never expires")
    else:
        print(f"  Token Lifetime:   {token_lifetime} days")

    print("\n" + "-" * 70)
    print("Starting OAuth Flow...")
    print("-" * 70 + "\n")

    try:
        # Create OAuth client
        oauth_client = GitGuardianOAuthClient(
            api_url=api_url,
            dashboard_url=dashboard_url,
            scopes=scopes,
            token_name=token_name,
            token_lifetime=token_lifetime,
        )

        # Check if we already have a valid token
        if oauth_client.access_token:
            print("\n Found existing valid token!")
            print(f"  Token will be reused without re-authentication")
        else:
            print("\nNo valid token found. Starting OAuth authentication...")
            print("A browser window will open for you to authenticate.")

        # Run the OAuth process
        access_token = await oauth_client.oauth_process()

        print("\n" + "=" * 70)
        print("OAuth Flow Completed Successfully!")
        print("=" * 70)

        # Get token info
        token_info = oauth_client.get_token_info()

        if token_info:
            print(f"\nToken Information:")
            print(f"  Token ID:         {token_info.id}")
            print(f"  Token Name:       {token_info.name}")
            print(f"  Workspace ID:     {token_info.workspace_id}")
            print(f"  Type:             {token_info.type}")
            print(f"  Status:           {token_info.status}")
            print(f"  Created:          {token_info.created_at}")

            if token_info.expire_at:
                print(f"  Expires:          {token_info.expire_at}")
            else:
                print(f"  Expires:          Never")

            print(f"  Scopes:           {', '.join(token_info.scopes)}")
            print(f"\n  Access Token:     {access_token[:20]}...{access_token[-10:]}")
        else:
            print(f"\n  Access Token:     {access_token[:20]}...{access_token[-10:]}")
            print("\n  Note: Could not retrieve detailed token information")

        # Show where token is stored
        from gg_api_core.oauth import FileTokenStorage
        storage = FileTokenStorage()
        print(f"\nToken stored at:    {storage.token_file}")

        print("\n" + "=" * 70)
        print("You can now use this token with the MCP server")
        print("=" * 70 + "\n")

        return 0

    except KeyboardInterrupt:
        print("\n\nOAuth flow cancelled by user.")
        return 1

    except Exception as e:
        logger.exception("OAuth flow failed")
        print(f"\n\nL OAuth Flow Failed!")
        print(f"Error: {str(e)}")
        print("\nPlease check:")
        print("  1. Your GITGUARDIAN_URL is correct")
        print("  2. You have network access to the GitGuardian instance")
        print("  3. The OAuth client ID is correct for your instance")
        return 1


def main():
    """Main entry point."""
    try:
        # Run the async OAuth flow
        exit_code = asyncio.run(run_oauth_flow())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nScript interrupted by user.")
        sys.exit(1)


if __name__ == "__main__":
    main()
