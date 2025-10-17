"""GitGuardian MCP server for developers with remediation tools."""

import logging
import os
import subprocess
from typing import Any

from gg_api_core.mcp_server import GitGuardianFastMCP
from gg_api_core.scopes import get_developer_scopes, is_self_hosted_instance, validate_scopes
from gg_api_core.tools.find_current_source_id import find_current_source_id
from gg_api_core.utils import parse_repo_url

from gg_api_core.tools.list_repo_incidents import list_repo_incidents
from gg_api_core.tools.list_repo_occurrences import list_repo_occurrences
from gg_api_core.tools.remediate_secret_incidents import remediate_secret_incidents
from gg_api_core.tools.scan_secret import scan_secrets

# Configure more detailed logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)

# Log environment variables
gitguardian_url = os.environ.get("GITGUARDIAN_URL")

logger.info("Starting Developer MCP Server")
logger.debug(f"GitGuardian URL: {gitguardian_url or 'Using default'}")

# Set specific environment variable for this server to request only developer-specific scopes
# Use dynamic scope detection based on instance type (self-hosted vs SaaS)
# But respect user-specified scopes if they exist
is_self_hosted = is_self_hosted_instance(gitguardian_url)

# Only override scopes if user hasn't specified them
if not os.environ.get("GITGUARDIAN_SCOPES"):
    developer_scopes = get_developer_scopes(gitguardian_url)
    os.environ["GITGUARDIAN_SCOPES"] = ",".join(developer_scopes)
    logger.debug(f"Auto-detected scopes for instance type: {'Self-hosted' if is_self_hosted else 'SaaS'}")
    if is_self_hosted:
        logger.info("Self-hosted instance detected - honeytokens:write scope omitted to avoid permission issues")
else:
    # Validate user-specified scopes
    try:
        user_scopes_str = os.environ.get("GITGUARDIAN_SCOPES")
        validated_scopes = validate_scopes(user_scopes_str)
        os.environ["GITGUARDIAN_SCOPES"] = ",".join(validated_scopes)
        logger.info(f"Using validated user-specified scopes: {os.environ.get('GITGUARDIAN_SCOPES')}")
    except ValueError as e:
        logger.error(f"Invalid scopes configuration: {e}")
        logger.error("Please check your GITGUARDIAN_SCOPES environment variable")
        raise

logger.debug(f"Final scopes: {os.environ.get('GITGUARDIAN_SCOPES')}")

# Use our custom GitGuardianFastMCP from the core package
mcp = GitGuardianFastMCP(
    "GitGuardian Developer",
    log_level="DEBUG",
    instructions="""
    # GitGuardian Developer Tools for Secret Detection & Remediation

    This server provides GitGuardian's secret detection and remediation capabilities through MCP for developers working within IDE environments like Cursor, Windsurf, or Zed.

    ## Secret Management Capabilities

    This server focuses on helping developers manage secrets in their repositories through:

    1. **Finding Existing Secret Incidents**:
       - Detect secrets already identified as GitGuardian incidents in your repository
       - Use `list_repo_incidents` to view secret incidents in a repository (defaults to first page)
       - Filter incidents by various criteria including those assigned to you
       - Pass get_all=True when you need comprehensive results

    2. **Proactive Secret Scanning**:
       - Use `scan_secrets` to detect secrets in code before they're committed
       - Identify secrets that haven't yet been reported as GitGuardian incidents
       - Prevent accidental secret commits before they happen

    3. **Complete Secret Remediation**:
       - Use `remediate_secret_incidents` for guided secret removal
       - By default fetches the first page of results for token efficiency; pass get_all=True for comprehensive results
       - Get best practice recommendations for different types of secrets
       - Replace hardcoded secrets with environment variables
       - Create .env.example files with placeholders for detected secrets
       - Get optional git commands to repair git history containing secrets
    
    4. **Generate and hide honey tokens**:
       - Use `generate_honey_tokens` to generate and hide honey tokens
       - If you want to create a new token, you must pass new_token=True to generate_honey_tokens
       - hide the generated token in the codebase


    All tools operate within your IDE environment to provide immediate feedback and remediation steps for secret management.
    """,
)
logger.info("Created Developer GitGuardianFastMCP instance")


mcp.add_tool(remediate_secret_incidents,
    description="Find and fix secrets in the current repository using exact match locations (file paths, line numbers, character indices). "
    "This tool leverages the occurrences API to provide precise remediation instructions without needing to search for secrets in files. "
    "By default, only shows incidents assigned to the current user and fetches the first page of results for token efficiency. "
    "Pass mine=False to get all incidents. Pass get_all=True for comprehensive results when explicitly requested.",
    required_scopes=["incidents:read", "sources:read"],
)

mcp.add_tool(scan_secrets,
             description="""
    Scan multiple content items for secrets and policy breaks.

    This tool allows you to scan multiple files or content strings at once for secrets and policy violations.
    Each document must have a 'document' field and can optionally include a 'filename' field for better context.
    Do not send documents that are not related to the codebase, only send files that are part of the codebase.
    Do not send documents that are in the .gitignore file.
    """,
             required_scopes=["scan"],
)

mcp.add_tool(list_repo_incidents,
    description="List secret incidents or occurrences related to a specific repository. "
    "By default, only shows incidents assigned to the current user and fetches the first page of results for token efficiency. "
    "Pass mine=False to get all incidents (even ones not assigned to you). Pass get_all=True for comprehensive results when explicitly requested.",
    required_scopes=["incidents:read", "sources:read"],
)


mcp.add_tool(
    list_repo_occurrences,
    description="List secret occurrences for a specific repository with exact match locations. "
    "Returns detailed occurrence data including file paths, line numbers, and character indices where secrets were detected. "
    "By default fetches the first page of results for token efficiency; pass get_all=True for comprehensive results. "
    "Use this tool when you need to locate and remediate secrets in the codebase with precise file locations.",
    required_scopes=["incidents:read"],
)


mcp.add_tool(
    find_current_source_id,
    description="Find the GitGuardian source_id for the current repository. "
    "This tool automatically detects the current git repository and searches for its source_id in GitGuardian. "
    "Useful when you need to reference the repository in other API calls.",
    required_scopes=["sources:read"],
)

# TODO(APPAI-28)
# mcp.add_tool(
#     generate_honeytoken,
#     description="Generate an AWS GitGuardian honeytoken and get injection recommendations",
#     required_scopes=["honeytokens:write"],
# )


# TODO(APPAI-28)
# mcp.add_tool(
#     list_honeytokens,
#     description="List honeytokens from the GitGuardian dashboard with filtering options",
#     required_scopes=["honeytokens:read"],
# )


if __name__ == "__main__":
    logger.info("Starting Developer MCP server...")
    mcp.run()
