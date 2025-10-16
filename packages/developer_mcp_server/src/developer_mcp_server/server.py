"""GitGuardian MCP server for developers with remediation tools."""

import logging
import os
import subprocess
from typing import Any

from gg_api_core.mcp_server import GitGuardianFastMCP
from gg_api_core.scopes import get_developer_scopes, is_self_hosted_instance, validate_scopes
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
       - Use `list_repo_incidents` to view all secret incidents in a repository
       - Filter incidents by various criteria including those assigned to you

    2. **Proactive Secret Scanning**:
       - Use `scan_secrets` to detect secrets in code before they're committed
       - Identify secrets that haven't yet been reported as GitGuardian incidents
       - Prevent accidental secret commits before they happen

    3. **Complete Secret Remediation**:
       - Use `remediate_secret_incidents` for guided secret removal
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
    "By default, this only shows incidents assigned to the current user. Pass mine=False to get all incidents related to this repo.",
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
    description="List secret incidents or occurrences related to a specific repository, and assigned to the current user."
    "By default, this tool only shows incidents assigned to the current user. "
    "Only pass mine=False to get all incidents related to this repo if the user explicitly asks for all incidents even the ones not assigned to him.",
    required_scopes=["incidents:read", "sources:read"],
)


mcp.add_tool(
    list_repo_occurrences,
    description="List secret occurrences for a specific repository with exact match locations. "
    "Returns detailed occurrence data including file paths, line numbers, and character indices where secrets were detected. "
    "Use this tool when you need to locate and remediate secrets in the codebase with precise file locations.",
    required_scopes=["incidents:read"],
)


@mcp.tool(
    description="Find the GitGuardian source_id for the current repository. "
    "This tool automatically detects the current git repository and searches for its source_id in GitGuardian. "
    "Useful when you need to reference the repository in other API calls.",
    required_scopes=["sources:read"],
)
async def find_current_repo_source_id() -> dict[str, Any]:
    """
    Find the GitGuardian source_id for the current repository.

    This tool:
    1. Gets the current repository information from git
    2. Extracts the repository name from the remote URL
    3. Searches GitGuardian for matching sources
    4. Returns the source_id if an exact match is found
    5. If no exact match, returns all search results for the model to choose from

    Returns:
        A dictionary containing:
        - repository_name: The detected repository name
        - source_id: The GitGuardian source ID (if exact match found)
        - source: Full source information from GitGuardian (if exact match found)
        - candidates: List of candidate sources (if no exact match but potential matches found)
        - error: Error message if something went wrong
    """
    client = mcp.get_client()
    logger.debug("Finding source_id for current repository")

    try:
        # Get current repository remote URL
        try:
            result = subprocess.run(
                ["git", "config", "--get", "remote.origin.url"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )
            remote_url = result.stdout.strip()
            logger.debug(f"Found remote URL: {remote_url}")
        except subprocess.CalledProcessError as e:
            return {
                "error": "Not a git repository or no remote 'origin' configured",
                "details": str(e),
            }
        except subprocess.TimeoutExpired:
            return {"error": "Git command timed out"}

        # Parse repository name from remote URL
        repository_name = parse_repo_url(remote_url)

        if not repository_name:
            return {
                "error": f"Could not parse repository URL: {remote_url}",
                "details": "The URL format is not recognized. Supported platforms: GitHub, GitLab (Cloud & Self-hosted), Bitbucket (Cloud & Data Center), Azure DevOps",
            }

        logger.info(f"Detected repository name: {repository_name}")

        # Search for the source in GitGuardian with robust non-exact matching
        result = await client.get_source_by_name(repository_name, return_all_on_no_match=True)

        # Handle exact match (single dict result)
        if isinstance(result, dict):
            source_id = result.get("id")
            logger.info(f"Found exact match with source_id: {source_id}")
            return {
                "repository_name": repository_name,
                "source_id": source_id,
                "source": result,
                "message": f"Successfully found exact match for GitGuardian source: {repository_name}",
            }

        # Handle multiple candidates (list result)
        elif isinstance(result, list) and len(result) > 0:
            logger.info(f"Found {len(result)} candidate sources for repository: {repository_name}")
            return {
                "repository_name": repository_name,
                "message": f"No exact match found for '{repository_name}', but found {len(result)} potential matches.",
                "suggestion": "Review the candidates below and determine which source best matches the current repository based on the name and URL.",
                "candidates": [
                    {
                        "id": source.get("id"),
                        "url": source.get("url"),
                        "name": source.get("full_name") or source.get("name"),
                        "monitored": source.get("monitored"),
                        "deleted_at": source.get("deleted_at"),
                    }
                    for source in result
                ],
            }

        # No matches found at all
        else:
            # Try searching with just the repo name (without org) as fallback
            if "/" in repository_name:
                repo_only = repository_name.split("/")[-1]
                logger.debug(f"Trying fallback search with repo name only: {repo_only}")
                fallback_result = await client.get_source_by_name(repo_only, return_all_on_no_match=True)

                # Handle fallback results
                if isinstance(fallback_result, dict):
                    source_id = fallback_result.get("id")
                    logger.info(f"Found match using repo name only, source_id: {source_id}")
                    return {
                        "repository_name": repository_name,
                        "source_id": source_id,
                        "source": fallback_result,
                        "message": f"Found match using repository name '{repo_only}' (without organization prefix)",
                    }
                elif isinstance(fallback_result, list) and len(fallback_result) > 0:
                    logger.info(f"Found {len(fallback_result)} candidates using repo name only")
                    return {
                        "repository_name": repository_name,
                        "message": f"No exact match for '{repository_name}', but found {len(fallback_result)} potential matches using repo name '{repo_only}'.",
                        "suggestion": "Review the candidates below and determine which source best matches the current repository.",
                        "candidates": [
                            {
                                "id": source.get("id"),
                                "url": source.get("url"),
                                "name": source.get("full_name") or source.get("name"),
                                "monitored": source.get("monitored"),
                                "deleted_at": source.get("deleted_at"),
                            }
                            for source in fallback_result
                        ],
                    }

            # Absolutely no matches found
            logger.warning(f"No sources found for repository: {repository_name}")
            return {
                "repository_name": repository_name,
                "error": f"Repository '{repository_name}' not found in GitGuardian",
                "message": "The repository may not be connected to GitGuardian, or you may not have access to it.",
                "suggestion": "Check that the repository is properly connected to GitGuardian and that your account has access to it.",
            }

    except Exception as e:
        logger.error(f"Error finding source_id: {str(e)}")
        return {"error": f"Failed to find source_id: {str(e)}"}


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
