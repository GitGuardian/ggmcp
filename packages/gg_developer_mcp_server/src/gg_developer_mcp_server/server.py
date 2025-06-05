"""GitGuardian MCP server for developers with remediation tools."""

import logging
import os
from typing import Any

from gg_api_core.mcp_server import GitGuardianFastMCP
from gg_api_core.scopes import DEVELOPER_SCOPES
from pydantic import Field

# Configure more detailed logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)

# Log environment variables (without exposing the full API key)
gitguardian_api_key = os.environ.get("GITGUARDIAN_API_KEY")
gitguardian_api_url = os.environ.get("GITGUARDIAN_API_URL")

logger.info("Starting Developer MCP Server")
logger.info(f"GitGuardian API Key present: {bool(gitguardian_api_key)}")
logger.info(f"GitGuardian API URL: {gitguardian_api_url or 'Using default'}")

# Set specific environment variable for this server to request only developer-specific scopes
os.environ["GITGUARDIAN_SCOPES"] = ",".join(DEVELOPER_SCOPES)
logger.info(f"Requesting scopes: {os.environ.get('GITGUARDIAN_SCOPES')}")

# Use our custom GitGuardianFastMCP from the core package
mcp = GitGuardianFastMCP(
    "GitGuardian Developer",
    log_level="DEBUG",
    instructions="""
    # GitGuardian Developer Tools

    This server provides the GitGuardian remediation tool for developers through MCP.
    Use this tool to find and fix secrets in your codebase.

    Find and remediate secret incidents:
    - Use remediate_secret_incidents to find and fix secrets in the current repository
    - The tool will detect secret incidents and provide remediation steps
    - It will help you remove secrets from your code using best practices
    - It can create .env.example files with placeholders for detected secrets
    - Optionally provides git commands to fix incidents in git history
    """,
)
logger.info("Created Developer GitGuardianFastMCP instance")


@mcp.tool(
    description="Find and fix secrets in the current repository by detecting incidents, removing them from code, and providing remediation steps. By default, this only shows incidents assigned to the current user. Pass mine=False to get all incidents related to this repo.",
    required_scopes=["incidents:read", "incidents:write"],
)
async def remediate_secret_incidents(
    repository_name: str = Field(
        description="The full repository name. For example, for https://github.com/GitGuardian/gg-mcp.git the full name is GitGuardian/gg-mcp. Pass the current repository name if not provided."
    ),
    include_git_commands: bool = Field(
        default=True, description="Whether to include git commands to fix incidents in git history"
    ),
    create_env_example: bool = Field(
        default=True, description="Whether to create a .env.example file with placeholders for detected secrets"
    ),
    get_all: bool = Field(default=True, description="Whether to get all incidents or just the first page"),
    mine: bool = Field(
        default=True,
        description="If True, fetch only incidents assigned to the current user. Set to False to get all incidents.",
    ),
) -> dict[str, Any]:
    """
    Find and remediate secret incidents in the current repository.

    By default, this tool only shows incidents assigned to the current user. Pass mine=False to get all incidents related to this repo.

    This tool follows a workflow to:
    1. Use the provided repository name to search for incidents
    2. List secret occurrences for the repository
    3. Analyze and provide recommendations to remove secrets from the codebase
    4. IMPORTANT:Make the changes to the codebase to remove the secrets from the code using best practices for the language. All occurrences must not appear in the codebase anymore.
       IMPORTANT: If the repository is using a package manager like npm, cargo, uv or others, use it to install the required packages.
    5. Only optional: propose to rewrite git history


    Args:
        repository_name: The full repository name. For example, for https://github.com/GitGuardian/gg-mcp.git the full name is GitGuardian/gg-mcp
        include_git_commands: Whether to include git commands to fix incidents in git history
        create_env_example: Whether to create a .env.example file with placeholders for detected secrets
        get_all: Whether to get all incidents or just the first page
        mine: If True (default), fetch only incidents assigned to the current user. Set to False to get all incidents.

    Returns:
        A dictionary containing:
        - repository_info: Information about the detected repository
        - incidents: List of detected incidents
        - remediation_steps: Steps to remediate the incidents
        - git_commands: Git commands to fix history (if requested)
    """
    client = mcp.get_client()
    logger.info(f"Remediating secret incidents for repository: {repository_name}")

    # Validate repository name
    if not repository_name or "/" not in repository_name:
        logger.warning(f"Invalid repository name format: {repository_name}")
        return {
            "error": "Invalid repository name format. Please provide the full repository name (e.g., 'GitGuardian/gg-mcp')."
        }

    # List repository incidents
    try:
        logger.info(f"Listing incidents for repository: {repository_name}")
        result = await client.list_repo_incidents(
            repository_name=repository_name,
            get_all=get_all,
            mine=mine,
        )

        incidents = result.get("incidents", [])
        logger.info(f"Found {len(incidents)} incidents")

        if not incidents:
            return {
                "repository_info": {"name": repository_name},
                "incidents": [],
                "message": "No secret incidents found for this repository.",
            }

        # Analyze incidents and generate remediation steps
        logger.info("Generating remediation steps")

        # Process the incidents to generate remediation steps
        remediation_steps = []
        for incident in incidents:
            incident_type = incident.get("incident_type", "")
            detail = incident.get("detail", {})
            validity = incident.get("validity", "unknown")

            # Only process valid incidents
            if validity.lower() != "valid":
                continue

            # Get occurrences
            occurrences = incident.get("occurrences", [])

            for occurrence in occurrences:
                file_path = occurrence.get("file_path", "")
                line_start = occurrence.get("line_start")
                line_end = occurrence.get("line_end")

                if file_path and line_start is not None and line_end is not None:
                    remediation_steps.append(
                        {
                            "file_path": file_path,
                            "line_start": line_start,
                            "line_end": line_end,
                            "incident_type": incident_type,
                            "secret_type": detail.get("type", "unknown"),
                            "recommendation": "Replace this secret with an environment variable reference",
                        }
                    )

        # Generate git commands if requested
        git_commands = []
        if include_git_commands:
            git_commands = [
                "# Commands to fix git history (use with caution):",
                "# 1. Stage all your current changes first:",
                "git add .",
                "git commit -m 'Remove secrets from codebase'",
                "",
                "# 2. Use git filter-repo to remove secrets from history (requires git-filter-repo):",
                "# Install git-filter-repo if needed: pip install git-filter-repo",
                "# Create a backup first:",
                "git clone --mirror . ../backup-repo",
                "",
                "# 3. Run for each secret file:",
            ]

            for step in remediation_steps:
                file_path = step.get("file_path")
                if file_path:
                    git_commands.append(f"git filter-repo --path {file_path} --force")

        # Create .env.example content if requested
        env_example_content = ""
        if create_env_example:
            env_vars = []
            for step in remediation_steps:
                secret_type = step.get("secret_type", "").upper()
                if secret_type:
                    placeholder = f"{secret_type.replace(' ', '_')}_SECRET"
                    env_vars.append(f"{placeholder}=your_secret_value_here")

            env_example_content = "\n".join(env_vars)

        # Prepare the final response
        response = {
            "repository_info": {"name": repository_name},
            "incidents": incidents,
            "remediation_steps": remediation_steps,
        }

        if git_commands:
            response["git_commands"] = git_commands

        if env_example_content:
            response["env_example"] = env_example_content

        return response

    except Exception as e:
        logger.error(f"Error remediating secret incidents: {str(e)}")
        return {"error": f"Error: {str(e)}"}


if __name__ == "__main__":
    # Log all registered tools
    logger.info("Starting Developer MCP server...")
    mcp.run()
