from typing import Any
import logging

from pydantic import Field

from .list_repo_incidents import list_repo_incidents

logger = logging.getLogger(__name__)




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
        mine: If True, fetch only incidents assigned to the current user. Set to False to get all incidents.

    Returns:
        A dictionary containing:
        - repository_info: Information about the detected repository
        - incidents: List of detected incidents
        - remediation_steps: Steps to remediate the incidents
        - git_commands: Git commands to fix history (if requested)
    """
    logger.debug(f"Using remediate_secret_incidents with sources API for: {repository_name}")

    try:
        incidents_result = await list_repo_incidents(
            repository_name=repository_name,
            get_all=get_all,
            mine=mine,
            # Explicitly pass None for optional parameters to avoid FieldInfo objects
            from_date=None,
            to_date=None,
            presence=None,
            tags=None,
            ordering=None,
            per_page=20,
            cursor=None,
        )

        if "error" in incidents_result:
            return {"error": incidents_result["error"]}

        incidents = incidents_result.get("incidents", [])

        if not incidents:
            return {
                "repository_info": {"name": repository_name},
                "message": "No secret incidents found for this repository that match the criteria.",
                "remediation_steps": [],
            }

        # Continue with remediation logic using the incidents...
        # This part is common between the optimized and fallback versions, so we can call a helper function
        logger.debug(f"Processing {len(incidents)} incidents for remediation")
        result = await _process_incidents_for_remediation(
            incidents=incidents,
            repository_name=repository_name,
            include_git_commands=include_git_commands,
            create_env_example=create_env_example,
        )
        logger.debug(
            f"Remediation processing complete, returning result with {len(result.get('remediation_steps', []))} steps"
        )
        return result

    except Exception as e:
        logger.error(f"Error remediating incidents: {str(e)}")
        return {"error": f"Failed to remediate incidents: {str(e)}"}


async def _process_incidents_for_remediation(
    incidents: list[dict[str, Any]],
    repository_name: str,
    include_git_commands: bool = True,
    create_env_example: bool = True,
) -> dict[str, Any]:
    """
    Process incidents for remediation after they've been fetched.

    This helper function contains the shared logic for processing incidents
    and providing remediation steps.

    Args:
        incidents: List of incidents to remediate
        repository_name: Repository name
        include_git_commands: Whether to include git commands
        create_env_example: Whether to create .env.example

    Returns:
        Remediation steps for each incident
    """
    # For now, we'll just return the incidents list
    # In a real implementation, this would analyze the incidents and provide remediation steps
    remediation_steps = []
    for incident in incidents:
        step = {
            "incident_id": incident.get("id"),
            "secret_type": incident.get("type"),
            "recommendations": [
                f"Remove the secret from {len(incident.get('repository_occurrences', []))} files",
                "Use environment variables instead of hardcoded secrets",
            ],
            "include_git_commands": include_git_commands,
            "create_env_example": create_env_example,
        }
        remediation_steps.append(step)

    return {
        "repository_info": {"name": repository_name},
        "incidents_count": len(incidents),
        "incidents": incidents,
        "remediation_steps": remediation_steps,
    }
