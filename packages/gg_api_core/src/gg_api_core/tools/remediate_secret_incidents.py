from typing import Any
import logging

from pydantic import BaseModel, Field, model_validator

from gg_api_core.client import TagNames
from gg_api_core.utils import get_client
from .list_repo_occurrences import list_repo_occurrences, ListRepoOccurrencesParams, ListRepoOccurrencesFilters
from .list_repo_incidents import list_repo_incidents

logger = logging.getLogger(__name__)


class RemediateOccurrencesFilters(ListRepoOccurrencesFilters):
    tags: list[str] = Field(
        default=[TagNames.DEFAULT_BRANCH.value],
        description="List of tags to filter incidents by. Default to DEFAULT_BRANCH to avoid requiring a git checkout for the fix",
    )


class RemediateSecretIncidentsParams(RemediateOccurrencesFilters):
    """Parameters for remediating secret incidents."""
    repository_name: str = Field(
        description="The full repository name. For example, for https://github.com/GitGuardian/ggmcp.git the full name is GitGuardian/ggmcp. Pass the current repository name if not provided.",
        default = None
    )
    source_id: str = Field(
        description="The source ID of the repository. Pass the current repository source ID if not provided.",
        default=None
    )
    get_all: bool = Field(default=True, description="Whether to get all incidents or just the first page")
    mine: bool = Field(
        default=False,
        description="If True, fetch only incidents assigned to the current user. Set to False to get all incidents.",
    )

    # Behaviour
    include_git_commands: bool = Field(
        default=True, description="Whether to include git commands to fix incidents in git history"
    )
    create_env_example: bool = Field(
        default=True, description="Whether to create a .env.example file with placeholders for detected secrets"
    )

    # sub tools
    list_repo_occurrences_params: RemediateOccurrencesFilters = Field(
        default_factory=RemediateOccurrencesFilters,
        description="Parameters for listing repository occurrences",
    )

    @model_validator(mode="after")
    def validate_source_or_repository(self) -> "RemediateSecretIncidentsParams":
        """Validate that either source_id or repository_name is provided."""
        if not self.source_id and not self.repository_name:
            raise ValueError("Either 'source_id' or 'repository_name' must be provided")
        return self


class RemediateSecretIncidentsResult(BaseModel):
    """Result from remediating secret incidents."""
    repository_info: dict[str, Any] = Field(description="Information about the repository")
    summary: dict[str, Any] | None = Field(default=None, description="Summary of occurrences, files, and secret types")
    remediation_steps: list[dict[str, Any]] = Field(default_factory=list, description="Steps for remediating each file")
    message: str | None = Field(default=None, description="Message when no occurrences found")
    env_example_content: str | None = Field(default=None, description="Suggested .env.example content")
    env_example_instructions: list[str] | None = Field(default=None, description="Instructions for .env.example")
    git_commands: dict[str, Any] | None = Field(default=None, description="Git commands to fix history")
    applied_filters: dict[str, Any] = Field(default_factory=dict, description="Filters applied when querying occurrences")
    suggestion: str = Field(default="", description="Suggestions for interpreting results")


class RemediateSecretIncidentsError(BaseModel):
    """Error result from remediating secret incidents."""
    error: str = Field(description="Error message")


async def remediate_secret_incidents(params: RemediateSecretIncidentsParams) -> RemediateSecretIncidentsResult | RemediateSecretIncidentsError:
    """
    Find and remediate secret incidents in the current repository using EXACT match locations.

    By default, this tool only shows incidents assigned to the current user. Pass mine=False to get all incidents related to this repo.

    This tool now uses the occurrences API to get precise file locations, line numbers, and character indices,
    eliminating the need to search for secrets in files. The workflow is:

    1. Fetch secret occurrences with exact match locations (file path, line_start, line_end, index_start, index_end)
    2. Group occurrences by file for efficient remediation
    3. Sort matches from bottom to top to prevent line number shifts during editing
    4. Provide detailed remediation steps with exact locations for each secret
    5. IMPORTANT: Make the changes to the codebase using the provided indices:
       - Use index_start and index_end to locate the exact secret in the file
       - Replace hardcoded secrets with environment variable references
       - Ensure all occurrences are removed from the codebase
       - IMPORTANT: If the repository uses a package manager (npm, cargo, uv, etc.), use it to install required packages
    6. Optional: Generate git commands to rewrite history and remove secrets from git

    The tool provides:
    - Exact file paths and line numbers for each secret
    - Character-level indices (index_start, index_end) to locate secrets precisely
    - Context lines (pre/post) to understand the surrounding code
    - Sorted matches to enable safe sequential removal (bottom-to-top)

    Args:
        params: RemediateSecretIncidentsParams model containing remediation configuration

    Returns:
        A dictionary containing:
        - repository_info: Information about the repository
        - summary: Overview of occurrences, files affected, and secret types
        - remediation_steps: Detailed steps with exact locations for each file
        - env_example_content: Suggested .env.example content (if requested)
        - git_commands: Git commands to fix history (if requested)
    """
    logger.debug(f"Using remediate_secret_incidents with occurrences API for: {params.repository_name}")

    try:
        # Get detailed occurrences with exact match locations
        # Extract filter parameters from list_repo_occurrences_params
        filter_params = params.list_repo_occurrences_params.model_dump(exclude_none=True)

        occurrences_params = ListRepoOccurrencesParams(
            repository_name=params.repository_name,
            source_id=params.source_id,
            get_all=params.get_all,
            **filter_params,  # Spread the filter parameters
        )
        occurrences_result = await list_repo_occurrences(occurrences_params)

        # Check if list_repo_occurrences returned an error
        if isinstance(occurrences_result, dict) and "error" in occurrences_result:
            return RemediateSecretIncidentsError(error=occurrences_result["error"])

        # Since list_repo_occurrences now returns Pydantic models, handle both old dict and new model formats
        if hasattr(occurrences_result, 'model_dump'):
            occurrences_dict = occurrences_result.model_dump()
        else:
            occurrences_dict = occurrences_result

        occurrences = occurrences_dict.get("occurrences", [])

        # Filter by assignee if mine=True
        if params.mine:
            # Get current user info to filter by assignee
            client = get_client()
            try:
                token_info = await client.get_current_token_info()
                current_user_id = token_info.get("user_id") if token_info else None

                if current_user_id:
                    # Filter occurrences assigned to current user
                    occurrences = [
                        occ for occ in occurrences
                        if occ.get("incident", {}).get("assignee_id") == current_user_id
                    ]
                    logger.debug(f"Filtered to {len(occurrences)} occurrences assigned to user {current_user_id}")
            except Exception as e:
                logger.warning(f"Could not filter by assignee: {str(e)}")

        if not occurrences:
            return RemediateSecretIncidentsResult(
                repository_info={"name": params.repository_name},
                message="No secret occurrences found for this repository that match the criteria.",
                remediation_steps=[],
                applied_filters=occurrences_dict.get("applied_filters", {}),
                suggestion=occurrences_dict.get("suggestion", ""),
            )

        # Process occurrences for remediation with exact location data
        logger.debug(f"Processing {len(occurrences)} occurrences with exact locations for remediation")
        result = await _process_occurrences_for_remediation(
            occurrences=occurrences,
            repository_name=params.repository_name,
            include_git_commands=params.include_git_commands,
            create_env_example=params.create_env_example,
        )
        logger.debug(
            f"Remediation processing complete, returning result with {len(result.get('remediation_steps', []))} steps"
        )
        # Convert dict result to Pydantic model
        return RemediateSecretIncidentsResult(**result)

    except Exception as e:
        logger.error(f"Error remediating incidents: {str(e)}")
        return RemediateSecretIncidentsError(error=f"Failed to remediate incidents: {str(e)}")


async def _process_occurrences_for_remediation(
    occurrences: list[dict[str, Any]],
    repository_name: str,
    include_git_commands: bool = True,
    create_env_example: bool = True,
) -> dict[str, Any]:
    """
    Process occurrences for remediation using exact match locations.

    This function leverages the detailed location data from occurrences (file paths, line numbers,
    character indices) to provide precise remediation instructions without needing to search files.

    Args:
        occurrences: List of occurrences with exact match locations
        repository_name: Repository name
        include_git_commands: Whether to include git commands
        create_env_example: Whether to create .env.example

    Returns:
        Remediation steps for each occurrence with exact file locations
    """
    # Group occurrences by file for efficient remediation
    occurrences_by_file = {}
    secret_types = set()
    affected_files = set()

    for occurrence in occurrences:
        # Extract location data
        matches = occurrence.get("matches", [])
        incident_data = occurrence.get("incident", {})
        secret_type = incident_data.get("detector", {}).get("name", "Unknown")
        secret_types.add(secret_type)

        for match in matches:
            file_path = match.get("match", {}).get("filename")
            if not file_path:
                continue

            affected_files.add(file_path)

            if file_path not in occurrences_by_file:
                occurrences_by_file[file_path] = []

            # Store detailed match information
            match_info = {
                "occurrence_id": occurrence.get("id"),
                "incident_id": incident_data.get("id"),
                "secret_type": secret_type,
                "line_start": match.get("match", {}).get("line_start"),
                "line_end": match.get("match", {}).get("line_end"),
                "index_start": match.get("match", {}).get("index_start"),
                "index_end": match.get("match", {}).get("index_end"),
                "match_type": match.get("type"),
                "pre_line_start": match.get("pre_line_start"),
                "pre_line_end": match.get("pre_line_end"),
                "post_line_start": match.get("post_line_start"),
                "post_line_end": match.get("post_line_end"),
            }
            occurrences_by_file[file_path].append(match_info)

    # Build remediation steps with exact locations
    remediation_steps = []

    for file_path, matches in occurrences_by_file.items():
        # Sort matches by line number (descending) so we can remove from bottom to top
        # This prevents line number shifts when making multiple edits
        sorted_matches = sorted(matches, key=lambda m: m["line_start"] or 0, reverse=True)

        step = {
            "file": file_path,
            "action": "remove_secrets",
            "matches": sorted_matches,
            "instructions": [
                f"File: {file_path}",
                f"Found {len(sorted_matches)} secret(s) in this file",
                "Matches are sorted from bottom to top for safe sequential removal",
                "",
                "For each match:",
                "1. Read the file content",
                f"2. Navigate to line {sorted_matches[0].get('line_start')} (and other match locations)",
                "3. Use the exact index_start and index_end to locate the secret",
                "4. Replace the hardcoded secret with an environment variable reference",
                "5. Ensure the secret is added to .env (gitignored) and .env.example (committed)",
            ],
            "recommendations": [
                "Replace secrets with environment variables (e.g., process.env.API_KEY, os.getenv('API_KEY'))",
                "Add the real secret to .env file (ensure .env is in .gitignore)",
                "Add a placeholder to .env.example for documentation",
                "Use a secrets management solution for production (e.g., AWS Secrets Manager, HashiCorp Vault)",
            ],
        }
        remediation_steps.append(step)

    # Generate .env.example content if requested
    env_example_content = None
    if create_env_example:
        env_vars = []
        for secret_type in secret_types:
            # Generate sensible environment variable names from secret types
            env_var_name = secret_type.upper().replace(" ", "_").replace("-", "_")
            env_vars.append(f"{env_var_name}=your_{secret_type.lower().replace(' ', '_')}_here")

        if env_vars:
            env_example_content = "\n".join(env_vars)

    # Generate git commands if requested
    git_commands = None
    if include_git_commands:
        git_commands = {
            "warning": "⚠️  These commands will rewrite git history. Only use if you understand the implications.",
            "commands": [
                "# First, ensure all secrets are removed from working directory",
                "git add .",
                'git commit -m "Remove hardcoded secrets"',
            ],
        }

    result = {
        "repository_info": {"name": repository_name},
        "summary": {
            "total_occurrences": len(occurrences),
            "affected_files": len(affected_files),
            "secret_types": list(secret_types),
            "files": list(affected_files),
        },
        "remediation_steps": remediation_steps,
    }

    if env_example_content:
        result["env_example_content"] = env_example_content
        result["env_example_instructions"] = [
            "Create or update .env.example in your repository root:",
            f"```\n{env_example_content}\n```",
            "",
            "Ensure .env is in .gitignore:",
            "```\n.env\n```",
        ]

    if git_commands:
        result["git_commands"] = git_commands

    return result
