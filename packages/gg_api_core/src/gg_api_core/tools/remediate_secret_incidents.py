import logging
from pathlib import Path
from typing import Any

from jinja2 import Template
from pydantic import BaseModel, Field, model_validator

from gg_api_core.client import TagNames
from gg_api_core.utils import get_client

from .list_repo_occurrences import ListRepoOccurrencesError, ListRepoOccurrencesParams, list_repo_occurrences

logger = logging.getLogger(__name__)

REMEDIATION_PROMPT_PATH = Path(__file__).parent / "remediation_prompt.md"


class ListRepoOccurrencesParamsForRemediate(ListRepoOccurrencesParams):
    # Overriding the tags one to add a default filter : for remediation, we're more interested in occurrences that
    # are in the branch the developer is currently on. And occurrences on DEFAULT_BRANCH are a heuristic for that
    tags: list[str] = Field(
        default=[TagNames.DEFAULT_BRANCH.value],
        description="List of tags to filter incidents by. Default to DEFAULT_BRANCH to avoid requiring a git checkout for the fix",
    )


class RemediateSecretIncidentsParams(BaseModel):
    """Parameters for remediating secret incidents."""

    repository_name: str | None = Field(
        default=None,
        description="The full repository name. For example, for https://github.com/GitGuardian/ggmcp.git the full name is GitGuardian/ggmcp. Pass the current repository name if not provided.",
    )
    source_id: str | int | None = Field(
        default=None,
        description="The source ID of the repository. Pass the current repository source ID if not provided.",
    )
    get_all: bool = Field(default=True, description="Whether to get all occurrences or just the first page")
    mine: bool = Field(
        default=False,
        description="If True, fetch only incidents assigned to the current user. Set to False to get all incidents.",
    )

    # Behaviour
    git_commands: bool = Field(
        default=True, description="Whether to include git commands to fix incidents in git history"
    )
    create_env_example: bool = Field(
        default=True,
        description="Whether to suggest creating a .env.example file with placeholders for detected secrets",
    )
    add_to_env: bool = Field(default=True, description="Whether to suggest adding secrets to .env file")

    # sub tools
    list_repo_occurrences_params: ListRepoOccurrencesParamsForRemediate | None = Field(
        default=None,
        description="Parameters for listing repository occurrences",
    )

    @model_validator(mode="after")
    def populate_list_repo_occurrences_params(self) -> "RemediateSecretIncidentsParams":
        """Populate list_repo_occurrences_params with repository info from parent if not provided."""
        if self.list_repo_occurrences_params is None:
            # Create with parent's repository info
            self.list_repo_occurrences_params = ListRepoOccurrencesParamsForRemediate(
                repository_name=self.repository_name,
                source_id=self.source_id,
            )
        return self


class RemediateSecretIncidentsResult(BaseModel):
    """Result from remediating secret incidents."""

    remediation_instructions: str = Field(default="", description="Instructions for remediating occurrences")
    occurrences_count: int = Field(default=0, description="Number of occurrences found")
    suggested_occurrences_for_remediation_count: int = Field(
        default=0, description="Number of occurrences suggested for remediation"
    )

    sub_tools_results: dict[str, BaseModel] = Field(default_factory=dict, description="Results from sub tools")


class RemediateSecretIncidentsError(BaseModel):
    """Error result from remediating secret incidents."""

    error: str = Field(description="Error message")
    sub_tools_results: dict[str, Any] = Field(default_factory=dict, description="Results from sub tools")


async def remediate_secret_incidents(
    params: RemediateSecretIncidentsParams,
) -> RemediateSecretIncidentsResult | RemediateSecretIncidentsError:
    """
    Find and remediate secret incidents in the current repository.

    This tool uses the occurrences API to find secrets and provides simple remediation suggestions.

    Args:
        params: RemediateSecretIncidentsParams model containing remediation configuration

    Returns:
        RemediateSecretIncidentsResult or RemediateSecretIncidentsError
    """
    logger.debug(f"Using remediate_secret_incidents for: {params.repository_name}")

    try:
        # Use the list_repo_occurrences_params and update with parent-level repository info
        if params.list_repo_occurrences_params is None:
            return RemediateSecretIncidentsError(error="list_repo_occurrences_params is required", sub_tools_results={})

        occurrences_params = params.list_repo_occurrences_params.model_copy(
            update={
                "repository_name": params.repository_name or params.list_repo_occurrences_params.repository_name,
                "source_id": params.source_id or params.list_repo_occurrences_params.source_id,
                "get_all": params.get_all,
            }
        )

        occurrences_result = await list_repo_occurrences(occurrences_params)
        if isinstance(occurrences_result, ListRepoOccurrencesError):
            return RemediateSecretIncidentsError(
                error=occurrences_result.error, sub_tools_results={"list_repo_occurrences": occurrences_result}
            )

        occurrences = occurrences_result.occurrences
        if params.mine:
            occurrences = await filter_mine(occurrences)
        occurrences_count = len(occurrences)
        occurrences_result.occurrences = await trim_occurrences_for_remediation(occurrences)

        if not occurrences:
            remediation_instructions = (
                "No secret occurrences found for this repository that match the criteria. "
                "Adjust 'list_repo_occurrences_params' to modify filtering."
            )
        else:
            # Load and render the Jinja2 template
            template_content = REMEDIATION_PROMPT_PATH.read_text()
            template = Template(template_content)
            remediation_instructions = template.render(
                add_to_env=params.add_to_env,
                env_example=params.create_env_example,
                git_commands=params.git_commands,
            )
        return RemediateSecretIncidentsResult(
            remediation_instructions=remediation_instructions,
            sub_tools_results={"list_repo_occurrences": occurrences_result},
            occurrences_count=occurrences_count,
            suggested_occurrences_for_remediation_count=len(occurrences),
        )

    except Exception as e:
        logger.exception(f"Error remediating incidents: {str(e)}")
        return RemediateSecretIncidentsError(error=f"Failed to remediate incidents: {str(e)}")


async def filter_mine(occurrences):
    """Filter occurrences create by the current user"""
    client = await get_client()
    try:
        token_info = await client.get_current_token_info()
        current_user_id = token_info.get("user_id") if token_info else None

        if current_user_id:
            occurrences = [occ for occ in occurrences if occ.get("incident", {}).get("assignee_id") == current_user_id]
            logger.debug(f"Filtered to {len(occurrences)} occurrences for user {current_user_id}")
    except Exception as e:
        logger.warning(f"Could not filter by assignee: {str(e)}")
    return occurrences


async def trim_occurrences_for_remediation(occurrences):
    """Limit the number of occurrences to be remediated by the agent"""
    return occurrences[:10]
