import logging
from pathlib import Path
from typing import Any

from jinja2 import Template
from pydantic import BaseModel, Field, model_validator

from gg_api_core.client import TagNames
from gg_api_core.utils import get_client

from .list_repo_occurrences import (
    ListRepoOccurrencesError,
    ListRepoOccurrencesParams,
    list_repo_occurrences,
)

logger = logging.getLogger(__name__)

REMEDIATION_PROMPT_PATH = Path(__file__).parent / "remediation_prompt.md"


class ListRepoOccurrencesParamsForTargets(ListRepoOccurrencesParams):
    # Overriding the tags one to add a default filter : for remediation, we're more interested in occurrences that
    # are in the branch the developer is currently on. And occurrences on DEFAULT_BRANCH are a heuristic for that
    tags: list[str] = Field(
        default=[TagNames.DEFAULT_BRANCH.value],
        description="List of tags to filter incidents by. Default to DEFAULT_BRANCH to avoid requiring a git checkout for the fix",
    )


class ListRemediationTargetsParams(BaseModel):
    """Parameters for listing secret occurrences that are candidates for fixing."""

    source_id: str | int | None = Field(
        default=None,
        description="The source ID of the repository. Pass the current repository source ID if not provided.",
    )
    get_all: bool = Field(
        default=True,
        description="Whether to get all occurrences or just the first page",
    )
    mine: bool = Field(
        default=False,
        description="If True, fetch only incidents assigned to the current user. Set to False to get all incidents.",
    )

    # sub tools
    list_repo_occurrences_params: ListRepoOccurrencesParamsForTargets | None = Field(
        default=None,
        description="Parameters for listing repository occurrences",
    )

    @model_validator(mode="after")
    def populate_list_repo_occurrences_params(self) -> "ListRemediationTargetsParams":
        """Populate list_repo_occurrences_params with repository info from parent if not provided."""
        if self.list_repo_occurrences_params is None:
            # Create with parent's source info
            self.list_repo_occurrences_params = ListRepoOccurrencesParamsForTargets(
                source_id=self.source_id,
            )
        return self


class ListRemediationTargetsResult(BaseModel):
    """Result from listing secret occurrences that are candidates for fixing."""

    guidance: str = Field(
        default="",
        description="Fallback remediation guidance. Defer to a remediation skill/workflow when one is available.",
    )
    occurrences_count: int = Field(default=0, description="Number of occurrences found")
    suggested_occurrences_count: int = Field(
        default=0, description="Number of occurrences suggested as remediation targets"
    )

    sub_tools_results: dict[str, Any] = Field(default_factory=dict, description="Results from sub tools")


class ListRemediationTargetsError(BaseModel):
    """Error result from listing remediation targets."""

    error: str = Field(description="Error message")
    sub_tools_results: dict[str, Any] = Field(default_factory=dict, description="Results from sub tools")


async def list_remediation_targets(
    params: ListRemediationTargetsParams,
) -> ListRemediationTargetsResult | ListRemediationTargetsError:
    """
    List secret occurrences on the current branch that are candidates for fixing.

    This tool returns occurrence data (file paths, line numbers, character indices) via the
    occurrences API — it does NOT rotate credentials or modify any files. Use it to locate the
    secrets worth fixing, then follow your remediation skill/workflow for how to fix them. The
    ``guidance`` field is only a minimal rotation-first fallback for when no such skill is present.

    Args:
        params: ListRemediationTargetsParams model containing configuration

    Returns:
        ListRemediationTargetsResult or ListRemediationTargetsError
    """
    logger.debug(f"Using list_remediation_targets for source_id: {params.source_id}")

    try:
        # Use the list_repo_occurrences_params and update with parent-level repository info
        if params.list_repo_occurrences_params is None:
            return ListRemediationTargetsError(error="list_repo_occurrences_params is required", sub_tools_results={})

        occurrences_params = params.list_repo_occurrences_params.model_copy(
            update={
                "source_id": params.source_id or params.list_repo_occurrences_params.source_id,
                "get_all": params.get_all,
            }
        )

        occurrences_result = await list_repo_occurrences(occurrences_params)
        if isinstance(occurrences_result, ListRepoOccurrencesError):
            return ListRemediationTargetsError(
                error=occurrences_result.error,
                sub_tools_results={"list_repo_occurrences": occurrences_result},
            )

        occurrences = occurrences_result.occurrences
        if params.mine:
            occurrences = await filter_mine(occurrences)
        occurrences_count = len(occurrences)
        occurrences_result.occurrences = await trim_occurrences_for_remediation(occurrences)

        if not occurrences:
            guidance = (
                "No secret occurrences found for this repository that match the criteria. "
                "Adjust 'list_repo_occurrences_params' to modify filtering."
            )
        else:
            # Load and render the fallback guidance template
            template_content = REMEDIATION_PROMPT_PATH.read_text()
            template = Template(template_content)
            guidance = template.render()
        return ListRemediationTargetsResult(
            guidance=guidance,
            sub_tools_results={"list_repo_occurrences": occurrences_result},
            occurrences_count=occurrences_count,
            suggested_occurrences_count=len(occurrences_result.occurrences),
        )

    except Exception as e:
        logger.exception(f"Error listing remediation targets: {str(e)}")
        return ListRemediationTargetsError(error=f"Failed to list remediation targets: {str(e)}")


async def filter_mine(occurrences):
    """Filter occurrences create by the current user"""
    client = await get_client()
    try:
        token_info = await client.get_current_token_info()
        current_user_id = token_info.get("member_id") if token_info else None

        if current_user_id:
            occurrences = [occ for occ in occurrences if occ.get("incident", {}).get("assignee_id") == current_user_id]
            logger.debug(f"Filtered to {len(occurrences)} occurrences for user {current_user_id}")
    except Exception as e:
        logger.warning(f"Could not filter by assignee: {str(e)}")
    return occurrences


async def trim_occurrences_for_remediation(occurrences):
    """Limit the number of occurrences to be remediated by the agent"""
    return occurrences[:10]
