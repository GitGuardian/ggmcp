from typing import Any
import logging

from pydantic import BaseModel, Field

from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


DEFAULT_EXCLUDED_TAGS = ["TEST_FILE", "FALSE_POSITIVE", "CHECK_RUN_SKIP_FALSE_POSITIVE", "CHECK_RUN_SKIP_LOW_RISK", "CHECK_RUN_SKIP_TEST_CRED"]
DEFAULT_SEVERITIES = ["critical", "high", "medium"]
DEFAULT_STATUSES = ["TRIGGERED", "ASSIGNED", "RESOLVED"]  # We exclude "IGNORED" ones
DEFAULT_VALIDITIES = ["valid", "failed_to_check", "no_checker", "unknown"]  # We exclude "invalid" ones


class ListRepoOccurrencesParams(BaseModel):
    """Parameters for listing repository occurrences."""
    repository_name: str | None = Field(
        default=None,
        description="The full repository name. For example, for https://github.com/GitGuardian/ggmcp.git the full name is GitGuardian/ggmcp. Pass the current repository name if not provided. Not required if source_id is provided."
    )
    source_id: str | None = Field(
        default=None,
        description="The GitGuardian source ID to filter by. Can be obtained using find_current_source_id. If provided, repository_name is not required."
    )
    from_date: str | None = Field(
        default=None, description="Filter occurrences created after this date (ISO format: YYYY-MM-DD)"
    )
    to_date: str | None = Field(
        default=None, description="Filter occurrences created before this date (ISO format: YYYY-MM-DD)"
    )
    presence: str | None = Field(default=None, description="Filter by presence status")
    tags: list[str] | None = Field(default=None, description="Filter by tags (list of tag names)")
    exclude_tags: list[str] | None = Field(
        default=DEFAULT_EXCLUDED_TAGS,
        description="Exclude occurrences with these tag names. Pass empty list to disable filtering."
    )
    ordering: str | None = Field(default=None, description="Sort field (e.g., 'date', '-date' for descending)")
    per_page: int = Field(default=20, description="Number of results per page (default: 20, min: 1, max: 100)")
    cursor: str | None = Field(default=None, description="Pagination cursor for fetching next page of results")
    get_all: bool = Field(default=False, description="If True, fetch all results using cursor-based pagination")
    status: list[str] | None = Field(default=DEFAULT_STATUSES, description="Filter by status (list of status names)")
    severity: list[str] | None = Field(default=DEFAULT_SEVERITIES, description="Filter by severity (list of severity names)")
    validity: list[str] | None = Field(default=DEFAULT_VALIDITIES, description="Filter by validity (list of validity names)")


async def list_repo_occurrences(params: ListRepoOccurrencesParams) -> dict[str, Any]:
    """
    List secret occurrences for a specific repository using the GitGuardian v1/occurrences/secrets API.

    This tool returns detailed occurrence data with EXACT match locations, including:
    - File path where the secret was found
    - Line number in the file
    - Start and end character indices of the match
    - The type of secret detected
    - Match context and patterns

    This is particularly useful for automated remediation workflows where the agent needs to:
    1. Locate the exact position of secrets in files
    2. Read the surrounding code context
    3. Make precise edits to remove or replace secrets
    4. Verify that secrets have been properly removed

    Use list_repo_incidents for a higher-level view of incidents grouped by secret type.

    By default, occurrences tagged with TEST_FILE or FALSE_POSITIVE are excluded. Pass exclude_tags=[] to disable this filtering.

    Args:
        params: ListRepoOccurrencesParams model containing all filtering options

    Returns:
        List of secret occurrences with detailed match information including file locations and indices
    """
    client = get_client()

    # Validate that at least one of repository_name or source_id is provided
    if not params.repository_name and not params.source_id:
        return {"error": "Either repository_name or source_id must be provided"}

    logger.debug(f"Listing occurrences with repository_name={params.repository_name}, source_id={params.source_id}")

    try:
        # Call the list_occurrences method with appropriate filter
        if params.source_id:
            # Use source_id directly
            result = await client.list_occurrences(
                source_id=params.source_id,
                from_date=params.from_date,
                to_date=params.to_date,
                presence=params.presence,
                tags=params.tags,
                exclude_tags=params.exclude_tags,
                per_page=params.per_page,
                cursor=params.cursor,
                ordering=params.ordering,
                get_all=params.get_all,
                status=params.status,
                severity=params.severity,
                validity=params.validity,
            )
        else:
            # Use source_name (legacy path)
            source_name = params.repository_name.strip()
            result = await client.list_occurrences(
                source_name=source_name,
                source_type="github",  # Default to github, could be made configurable
                from_date=params.from_date,
                to_date=params.to_date,
                presence=params.presence,
                tags=params.tags,
                exclude_tags=params.exclude_tags,
                per_page=params.per_page,
                cursor=params.cursor,
                ordering=params.ordering,
                get_all=params.get_all,
                status=params.status,
                severity=params.severity,
                validity=params.validity,
            )

        # Handle the response format
        if isinstance(result, dict):
            occurrences = result.get("occurrences", [])
            return {
                "repository": params.repository_name,
                "occurrences_count": len(occurrences),
                "occurrences": occurrences,
                "cursor": result.get("cursor"),
                "has_more": result.get("has_more", False),
            }
        elif isinstance(result, list):
            # If get_all=True, we get a list directly
            return {
                "repository": params.repository_name,
                "occurrences_count": len(result),
                "occurrences": result,
            }
        else:
            return {
                "repository": params.repository_name,
                "occurrences_count": 0,
                "occurrences": [],
            }

    except Exception as e:
        logger.error(f"Error listing repository occurrences: {str(e)}")
        return {"error": f"Failed to list repository occurrences: {str(e)}"}
