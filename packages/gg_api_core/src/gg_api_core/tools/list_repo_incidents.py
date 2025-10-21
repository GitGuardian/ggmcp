from typing import Any
import logging

from pydantic import BaseModel, Field

from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)

DEFAULT_EXCLUDED_TAGS = ["TEST_FILE", "FALSE_POSITIVE", "CHECK_RUN_SKIP_FALSE_POSITIVE", "CHECK_RUN_SKIP_LOW_RISK", "CHECK_RUN_SKIP_TEST_CRED"]
DEFAULT_SEVERITIES = ["critical", "high", "medium"]
DEFAULT_STATUSES = ["TRIGGERED", "ASSIGNED", "RESOLVED"]  # We exclude "IGNORED" ones
DEFAULT_VALIDITIES = ["valid", "failed_to_check", "no_checker", "unknown"]  # We exclude "invalid" ones


class ListRepoIncidentsParams(BaseModel):
    """Parameters for listing repository incidents."""
    repository_name: str | None = Field(
        default=None,
        description="The full repository name. For example, for https://github.com/GitGuardian/gg-mcp.git the full name is GitGuardian/gg-mcp. Pass the current repository name if not provided. Not required if source_id is provided."
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
        description="Exclude incidents with these tag names."
    )
    status: list[str] | None = Field(default=DEFAULT_STATUSES, description="Filter by status (list of status names)")
    ordering: str | None = Field(default=None, description="Sort field (e.g., 'date', '-date' for descending)")
    per_page: int = Field(default=20, description="Number of results per page (default: 20, min: 1, max: 100)")
    cursor: str | None = Field(default=None, description="Pagination cursor for fetching next page of results")
    get_all: bool = Field(default=False, description="If True, fetch all results using cursor-based pagination")
    mine: bool = Field(
        default=True,
        description="If True, fetch only incidents assigned to the current user. Set to False to get all incidents.",
    )
    severity: list[str] | None = Field(default=DEFAULT_SEVERITIES, description="Filter by severity (list of severity names)")
    validity: list[str] | None = Field(default=DEFAULT_VALIDITIES, description="Filter by validity (list of validity names)")


async def list_repo_incidents(params: ListRepoIncidentsParams) -> dict[str, Any]:
    """
    List secret incidents or occurrences related to a specific repository.

    By default, this tool only shows incidents assigned to the current user. Pass mine=False to get all incidents related to this repo.
    By default, incidents tagged with TEST_FILE or FALSE_POSITIVE are excluded. Pass exclude_tags=[] to disable this filtering.

    Args:
        params: ListRepoIncidentsParams model containing all filtering options

    Returns:
        List of incidents and occurrences matching the specified criteria
    """
    client = get_client()

    # Validate that at least one of repository_name or source_id is provided
    if not params.repository_name and not params.source_id:
        return {"error": "Either repository_name or source_id must be provided"}

    logger.debug(f"Listing incidents with repository_name={params.repository_name}, source_id={params.source_id}")

    # Use the new direct approach using the GitGuardian Sources API
    try:
        # If source_id is provided, use it directly; otherwise use repository_name lookup
        if params.source_id:
            # Prepare parameters for the API call
            api_params = {}
            if params.from_date:
                api_params["from_date"] = params.from_date
            if params.to_date:
                api_params["to_date"] = params.to_date
            if params.presence:
                api_params["presence"] = params.presence
            if params.tags:
                api_params["tags"] = ",".join(params.tags) if isinstance(params.tags, list) else params.tags
            if params.exclude_tags:
                api_params["exclude_tags"] = ",".join(params.exclude_tags) if isinstance(params.exclude_tags, list) else params.exclude_tags
            if params.per_page:
                api_params["per_page"] = params.per_page
            if params.cursor:
                api_params["cursor"] = params.cursor
            if params.ordering:
                api_params["ordering"] = params.ordering
            if params.mine:
                api_params["assigned_to_me"] = "true"
            if params.severity:
                api_params["severity"] = ",".join(params.severity) if isinstance(params.severity, list) else params.severity
            if params.status:
                api_params["status"] = ",".join(params.status) if isinstance(params.status, list) else params.status
            if params.validity:
                api_params["validity"] = ",".join(params.validity) if isinstance(params.validity, list) else params.validity

            # Get incidents directly using source_id
            if params.get_all:
                incidents_result = await client.paginate_all(f"/sources/{params.source_id}/incidents/secrets", api_params)
                if isinstance(incidents_result, list):
                    return {
                        "source_id": params.source_id,
                        "incidents": incidents_result,
                        "total_count": len(incidents_result),
                    }
                elif isinstance(incidents_result, dict):
                    return {
                        "source_id": params.source_id,
                        "incidents": incidents_result.get("data", []),
                        "total_count": incidents_result.get("total_count", len(incidents_result.get("data", []))),
                    }
                else:
                    # Fallback for unexpected types
                    return {
                        "source_id": params.source_id,
                        "incidents": [],
                        "total_count": 0,
                        "error": f"Unexpected response type: {type(incidents_result).__name__}",
                    }
            else:
                incidents_result = await client.list_source_incidents(params.source_id, **api_params)
                if isinstance(incidents_result, dict):
                    return {
                        "source_id": params.source_id,
                        "incidents": incidents_result.get("data", []),
                        "next_cursor": incidents_result.get("next_cursor"),
                        "total_count": incidents_result.get("total_count", 0),
                    }
                elif isinstance(incidents_result, list):
                    # Handle case where API returns a list directly
                    return {
                        "source_id": params.source_id,
                        "incidents": incidents_result,
                        "total_count": len(incidents_result),
                    }
                else:
                    # Fallback for unexpected types
                    return {
                        "source_id": params.source_id,
                        "incidents": [],
                        "total_count": 0,
                        "error": f"Unexpected response type: {type(incidents_result).__name__}",
                    }
        else:
            # Use repository_name lookup (legacy path)
            result = await client.list_repo_incidents_directly(
                repository_name=params.repository_name,
                from_date=params.from_date,
                to_date=params.to_date,
                presence=params.presence,
                tags=params.tags,
                exclude_tags=params.exclude_tags,
                per_page=params.per_page,
                cursor=params.cursor,
                ordering=params.ordering,
                get_all=params.get_all,
                mine=params.mine,
            )
            return result

    except Exception as e:
        logger.error(f"Error listing repository incidents: {str(e)}")
        return {"error": f"Failed to list repository incidents: {str(e)}"}
