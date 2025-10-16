from typing import Any
import logging

from pydantic import Field

from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


async def list_repo_incidents(
    repository_name: str | None = Field(
        default=None,
        description="The full repository name. For example, for https://github.com/GitGuardian/gg-mcp.git the full name is GitGuardian/gg-mcp. Pass the current repository name if not provided. Not required if source_id is provided."
    ),
    source_id: str | None = Field(
        default=None,
        description="The GitGuardian source ID to filter by. Can be obtained using find_current_source_id. If provided, repository_name is not required."
    ),
    from_date: str | None = Field(
        default=None, description="Filter occurrences created after this date (ISO format: YYYY-MM-DD)"
    ),
    to_date: str | None = Field(
        default=None, description="Filter occurrences created before this date (ISO format: YYYY-MM-DD)"
    ),
    presence: str | None = Field(default=None, description="Filter by presence status"),
    tags: list[str] | None = Field(default=None, description="Filter by tags (list of tag names)"),
    exclude_tags: list[str] | None = Field(
        default=["TEST_FILE", "FALSE_POSITIVE"],
        description="Exclude incidents with these tag names (default: TEST_FILE, FALSE_POSITIVE). Pass empty list to disable filtering."
    ),
    ordering: str | None = Field(default=None, description="Sort field (e.g., 'date', '-date' for descending)"),
    per_page: int = Field(default=20, description="Number of results per page (default: 20, min: 1, max: 100)"),
    cursor: str | None = Field(default=None, description="Pagination cursor for fetching next page of results"),
    get_all: bool = Field(default=False, description="If True, fetch all results using cursor-based pagination"),
    mine: bool = Field(
        default=True,
        description="If True, fetch only incidents assigned to the current user. Set to False to get all incidents.",
    ),
) -> dict[str, Any]:
    """
    List secret incidents or occurrences related to a specific repository.

    By default, this tool only shows incidents assigned to the current user. Pass mine=False to get all incidents related to this repo.
    By default, incidents tagged with TEST_FILE or FALSE_POSITIVE are excluded. Pass exclude_tags=[] to disable this filtering.

    Args:
        repository_name: The full repository name (e.g., 'GitGuardian/gg-mcp')
        source_id: The GitGuardian source ID (alternative to repository_name)
        from_date: Filter occurrences created after this date (ISO format: YYYY-MM-DD)
        to_date: Filter occurrences created before this date (ISO format: YYYY-MM-DD)
        presence: Filter by presence status
        tags: Filter by tags (list of tag names)
        exclude_tags: Exclude incidents with these tag names (default: TEST_FILE, FALSE_POSITIVE)
        ordering: Sort field (e.g., 'date', '-date' for descending)
        per_page: Number of results per page (default: 20, min: 1, max: 100)
        cursor: Pagination cursor for fetching next page of results
        get_all: If True, fetch all results using cursor-based pagination
        mine: If True, fetch only incidents assigned to the current user. Set to False to get all incidents.

    Returns:
        List of incidents and occurrences matching the specified criteria
    """
    client = get_client()

    # Validate that at least one of repository_name or source_id is provided
    if not repository_name and not source_id:
        return {"error": "Either repository_name or source_id must be provided"}

    logger.debug(f"Listing incidents with repository_name={repository_name}, source_id={source_id}")

    # Use the new direct approach using the GitGuardian Sources API
    try:
        # If source_id is provided, use it directly; otherwise use repository_name lookup
        if source_id:
            # Prepare parameters for the API call
            params = {}
            if from_date:
                params["from_date"] = from_date
            if to_date:
                params["to_date"] = to_date
            if presence:
                params["presence"] = presence
            if tags:
                params["tags"] = ",".join(tags) if isinstance(tags, list) else tags
            if exclude_tags:
                params["exclude_tags"] = ",".join(exclude_tags) if isinstance(exclude_tags, list) else exclude_tags
            if per_page:
                params["per_page"] = per_page
            if cursor:
                params["cursor"] = cursor
            if ordering:
                params["ordering"] = ordering
            if mine:
                params["assigned_to_me"] = "true"

            # Get incidents directly using source_id
            if get_all:
                incidents_result = await client.paginate_all(f"/sources/{source_id}/incidents/secrets", params)
                if isinstance(incidents_result, list):
                    return {
                        "source_id": source_id,
                        "incidents": incidents_result,
                        "total_count": len(incidents_result),
                    }
                elif isinstance(incidents_result, dict):
                    return {
                        "source_id": source_id,
                        "incidents": incidents_result.get("data", []),
                        "total_count": incidents_result.get("total_count", len(incidents_result.get("data", []))),
                    }
                else:
                    # Fallback for unexpected types
                    return {
                        "source_id": source_id,
                        "incidents": [],
                        "total_count": 0,
                        "error": f"Unexpected response type: {type(incidents_result).__name__}",
                    }
            else:
                incidents_result = await client.list_source_incidents(source_id, **params)
                if isinstance(incidents_result, dict):
                    return {
                        "source_id": source_id,
                        "incidents": incidents_result.get("data", []),
                        "next_cursor": incidents_result.get("next_cursor"),
                        "total_count": incidents_result.get("total_count", 0),
                    }
                elif isinstance(incidents_result, list):
                    # Handle case where API returns a list directly
                    return {
                        "source_id": source_id,
                        "incidents": incidents_result,
                        "total_count": len(incidents_result),
                    }
                else:
                    # Fallback for unexpected types
                    return {
                        "source_id": source_id,
                        "incidents": [],
                        "total_count": 0,
                        "error": f"Unexpected response type: {type(incidents_result).__name__}",
                    }
        else:
            # Use repository_name lookup (legacy path)
            result = await client.list_repo_incidents_directly(
                repository_name=repository_name,
                from_date=from_date,
                to_date=to_date,
                presence=presence,
                tags=tags,
                exclude_tags=exclude_tags,
                per_page=per_page,
                cursor=cursor,
                ordering=ordering,
                get_all=get_all,
                mine=mine,
            )
            return result

    except Exception as e:
        logger.error(f"Error listing repository incidents: {str(e)}")
        return {"error": f"Failed to list repository incidents: {str(e)}"}
