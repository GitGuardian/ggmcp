import logging
from typing import Any, Literal

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.client import DEFAULT_PAGINATION_MAX_BYTES
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class ListSourcesParams(BaseModel):
    """Parameters for listing sources."""

    search: str | None = Field(
        default=None,
        description="Search string to filter sources by name",
    )
    last_scan_status: (
        Literal[
            "pending",
            "running",
            "canceled",
            "failed",
            "too_large",
            "timeout",
            "pending_timeout",
            "finished",
        ]
        | None
    ) = Field(
        default=None,
        description="Filter sources based on the status of their latest historical scan",
    )
    health: Literal["safe", "unknown", "at_risk"] | None = Field(
        default=None,
        description="Filter sources based on their health status",
    )
    type: (
        Literal[
            "bitbucket",
            "bitbucket_cloud",
            "github",
            "gitlab",
            "azure_devops",
            "slack",
            "jira_cloud",
            "confluence_cloud",
            "microsoft_teams",
            "confluence_data_center",
            "jira_data_center",
            "aws_ecr",
            "azure_cr",
            "google_artifact",
            "jfrog_artifact",
            "docker_hub",
            "servicenow",
            "sharepoint_online",
            "sharepoint_online_drive",
            "sharepoint_online_pages",
            "microsoft_onedrive",
            "custom_source",
        ]
        | None
    ) = Field(
        default=None,
        description="Filter by source type (e.g., 'github', 'gitlab', 'bitbucket')",
    )
    ordering: Literal["last_scan_date", "-last_scan_date"] | None = Field(
        default=None,
        description="Sort by last scan date. Prefix with '-' for descending order.",
    )
    visibility: Literal["public", "private", "internal"] | None = Field(
        default=None,
        description="Filter by visibility status",
    )
    external_id: str | None = Field(
        default=None,
        description="Filter by specific external id",
    )
    source_criticality: Literal["critical", "high", "medium", "low", "unknown"] | None = Field(
        default=None,
        description="Filter by source criticality level",
    )
    monitored: bool | None = Field(
        default=None,
        description="Filter by monitored status (true/false)",
    )
    per_page: int = Field(
        default=20,
        description="Number of results per page (default: 20, min: 1, max: 100)",
    )
    cursor: str | None = Field(
        default=None,
        description="Pagination cursor from a previous response",
    )
    get_all: bool = Field(
        default=False,
        description=f"If True, fetch all pages (capped at ~{DEFAULT_PAGINATION_MAX_BYTES / 1000}KB; check 'has_more' and use cursor to continue)",
    )


class ListSourcesResult(BaseModel):
    """Result from listing sources."""

    sources: list[dict[str, Any]] = Field(description="List of source objects")
    next_cursor: str | None = Field(
        default=None,
        description="Cursor for fetching the next page (null if no more results)",
    )
    has_more: bool = Field(
        default=False,
        description="True if more results exist (use next_cursor to fetch)",
    )


async def list_sources(params: ListSourcesParams) -> ListSourcesResult:
    """
    List sources known by GitGuardian.

    Returns information about the sources (repositories, integrations) that
    GitGuardian is monitoring for secrets.

    Args:
        params: ListSourcesParams model containing all filtering options

    Returns:
        ListSourcesResult: Pydantic model containing:
            - sources: List of source objects with id, url, type, health, etc.
            - next_cursor: Cursor for pagination
            - has_more: Whether more results exist

    Raises:
        ToolError: If the listing operation fails
    """
    client = await get_client()
    logger.debug("Listing sources")

    try:
        response = await client.list_sources(
            search=params.search,
            last_scan_status=params.last_scan_status,
            health=params.health,
            type=params.type,
            ordering=params.ordering,
            visibility=params.visibility,
            external_id=params.external_id,
            source_criticality=params.source_criticality,
            monitored=params.monitored,
            per_page=params.per_page,
            cursor=params.cursor,
            get_all=params.get_all,
        )

        sources_data = response["data"]
        next_cursor = response["cursor"]

        logger.debug(f"Found {len(sources_data)} sources")
        return ListSourcesResult(
            sources=sources_data,
            next_cursor=next_cursor,
            has_more=response.get("has_more", False),
        )
    except Exception as e:
        logger.exception(f"Error listing sources: {str(e)}")
        raise ToolError(str(e))
