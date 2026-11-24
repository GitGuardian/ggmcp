import logging
from typing import Any, Literal

from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from gg_api_core.tools.ids import NumericId
from gg_api_core.tools.pagination import (
    CURSOR_DESCRIPTION,
    GET_ALL_DESCRIPTION,
    PageOfResults,
    PerPage,
    page_fields,
)
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
    team_id: NumericId | None = Field(
        default=None,
        description="Filter sources by team id. Only sources belonging to the given team's perimeter are returned.",
    )
    per_page: PerPage = 20
    cursor: str | None = Field(default=None, description=CURSOR_DESCRIPTION)
    get_all: bool = Field(default=False, description=GET_ALL_DESCRIPTION)


class ListSourcesResult(PageOfResults):
    """Result from listing sources."""

    sources: list[dict[str, Any]] = Field(description="List of source objects")


async def list_sources(params: ListSourcesParams = ListSourcesParams()) -> ListSourcesResult:
    """List sources known by GitGuardian.

    Args:
        params: ListSourcesParams model containing all filtering options
    """
    client = await get_client()

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
            team_id=params.team_id,
            per_page=params.per_page,
            cursor=params.cursor,
            get_all=params.get_all,
        )

        return ListSourcesResult(sources=response["data"], **page_fields(params, response))
    except Exception as e:
        raise ToolError(str(e))
