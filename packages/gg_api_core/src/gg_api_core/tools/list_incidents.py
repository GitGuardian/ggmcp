import json
import logging
from typing import Annotated, Any

from pydantic import BaseModel, Field

from gg_api_core.client import DEFAULT_PAGINATION_MAX_BYTES, MAX_PAGINATION_PAGES
from gg_api_core.generated_filter_vocabulary import (
    IncidentSeverityFilter,
    IncidentSourceTypeFilter,
    IncidentStatusFilter,
    IncidentValidityFilter,
)
from gg_api_core.incident_filter_adapters import (
    IncidentIntegrationFilter,
)
from gg_api_core.incident_filters import (
    DEFAULT_EXCLUDED_TAGS,
    DEFAULT_SEVERITIES,
    DEFAULT_STATUSES,
    DEFAULT_VALIDITIES,
    IncidentFilterParams,
    build_api_params,
    build_filter_info,
)
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_EXCLUDED_TAGS",
    "DEFAULT_SEVERITIES",
    "DEFAULT_STATUSES",
    "DEFAULT_VALIDITIES",
]


def _build_suggestion(params: "ListIncidentsParams", incidents_count: int) -> str:
    """Build a suggestion message based on applied filters and results."""
    suggestions = []

    if params.mine:
        suggestions.append("Incidents are filtered to show only those assigned to current user")
    if params.assignee_id is not None:
        if params.assignee_id == 0:
            suggestions.append("Incidents are filtered to show only unassigned incidents")
        else:
            suggestions.append(f"Incidents are filtered by assignee ID: {params.assignee_id}")

    if params.status:
        suggestions.append(f"Filtered by status: {', '.join(params.status)}")

    if params.severity:
        suggestions.append(f"Filtered by severity: {', '.join(str(s) for s in params.severity)}")

    if params.validity:
        suggestions.append(f"Filtered by validity: {', '.join(params.validity)}")

    if params.source_criticality:
        suggestions.append(f"Filtered by source criticality: {', '.join(params.source_criticality)}")

    if params.opened_for_days:
        suggestions.append(f"Filtered to incidents open for at least {params.opened_for_days} days")

    if params.public_exposure:
        suggestions.append(f"Filtered by public exposure: {', '.join(params.public_exposure)}")

    if incidents_count == 0 and suggestions:
        suggestions.append(
            "No incidents matched the applied filters. Try adjusting filters such as status, severity, or assignee."
        )

    return "\n".join(suggestions) if suggestions else ""


class ListIncidentsParams(IncidentFilterParams):
    """Parameters for listing incidents using the MCP-optimized endpoint."""

    # Pagination
    page: int = Field(default=1, description="Page number (1-indexed)", ge=1)
    page_size: int = Field(
        default=20,
        description="Number of results per page (default: 20, max: 100)",
        ge=1,
        le=100,
    )
    get_all: bool = Field(
        default=False,
        description=f"If True, fetch all pages (capped at ~{DEFAULT_PAGINATION_MAX_BYTES / 1000}KB; check 'has_more' to see if results were truncated)",
    )
    ordering: str | None = Field(
        default="-date",
        description="Sort field with optional '-' prefix for descending. Options: score, -score, date, -date, severity, -severity, status, -status",
    )


class ListIncidentsResult(BaseModel):
    """Result from listing incidents."""

    incidents: list[dict[str, Any]] = Field(default_factory=list, description="List of incident objects")
    page: int = Field(description="Current page number (last page fetched when get_all=True)")
    page_size: int = Field(description="Number of results per page")
    has_next: bool = Field(default=False, description="True if there are more pages available")
    has_previous: bool = Field(default=False, description="True if there are previous pages")
    has_more: bool = Field(
        default=False,
        description="True if results were truncated due to size limit (only relevant when get_all=True)",
    )
    applied_filters: dict[str, Any] = Field(default_factory=dict, description="Filters that were applied to the query")
    suggestion: str = Field(default="", description="Suggestions for interpreting or modifying the results")


class ListIncidentsError(BaseModel):
    """Error result from listing incidents."""

    error: str = Field(description="Error message")


async def list_incidents(
    page: Annotated[int, Field(default=1, ge=1, description="Page number (1-indexed)")] = 1,
    page_size: Annotated[
        int, Field(default=20, ge=1, le=100, description="Number of results per page (default: 20, max: 100)")
    ] = 20,
    get_all: Annotated[
        bool,
        Field(
            default=False,
            description="If True, fetch all pages (capped at ~20.0KB; check 'has_more' to see if results were truncated)",
        ),
    ] = False,
    ordering: Annotated[
        str | None,
        Field(
            default="-date",
            description="Sort field with optional '-' prefix for descending. Options: score, -score, date, -date, severity, -severity, status, -status",
        ),
    ] = "-date",
    search: Annotated[
        str | None, Field(default=None, description="Search term to filter incidents by name or content")
    ] = None,
    status: Annotated[
        list[IncidentStatusFilter] | IncidentStatusFilter | None,
        Field(
            default=DEFAULT_STATUSES,
            description="Filter by status. Values: TRIGGERED, ASSIGNED, RESOLVED, IGNORED. Default excludes IGNORED.",
        ),
    ] = DEFAULT_STATUSES,
    mine: Annotated[
        bool,
        Field(
            default=False,
            description="If True, fetch only incidents assigned to the current user. Overrides assignee_id.",
        ),
    ] = False,
    assignee_id: Annotated[
        int | None,
        Field(
            default=None,
            description="Filter by assignee member ID. Use 0 for unassigned incidents. Cannot be used with 'mine'.",
        ),
    ] = None,
    severity: Annotated[
        list[IncidentSeverityFilter] | IncidentSeverityFilter | None,
        Field(
            default=DEFAULT_SEVERITIES,
            description="Filter by severity levels. Values: critical (10), high (20), medium (30), low (40), info (50), unknown (100). Default excludes LOW and INFO.",
        ),
    ] = DEFAULT_SEVERITIES,
    score_min: Annotated[
        int | None,
        Field(
            default=None,
            ge=0,
            le=100,
            description="Filter incidents with a score greater than or equal to this value (0-100). Higher scores indicate higher priority incidents.",
        ),
    ] = None,
    score_max: Annotated[
        int | None,
        Field(
            default=None,
            ge=0,
            le=100,
            description="Filter incidents with a score less than or equal to this value (0-100).",
        ),
    ] = None,
    validity: Annotated[
        list[IncidentValidityFilter] | IncidentValidityFilter | None,
        Field(
            default=DEFAULT_VALIDITIES,
            description="Filter by validity status. Values: valid, invalid, failed_to_check, no_checker, unknown. Default excludes INVALID.",
        ),
    ] = DEFAULT_VALIDITIES,
    detector_group_name: Annotated[
        list[str] | str | None,
        Field(default=None, description="Filter by detector group name (e.g., 'AWS Keys', 'GitHub Tokens')"),
    ] = None,
    detector_type: Annotated[
        list[str] | str | None, Field(default=None, description="Filter by detector type/nature")
    ] = None,
    detector_category: Annotated[
        list[str] | str | None, Field(default=None, description="Filter by detector category")
    ] = None,
    issue_name: Annotated[
        list[str] | str | None, Field(default=None, description="Filter by issue/incident name")
    ] = None,
    secret_category: Annotated[
        list[str] | str | None, Field(default=None, description="Filter by secret category")
    ] = None,
    secret_family: Annotated[list[str] | str | None, Field(default=None, description="Filter by secret family")] = None,
    secret_provider: Annotated[
        list[str] | str | None,
        Field(default=None, description="Filter by secret provider (e.g., 'aws', 'github', 'google')"),
    ] = None,
    source_ids: Annotated[
        list[int] | int | None,
        Field(
            default=None,
            description="Filter by source ID(s). Can be obtained using list_source or find_current_source_id tools.",
        ),
    ] = None,
    source_type: Annotated[
        list[IncidentSourceTypeFilter] | IncidentSourceTypeFilter | None,
        Field(
            default=None,
            description="Filter by public API source type (for example: github, gitlab, bitbucket, azure_devops).",
        ),
    ] = None,
    source_criticality: Annotated[
        list[str] | str | None,
        Field(default=None, description="Filter by source criticality. Values: critical, high, medium, low, unknown"),
    ] = None,
    occurrence_count_min: Annotated[
        int | None, Field(default=None, description="Filter incidents with at least this many occurrences")
    ] = None,
    presence: Annotated[
        list[str] | str | None,
        Field(default=None, description="Filter by occurrence presence status. Values: present, removed"),
    ] = None,
    opened_for_days: Annotated[
        int | None, Field(default=None, description="Filter incidents that have been open for at least this many days")
    ] = None,
    tags: Annotated[
        list[str] | str | None,
        Field(default=None, description="Filter by tag names (e.g., 'REGRESSION', 'PUBLICLY_EXPOSED', 'TEST_FILE')"),
    ] = None,
    exclude_tags: Annotated[
        list[str] | str | None,
        Field(
            default=[
                "TEST_FILE",
                "FALSE_POSITIVE",
                "CHECK_RUN_SKIP_FALSE_POSITIVE",
                "CHECK_RUN_SKIP_LOW_RISK",
                "CHECK_RUN_SKIP_TEST_CRED",
            ],
            description="Exclude incidents with these tag names. Default excludes TEST_FILE, FALSE_POSITIVE, and CHECK_RUN_SKIP_* tags.",
        ),
    ] = [
        "TEST_FILE",
        "FALSE_POSITIVE",
        "CHECK_RUN_SKIP_FALSE_POSITIVE",
        "CHECK_RUN_SKIP_LOW_RISK",
        "CHECK_RUN_SKIP_TEST_CRED",
    ],
    public_exposure: Annotated[
        list[str] | str | None,
        Field(
            default=None,
            description="Filter by public exposure. Values: source_publicly_visible, public_incident_linked, leaked_outside_perimeter",
        ),
    ] = None,
    integration: Annotated[
        list[IncidentIntegrationFilter] | IncidentIntegrationFilter | None,
        Field(
            default=None,
            description="Filter by audited integration name. Values: github, github_enterprise_server, gitlab",
        ),
    ] = None,
    issue_tracker: Annotated[
        list[str] | str | None,
        Field(
            default=None,
            description="Filter by issue tracker type. Values: jira_cloud_notifier, jira_data_center_notifier, servicenow",
        ),
    ] = None,
    has_related_issues: Annotated[
        bool | None,
        Field(default=None, description="Filter to incidents with (True) or without (False) related issues"),
    ] = None,
    location: Annotated[
        bool | None,
        Field(default=None, description="Filter to incidents with (True) or without (False) location information"),
    ] = None,
    feedback: Annotated[
        bool | None, Field(default=None, description="Filter to incidents with (True) or without (False) feedback")
    ] = None,
    publicly_shared: Annotated[
        bool | None,
        Field(default=None, description="Filter to incidents that are (True) or aren't (False) publicly shared"),
    ] = None,
    secret_manager_type: Annotated[
        list[str] | str | None,
        Field(
            default=None,
            description="Filter by vault type. Values: hashicorpvault, awssecretsmanager, azurekeyvault, gcpsecretmanager, cyberarksaas, cyberarkselfhosted, akeyless, delineasecretserver",
        ),
    ] = None,
    secret_manager_instance: Annotated[
        list[int] | int | None, Field(default=None, description="Filter by vault instance ID(s)")
    ] = None,
    nhi_env: Annotated[
        list[str] | str | None, Field(default=None, description="Filter by NHI environment name(s)")
    ] = None,
    nhi_policy: Annotated[
        list[str] | str | None, Field(default=None, description="Filter by NHI policy breach name(s)")
    ] = None,
    teams: Annotated[list[int] | int | None, Field(default=None, description="Filter by team ID(s)")] = None,
    similar_to: Annotated[
        int | None, Field(default=None, description="Filter incidents similar to the given incident ID")
    ] = None,
    date_before: Annotated[
        str | None, Field(default=None, description="Filter incidents detected before this date (YYYY-MM-DD format)")
    ] = None,
    date_after: Annotated[
        str | None, Field(default=None, description="Filter incidents detected after this date (YYYY-MM-DD format)")
    ] = None,
    secret_scope: Annotated[
        list[str] | str | None, Field(default=None, description="Filter by secret scope name(s)")
    ] = None,
    analyzer_status: Annotated[
        list[str] | str | None,
        Field(
            default=None,
            description="Filter by analyzer status. Values: no_checker, not_checked, checked, invalid, failed_to_check",
        ),
    ] = None,
    custom_tags: Annotated[
        list[int] | int | None, Field(default=None, description="Filter by custom tag ID(s)")
    ] = None,
) -> ListIncidentsResult | ListIncidentsError:
    """
    List secret incidents with enhanced filtering using the MCP-optimized endpoint.

    This endpoint provides filtering options including detector type, secret category,
    source criticality, public exposure, and more. It uses page-based pagination.

    Features:
    - Page-based pagination
    - Status values: TRIGGERED, ASSIGNED, RESOLVED, IGNORED
    - Rich filtering options for detector types, secret categories, and public exposure
    - Returns detailed incident data including custom tags, vault metadata, and similar issue counts

    Args:
        params: ListIncidentsParams model containing all filtering options.

    Returns:
        ListIncidentsResult: Pydantic model containing:
            - incidents: List of incident objects with detailed information
            - page: Current page number
            - page_size: Results per page
            - has_next/has_previous: Pagination indicators
            - applied_filters: Dictionary of filters that were applied
            - suggestion: Suggestions for interpreting or modifying results

        ListIncidentsError: Pydantic model with error message if the operation fails

    """
    params = ListIncidentsParams(
        page=page,
        page_size=page_size,
        get_all=get_all,
        ordering=ordering,
        search=search,
        status=status,
        mine=mine,
        assignee_id=assignee_id,
        severity=severity,
        score_min=score_min,
        score_max=score_max,
        validity=validity,
        detector_group_name=detector_group_name,
        detector_type=detector_type,
        detector_category=detector_category,
        issue_name=issue_name,
        secret_category=secret_category,
        secret_family=secret_family,
        secret_provider=secret_provider,
        source_ids=source_ids,
        source_type=source_type,
        source_criticality=source_criticality,
        occurrence_count_min=occurrence_count_min,
        presence=presence,
        opened_for_days=opened_for_days,
        tags=tags,
        exclude_tags=exclude_tags,
        public_exposure=public_exposure,
        integration=integration,
        issue_tracker=issue_tracker,
        has_related_issues=has_related_issues,
        location=location,
        feedback=feedback,
        publicly_shared=publicly_shared,
        secret_manager_type=secret_manager_type,
        secret_manager_instance=secret_manager_instance,
        nhi_env=nhi_env,
        nhi_policy=nhi_policy,
        teams=teams,
        similar_to=similar_to,
        date_before=date_before,
        date_after=date_after,
        secret_scope=secret_scope,
        analyzer_status=analyzer_status,
        custom_tags=custom_tags,
    )

    client = await get_client()

    try:
        api_params: dict[str, Any] = {}

        # Handle 'mine' parameter - get current user's member ID
        if params.mine:
            member = await client.get_current_member()
            current_user_id = member["id"]
            if params.assignee_id is not None and params.assignee_id != current_user_id:
                return ListIncidentsError(
                    error=f"Conflict: 'mine=True' implies assignee_id={current_user_id}, "
                    f"but assignee_id={params.assignee_id} was explicitly provided. "
                    "Please use either 'mine=True' or an explicit 'assignee_id', not both."
                )
            api_params["assignee_id"] = current_user_id
        elif params.assignee_id is not None:
            api_params["assignee_id"] = params.assignee_id

        api_params.update(build_api_params(params))

        if params.get_all:
            # Fetch all pages with byte limit protection and hard page cap.
            all_incidents: list[dict[str, Any]] = []
            current_page = 1
            total_bytes = 0
            has_more = False

            while True:
                if current_page > MAX_PAGINATION_PAGES:
                    logger.warning(f"get_all pagination stopped: reached max page limit ({MAX_PAGINATION_PAGES})")
                    has_more = True
                    break

                response = await client.list_incidents_for_mcp(
                    page=current_page,
                    page_size=params.page_size,
                    ordering=params.ordering,
                    **api_params,
                )

                page_incidents = response.get("results", [])
                has_next_page = response.get("next") is not None

                # Empty page means no more matching results
                if not page_incidents:
                    break

                # Check byte limit before adding results
                page_bytes = len(json.dumps(page_incidents))
                if total_bytes + page_bytes > DEFAULT_PAGINATION_MAX_BYTES and all_incidents:
                    # Would exceed limit, stop here
                    has_more = True
                    break

                all_incidents.extend(page_incidents)
                total_bytes += page_bytes

                if not has_next_page:
                    break

                current_page += 1

            return ListIncidentsResult(
                incidents=all_incidents,
                page=current_page,
                page_size=params.page_size,
                has_next=has_more,
                has_previous=False,
                has_more=has_more,
                applied_filters=build_filter_info(params),
                suggestion=_build_suggestion(params, len(all_incidents)),
            )
        else:
            # Single page request
            response = await client.list_incidents_for_mcp(
                page=params.page,
                page_size=params.page_size,
                ordering=params.ordering,
                **api_params,
            )

            # Parse the response
            incidents_data = response.get("results", [])
            has_next = response.get("next") is not None
            has_previous = response.get("previous") is not None

            return ListIncidentsResult(
                incidents=incidents_data,
                page=params.page,
                page_size=params.page_size,
                has_next=has_next,
                has_previous=has_previous,
                has_more=False,
                applied_filters=build_filter_info(params),
                suggestion=_build_suggestion(params, len(incidents_data)),
            )

    except Exception as e:
        logger.exception(f"Error listing incidents: {str(e)}")
        return ListIncidentsError(error=f"Failed to list incidents: {str(e)}")
