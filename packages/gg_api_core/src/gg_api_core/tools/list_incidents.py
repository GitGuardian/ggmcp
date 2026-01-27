import json
import logging
from typing import Any

from pydantic import BaseModel, Field

from gg_api_core.client import DEFAULT_PAGINATION_MAX_BYTES
from gg_api_core.tools.find_current_source_id import find_current_source_id
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class IncidentStatus:
    TRIGGERED = "TRIGGERED"  # Unassigned active incidents
    ASSIGNED = "ASSIGNED"  # Assigned active incidents
    RESOLVED = "RESOLVED"
    IGNORED = "IGNORED"


# Severity numeric values (IntegerChoices in Django)
class SeverityValues:
    CRITICAL = 10
    HIGH = 20
    MEDIUM = 30
    LOW = 40
    INFO = 50
    UNKNOWN = 100


SEVERITY_NAME_TO_VALUE = {
    "critical": SeverityValues.CRITICAL,
    "high": SeverityValues.HIGH,
    "medium": SeverityValues.MEDIUM,
    "low": SeverityValues.LOW,
    "info": SeverityValues.INFO,
    "unknown": SeverityValues.UNKNOWN,
}


DEFAULT_STATUSES = [IncidentStatus.TRIGGERED, IncidentStatus.ASSIGNED]  # Active incidents


def _build_filter_info(params: "ListIncidentsParams") -> dict[str, Any]:
    """Build a dictionary describing the filters applied to the query."""
    filters: dict[str, Any] = {}

    if params.search:
        filters["search"] = params.search
    if params.status:
        filters["status"] = params.status
    if params.severity:
        filters["severity"] = params.severity
    if params.score_min is not None:
        filters["score_min"] = params.score_min
    if params.score_max is not None:
        filters["score_max"] = params.score_max
    if params.validity:
        filters["validity"] = params.validity
    if params.assignee_id is not None:
        filters["assignee_id"] = params.assignee_id
    if params.detector_group_name:
        filters["detector_group_name"] = params.detector_group_name
    if params.detector_type:
        filters["detector_type"] = params.detector_type
    if params.detector_category:
        filters["detector_category"] = params.detector_category
    if params.issue_name:
        filters["issue_name"] = params.issue_name
    if params.secret_category:
        filters["secret_category"] = params.secret_category
    if params.secret_family:
        filters["secret_family"] = params.secret_family
    if params.secret_provider:
        filters["secret_provider"] = params.secret_provider
    if params.repository_name:
        filters["repository_name"] = params.repository_name
    if params.source_ids:
        filters["source_ids"] = params.source_ids
    if params.source_type:
        filters["source_type"] = params.source_type
    if params.source_criticality:
        filters["source_criticality"] = params.source_criticality
    if params.presence:
        filters["presence"] = params.presence
    if params.tags:
        filters["tags"] = params.tags
    if params.public_exposure:
        filters["public_exposure"] = params.public_exposure
    if params.integration:
        filters["integration"] = params.integration
    if params.issue_tracker:
        filters["issue_tracker"] = params.issue_tracker
    if params.opened_for_days:
        filters["opened_for_days"] = params.opened_for_days
    if params.occurrence_count_min:
        filters["occurrence_count_min"] = params.occurrence_count_min
    if params.has_related_issues is not None:
        filters["has_related_issues"] = params.has_related_issues
    if params.location is not None:
        filters["location"] = params.location
    if params.feedback is not None:
        filters["feedback"] = params.feedback
    if params.publicly_shared is not None:
        filters["publicly_shared"] = params.publicly_shared
    if params.secret_manager_type:
        filters["secret_manager_type"] = params.secret_manager_type
    if params.secret_manager_instance:
        filters["secret_manager_instance"] = params.secret_manager_instance
    if params.nhi_env:
        filters["nhi_env"] = params.nhi_env
    if params.nhi_policy:
        filters["nhi_policy"] = params.nhi_policy
    if params.teams:
        filters["teams"] = params.teams
    if params.similar_to is not None:
        filters["similar_to"] = params.similar_to
    if params.date_before:
        filters["date_before"] = params.date_before
    if params.date_after:
        filters["date_after"] = params.date_after
    if params.secret_scope:
        filters["secret_scope"] = params.secret_scope
    if params.analyzer_status:
        filters["analyzer_status"] = params.analyzer_status
    if params.custom_tags:
        filters["custom_tags"] = params.custom_tags

    return filters


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


class ListIncidentsParams(BaseModel):
    """Parameters for listing incidents using the MCP-optimized endpoint."""

    # Pagination
    page: int = Field(default=1, description="Page number (1-indexed)", ge=1)
    page_size: int = Field(default=20, description="Number of results per page (default: 20, max: 100)", ge=1, le=100)
    get_all: bool = Field(
        default=False,
        description=f"If True, fetch all pages (capped at ~{DEFAULT_PAGINATION_MAX_BYTES / 1000}KB; check 'has_more' to see if results were truncated)",
    )
    ordering: str | None = Field(
        default="-date",
        description="Sort field with optional '-' prefix for descending. Options: score, -score, date, -date, severity, -severity, status, -status",
    )

    # Search
    search: str | None = Field(
        default=None,
        description="Search term to filter incidents by name or content",
    )

    # Status and assignment filters
    status: list[str] | None = Field(
        default=None,
        description="Filter by status. Values: TRIGGERED (unassigned active), ASSIGNED (assigned active), RESOLVED, IGNORED. Use both TRIGGERED and ASSIGNED to get all active incidents.",
    )
    mine: bool = Field(
        default=False,
        description="If True, fetch only incidents assigned to the current user. Overrides assignee_id.",
    )
    assignee_id: int | None = Field(
        default=None,
        description="Filter by assignee member ID. Use 0 for unassigned incidents. Cannot be used with 'mine'.",
    )

    # Severity, score, and validity filters
    severity: list[str | int] | None = Field(
        default=None,
        description="Filter by severity levels. Values: critical (10), high (20), medium (30), low (40), info (50), unknown (100). Can use names or numeric values.",
    )
    score_min: int | None = Field(
        default=None,
        description="Filter incidents with a score greater than or equal to this value (0-100). Higher scores indicate higher priority incidents.",
        ge=0,
        le=100,
    )
    score_max: int | None = Field(
        default=None,
        description="Filter incidents with a score less than or equal to this value (0-100).",
        ge=0,
        le=100,
    )
    validity: list[str] | None = Field(
        default=None,
        description="Filter by validity status. Values: valid, invalid, failed_to_check, no_checker, not_checked",
    )

    # Secret type filters
    detector_group_name: list[str] | None = Field(
        default=None,
        description="Filter by detector group name (e.g., 'AWS Keys', 'GitHub Tokens')",
    )
    detector_type: list[str] | None = Field(
        default=None,
        description="Filter by detector type/nature",
    )
    detector_category: list[str] | None = Field(
        default=None,
        description="Filter by detector category",
    )
    issue_name: list[str] | None = Field(
        default=None,
        description="Filter by issue/incident name",
    )
    secret_category: list[str] | None = Field(
        default=None,
        description="Filter by secret category",
    )
    secret_family: list[str] | None = Field(
        default=None,
        description="Filter by secret family",
    )
    secret_provider: list[str] | None = Field(
        default=None,
        description="Filter by secret provider (e.g., 'aws', 'github', 'google')",
    )

    # Source filters
    repository_name: str | None = Field(
        default=None,
        description="The full repository name. For example, for https://github.com/GitGuardian/ggmcp.git the full name is GitGuardian/ggmcp. Will be resolved to a source ID. Not required if source is provided.",
    )
    source_ids: list[int] | None = Field(
        default=None,
        description="Filter by source ID(s). If repository_name is provided, it will be resolved and added to this list.",
    )
    source_type: list[str] | None = Field(
        default=None,
        description="Filter by source type (e.g., 'github', 'gitlab', 'bitbucket')",
    )
    source_criticality: list[str] | None = Field(
        default=None,
        description="Filter by source criticality. Values: critical, high, medium, low, unknown",
    )

    # Occurrence and presence filters
    occurrence_count_min: int | None = Field(
        default=None,
        description="Filter incidents with at least this many occurrences",
    )
    presence: list[str] | None = Field(
        default=None,
        description="Filter by occurrence presence status. Values: present, removed",
    )

    # Date filters
    opened_for_days: int | None = Field(
        default=None,
        description="Filter incidents that have been open for at least this many days",
    )

    # Tags and exposure filters
    tags: list[str] | None = Field(
        default=None,
        description="Filter by tag names (e.g., 'REGRESSION', 'PUBLICLY_EXPOSED', 'TEST_FILE')",
    )
    exclude_tags: list[str] | None = Field(
        default=None,
        description="Exclude incidents with these tag names",
    )
    public_exposure: list[str] | None = Field(
        default=None,
        description="Filter by public exposure. Values: source_publicly_visible, public_incident_linked, leaked_outside_perimeter",
    )

    # Integration filters
    integration: list[str] | None = Field(
        default=None,
        description="Filter by integration type (e.g., 'github', 'gitlab', 'slack')",
    )
    issue_tracker: list[str] | None = Field(
        default=None,
        description="Filter by issue tracker type. Values: jira_cloud_notifier, jira_data_center_notifier, servicenow",
    )

    # Boolean filters
    has_related_issues: bool | None = Field(
        default=None,
        description="Filter to incidents with (True) or without (False) related issues",
    )
    location: bool | None = Field(
        default=None,
        description="Filter to incidents with (True) or without (False) location information",
    )
    feedback: bool | None = Field(
        default=None,
        description="Filter to incidents with (True) or without (False) feedback",
    )
    publicly_shared: bool | None = Field(
        default=None,
        description="Filter to incidents that are (True) or aren't (False) publicly shared",
    )

    # Vault/Secret Manager filters
    secret_manager_type: list[str] | None = Field(
        default=None,
        description="Filter by vault type. Values: hashicorpvault, awssecretsmanager, azurekeyvault, gcpsecretmanager, cyberarksaas, cyberarkselfhosted, akeyless, delineasecretserver",
    )
    secret_manager_instance: list[int] | None = Field(
        default=None,
        description="Filter by vault instance ID(s)",
    )

    # NHI (Non-Human Identity) filters
    nhi_env: list[str] | None = Field(
        default=None,
        description="Filter by NHI environment name(s)",
    )
    nhi_policy: list[str] | None = Field(
        default=None,
        description="Filter by NHI policy breach name(s)",
    )

    # Team filters
    teams: list[int] | None = Field(
        default=None,
        description="Filter by team ID(s)",
    )

    # Similar issues filter
    similar_to: int | None = Field(
        default=None,
        description="Filter incidents similar to the given incident ID",
    )

    # Date filters
    date_before: str | None = Field(
        default=None,
        description="Filter incidents detected before this date (YYYY-MM-DD format)",
    )
    date_after: str | None = Field(
        default=None,
        description="Filter incidents detected after this date (YYYY-MM-DD format)",
    )

    # Secret scope filter
    secret_scope: list[str] | None = Field(
        default=None,
        description="Filter by secret scope name(s)",
    )

    # Analyzer status filter
    analyzer_status: list[str] | None = Field(
        default=None,
        description="Filter by analyzer status. Values: no_checker, not_checked, checked, invalid, failed_to_check",
    )

    # Custom tags filter
    custom_tags: list[int] | None = Field(
        default=None,
        description="Filter by custom tag ID(s)",
    )


class ListIncidentsResult(BaseModel):
    """Result from listing incidents."""

    incidents: list[dict[str, Any]] = Field(default_factory=list, description="List of incident objects")
    total_count: int = Field(description="Total number of incidents matching the filters")
    page: int = Field(description="Current page number (last page fetched when get_all=True)")
    page_size: int = Field(description="Number of results per page")
    has_next: bool = Field(default=False, description="True if there are more pages available")
    has_previous: bool = Field(default=False, description="True if there are previous pages")
    has_more: bool = Field(
        default=False, description="True if results were truncated due to size limit (only relevant when get_all=True)"
    )
    applied_filters: dict[str, Any] = Field(default_factory=dict, description="Filters that were applied to the query")
    suggestion: str = Field(default="", description="Suggestions for interpreting or modifying the results")


class ListIncidentsError(BaseModel):
    """Error result from listing incidents."""

    error: str = Field(description="Error message")


async def list_incidents(params: ListIncidentsParams) -> ListIncidentsResult | ListIncidentsError:
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
            - total_count: Total number of matching incidents
            - page: Current page number
            - page_size: Results per page
            - has_next/has_previous: Pagination indicators
            - applied_filters: Dictionary of filters that were applied
            - suggestion: Suggestions for interpreting or modifying results

        ListIncidentsError: Pydantic model with error message if the operation fails
    """
    client = await get_client()

    try:
        # Build API parameters
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

        # Search
        if params.search:
            api_params["search"] = params.search

        # Basic filters
        if params.status:
            api_params["status"] = params.status
        if params.severity:
            # Convert severity names to numeric values if needed
            severity_values: list[int | str] = []
            for sev in params.severity:
                if isinstance(sev, int):
                    severity_values.append(sev)
                elif isinstance(sev, str) and sev.lower() in SEVERITY_NAME_TO_VALUE:
                    severity_values.append(SEVERITY_NAME_TO_VALUE[sev.lower()])
                else:
                    # Try to parse as int, or pass through as-is
                    try:
                        severity_values.append(int(str(sev)))
                    except ValueError:
                        severity_values.append(str(sev))
            api_params["severity"] = severity_values
        if params.score_min is not None:
            api_params["score__ge"] = params.score_min
        if params.score_max is not None:
            api_params["score__le"] = params.score_max
        if params.validity:
            api_params["validity"] = params.validity

        # Secret type filters
        if params.detector_group_name:
            api_params["detector_group_name"] = params.detector_group_name
        if params.detector_type:
            api_params["detector_type"] = params.detector_type
        if params.detector_category:
            api_params["detector_category"] = params.detector_category
        if params.issue_name:
            api_params["issue_name"] = params.issue_name
        if params.secret_category:
            api_params["secret_category"] = params.secret_category
        if params.secret_family:
            api_params["secret_family"] = params.secret_family
        if params.secret_provider:
            api_params["secret_provider"] = params.secret_provider

        # Source filters
        # Resolve repository_name to source ID if provided
        source_ids: list[int | str] = list(params.source_ids) if params.source_ids else []
        if params.repository_name:
            result = await find_current_source_id(params.repository_name)
            if hasattr(result, "error"):
                return ListIncidentsError(error=result.error)
            if result.source_id is not None:
                source_ids.append(int(result.source_id) if isinstance(result.source_id, str) else result.source_id)
        if source_ids:
            api_params["source"] = source_ids
        if params.source_type:
            api_params["source_type"] = params.source_type
        if params.source_criticality:
            api_params["source_criticality"] = params.source_criticality

        # Occurrence and presence filters
        if params.occurrence_count_min is not None:
            api_params["occurrence_count"] = f">={params.occurrence_count_min}"
        if params.presence:
            api_params["presence"] = params.presence

        # Date filters
        if params.opened_for_days is not None:
            api_params["opened_for"] = f">={params.opened_for_days}"

        # Tags filters
        if params.tags:
            api_params["tags"] = params.tags
        if params.exclude_tags:
            # Use the 'nin' operator for exclusion
            api_params["custom_filters"] = api_params.get("custom_filters", {})
            api_params["custom_filters"]["tags__nin"] = ",".join(params.exclude_tags)

        # Public exposure
        if params.public_exposure:
            api_params["public_exposure"] = params.public_exposure

        # Integration filters
        if params.integration:
            api_params["integration"] = params.integration
        if params.issue_tracker:
            api_params["issue_tracker"] = params.issue_tracker

        # Boolean filters
        if params.has_related_issues is not None:
            api_params["has_related_issues"] = params.has_related_issues
        if params.location is not None:
            api_params["location"] = params.location
        if params.feedback is not None:
            api_params["feedback"] = params.feedback
        if params.publicly_shared is not None:
            api_params["publicly_shared"] = params.publicly_shared

        # Vault/Secret Manager filters
        if params.secret_manager_type:
            api_params["secret_manager_type"] = params.secret_manager_type
        if params.secret_manager_instance:
            api_params["secret_manager_instance"] = params.secret_manager_instance

        # NHI filters
        if params.nhi_env:
            api_params["nhi_env"] = params.nhi_env
        if params.nhi_policy:
            api_params["nhi_policy"] = params.nhi_policy

        # Team filters
        if params.teams:
            api_params["teams"] = params.teams

        # Similar issues filter
        if params.similar_to is not None:
            api_params["similar_to"] = params.similar_to

        # Date filters
        if params.date_before:
            api_params["date_before"] = params.date_before
        if params.date_after:
            api_params["date_after"] = params.date_after

        # Secret scope filter
        if params.secret_scope:
            api_params["secret_scope"] = params.secret_scope

        # Analyzer status filter
        if params.analyzer_status:
            api_params["analyzer_status"] = params.analyzer_status

        # Custom tags filter
        if params.custom_tags:
            api_params["custom_tags"] = params.custom_tags

        if params.get_all:
            # Fetch all pages with byte limit protection
            all_incidents: list[dict[str, Any]] = []
            current_page = 1
            total_bytes = 0
            has_more = False
            total_count = 0

            while True:
                response = await client.list_incidents_for_mcp(
                    page=current_page,
                    page_size=params.page_size,
                    ordering=params.ordering,
                    **api_params,
                )

                page_incidents = response.get("results", [])
                total_count = response.get("count", 0)
                has_next_page = response.get("next") is not None

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
                total_count=total_count,
                page=current_page,
                page_size=params.page_size,
                has_next=has_more,
                has_previous=False,
                has_more=has_more,
                applied_filters=_build_filter_info(params),
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
            total_count = response.get("count", len(incidents_data))
            has_next = response.get("next") is not None
            has_previous = response.get("previous") is not None

            return ListIncidentsResult(
                incidents=incidents_data,
                total_count=total_count,
                page=params.page,
                page_size=params.page_size,
                has_next=has_next,
                has_previous=has_previous,
                has_more=False,
                applied_filters=_build_filter_info(params),
                suggestion=_build_suggestion(params, len(incidents_data)),
            )

    except Exception as e:
        logger.exception(f"Error listing incidents: {str(e)}")
        return ListIncidentsError(error=f"Failed to list incidents: {str(e)}")
