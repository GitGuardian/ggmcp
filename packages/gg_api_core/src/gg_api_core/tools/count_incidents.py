import logging
from typing import Any

from pydantic import BaseModel, Field, field_validator

from gg_api_core.tools.list_incidents import (
    DEFAULT_EXCLUDED_TAGS,
    DEFAULT_SEVERITIES,
    DEFAULT_STATUSES,
    DEFAULT_VALIDITIES,
    SEVERITY_NAME_TO_VALUE,
)
from gg_api_core.utils import get_client

logger = logging.getLogger(__name__)


class CountIncidentsParams(BaseModel):
    """Parameters for counting incidents using the MCP-optimized count endpoint.

    Accepts the same filters as list_incidents but returns only a count.
    """

    # Search
    search: str | None = Field(
        default=None,
        description="Search term to filter incidents by name or content",
    )

    # Status and assignment filters
    status: list[str] | None = Field(
        default=DEFAULT_STATUSES,
        description="Filter by status. Values: TRIGGERED (unassigned active), ASSIGNED (assigned active), RESOLVED, IGNORED. Default excludes IGNORED.",
    )
    mine: bool = Field(
        default=False,
        description="If True, count only incidents assigned to the current user. Overrides assignee_id.",
    )
    assignee_id: int | None = Field(
        default=None,
        description="Filter by assignee member ID. Use 0 for unassigned incidents. Cannot be used with 'mine'.",
    )

    # Severity, score, and validity filters
    severity: list[str | int] | None = Field(
        default=DEFAULT_SEVERITIES,
        description="Filter by severity levels. Values: critical (10), high (20), medium (30), low (40), info (50), unknown (100). Default excludes LOW and INFO.",
    )
    score_min: int | None = Field(
        default=None,
        description="Filter incidents with a score greater than or equal to this value (0-100).",
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
        default=DEFAULT_VALIDITIES,
        description="Filter by validity status. Values: valid, invalid, failed_to_check, no_checker, not_checked. Default excludes INVALID.",
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
    source_ids: list[int] | None = Field(
        default=None,
        description="Filter by source ID(s). Can be obtained using list_source or find_current_source_id tools.",
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
        default=DEFAULT_EXCLUDED_TAGS,
        description="Exclude incidents with these tag names. Default excludes TEST_FILE, FALSE_POSITIVE, and CHECK_RUN_SKIP_* tags.",
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

    @field_validator(
        "status",
        "severity",
        "validity",
        "detector_group_name",
        "detector_type",
        "detector_category",
        "issue_name",
        "secret_category",
        "secret_family",
        "secret_provider",
        "source_ids",
        "source_type",
        "source_criticality",
        "presence",
        "tags",
        "exclude_tags",
        "public_exposure",
        "integration",
        "issue_tracker",
        "secret_manager_type",
        "secret_manager_instance",
        "nhi_env",
        "nhi_policy",
        "teams",
        "secret_scope",
        "analyzer_status",
        "custom_tags",
        mode="before",
    )
    @classmethod
    def coerce_to_list(cls, v: Any) -> list[Any] | None:
        """Convert single values to lists for LLM compatibility."""
        if v is None:
            return None
        if isinstance(v, list):
            return v
        return [v]


class CountIncidentsResult(BaseModel):
    """Result from counting incidents."""

    count: int = Field(description="Total number of matching incidents")
    applied_filters: dict[str, Any] = Field(default_factory=dict, description="Filters that were applied to the query")


class CountIncidentsError(BaseModel):
    """Error result from counting incidents."""

    error: str = Field(description="Error message")


def _build_filter_info(params: CountIncidentsParams) -> dict[str, Any]:
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
    if params.exclude_tags:
        filters["exclude_tags"] = params.exclude_tags
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


async def count_incidents(
    params: CountIncidentsParams,
) -> CountIncidentsResult | CountIncidentsError:
    """
    Count secret incidents matching the given filters.

    Returns the total number of matching incidents without fetching the full list.
    This is useful to get an overview of incident volume, check filter results
    before paginating, or build dashboards.

    Accepts the same filters as list_incidents (status, severity, detector type,
    source, tags, etc.) but returns only the count.

    Args:
        params: CountIncidentsParams model containing all filtering options.

    Returns:
        CountIncidentsResult: Pydantic model containing:
            - count: Total number of matching incidents
            - applied_filters: Dictionary of filters that were applied

        CountIncidentsError: Pydantic model with error message if the operation fails
    """
    client = await get_client()

    try:
        api_params: dict[str, Any] = {}

        # Handle 'mine' parameter
        if params.mine:
            member = await client.get_current_member()
            current_user_id = member["id"]
            if params.assignee_id is not None and params.assignee_id != current_user_id:
                return CountIncidentsError(
                    error=f"Conflict: 'mine=True' implies assignee_id={current_user_id}, "
                    f"but assignee_id={params.assignee_id} was explicitly provided. "
                    "Please use either 'mine=True' or an explicit 'assignee_id', not both."
                )
            api_params["assignee_id"] = current_user_id
        elif params.assignee_id is not None:
            api_params["assignee_id"] = params.assignee_id

        if params.search:
            api_params["search"] = params.search

        if params.status:
            api_params["status"] = params.status
        if params.severity:
            severity_values: list[int | str] = []
            for sev in params.severity:
                if isinstance(sev, int):
                    severity_values.append(sev)
                elif isinstance(sev, str) and sev.lower() in SEVERITY_NAME_TO_VALUE:
                    severity_values.append(SEVERITY_NAME_TO_VALUE[sev.lower()])
                else:
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

        source_ids: list[int | str] = list(params.source_ids) if params.source_ids else []
        if source_ids:
            api_params["source"] = source_ids
        if params.source_type:
            api_params["source_type"] = params.source_type
        if params.source_criticality:
            api_params["source_criticality"] = params.source_criticality

        if params.occurrence_count_min is not None:
            api_params["occurrence_count"] = f">={params.occurrence_count_min}"
        if params.presence:
            api_params["presence"] = params.presence

        if params.opened_for_days is not None:
            api_params["opened_for"] = f">={params.opened_for_days}"

        if params.tags:
            api_params["tags"] = params.tags
        if params.exclude_tags:
            api_params["custom_filters"] = api_params.get("custom_filters", {})
            api_params["custom_filters"]["tags__nin"] = ",".join(params.exclude_tags)

        if params.public_exposure:
            api_params["public_exposure"] = params.public_exposure

        if params.integration:
            api_params["integration"] = params.integration
        if params.issue_tracker:
            api_params["issue_tracker"] = params.issue_tracker

        if params.has_related_issues is not None:
            api_params["has_related_issues"] = params.has_related_issues
        if params.location is not None:
            api_params["location"] = params.location
        if params.feedback is not None:
            api_params["feedback"] = params.feedback
        if params.publicly_shared is not None:
            api_params["publicly_shared"] = params.publicly_shared

        if params.secret_manager_type:
            api_params["secret_manager_type"] = params.secret_manager_type
        if params.secret_manager_instance:
            api_params["secret_manager_instance"] = params.secret_manager_instance

        if params.nhi_env:
            api_params["nhi_env"] = params.nhi_env
        if params.nhi_policy:
            api_params["nhi_policy"] = params.nhi_policy

        if params.teams:
            api_params["teams"] = params.teams

        if params.similar_to is not None:
            api_params["similar_to"] = params.similar_to

        if params.date_before:
            api_params["date_before"] = params.date_before
        if params.date_after:
            api_params["date_after"] = params.date_after

        if params.secret_scope:
            api_params["secret_scope"] = params.secret_scope

        if params.analyzer_status:
            api_params["analyzer_status"] = params.analyzer_status

        if params.custom_tags:
            api_params["custom_tags"] = params.custom_tags

        response = await client.count_incidents_for_mcp(**api_params)

        return CountIncidentsResult(
            count=response["count"],
            applied_filters=_build_filter_info(params),
        )

    except Exception as e:
        logger.exception(f"Error counting incidents: {str(e)}")
        return CountIncidentsError(error=f"Failed to count incidents: {str(e)}")
