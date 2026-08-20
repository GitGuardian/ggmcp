"""Shared incident filter model and query builders for the MCP incident read tools.

`list_incidents`, `count_incidents` and their VCR/e2e siblings accept the same
filter vocabulary and build the same ``/incidents-for-mcp`` query parameters.
This module holds the one canonical model and the two builders that convert it
into wire and ``applied_filters`` shapes, so the tools cannot drift apart.
"""

from typing import Any

from pydantic import BaseModel, Field, field_validator

from gg_api_core.generated_filter_vocabulary import (
    IncidentSeverityFilter,
    IncidentSourceTypeFilter,
    IncidentStatusFilter,
    IncidentValidityFilter,
)
from gg_api_core.incident_filter_adapters import IncidentIntegrationFilter

# Default filters to reduce noise - exclude test files, false positives, and low-priority incidents
DEFAULT_EXCLUDED_TAGS = [
    "TEST_FILE",
    "FALSE_POSITIVE",
    "CHECK_RUN_SKIP_FALSE_POSITIVE",
    "CHECK_RUN_SKIP_LOW_RISK",
    "CHECK_RUN_SKIP_TEST_CRED",
]
DEFAULT_SEVERITIES: list[IncidentSeverityFilter] = [
    "critical",
    "high",
    "medium",
    "unknown",
]  # Exclude low and info
DEFAULT_STATUSES: list[IncidentStatusFilter] = [
    "TRIGGERED",
    "ASSIGNED",
    "RESOLVED",
]  # Exclude IGNORED
DEFAULT_VALIDITIES: list[IncidentValidityFilter] = [
    "valid",
    "failed_to_check",
    "no_checker",
    "unknown",
]  # Exclude INVALID


def coerce_to_list(value: Any) -> list[Any] | None:
    """Normalize a single value, a list, or a comma-separated string into a list.

    MCP agents historically sent single values and comma-separated strings for
    list-shaped filters; this validator keeps accepting every shape while the
    strong (Literal/int) field types reject unsupported values.
    """
    if value is None:
        return None
    if isinstance(value, list):
        return value
    if isinstance(value, str) and "," in value:
        return [item.strip() for item in value.split(",") if item.strip()]
    return [value]


class IncidentFilterParams(BaseModel):
    """Filter fields shared by every incident read tool.

    Subclasses add their pagination/ordering/result-shaping fields. Defaults are
    defined once here so `list_incidents` and `count_incidents` stay consistent.
    """

    # Search
    search: str | None = Field(
        default=None,
        description="Search term to filter incidents by name or content",
    )

    # Status and assignment filters
    status: list[IncidentStatusFilter] | None = Field(
        default=DEFAULT_STATUSES,
        description="Filter by status. Values: TRIGGERED, ASSIGNED, RESOLVED, IGNORED. Default excludes IGNORED.",
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
    severity: list[IncidentSeverityFilter] | None = Field(
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
    validity: list[IncidentValidityFilter] | None = Field(
        default=DEFAULT_VALIDITIES,
        description="Filter by validity status. Values: valid, invalid, failed_to_check, no_checker, unknown. Default excludes INVALID.",
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
    source_type: list[IncidentSourceTypeFilter] | None = Field(
        default=None,
        description="Filter by public API source type (for example: github, gitlab, bitbucket, azure_devops).",
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
    integration: list[IncidentIntegrationFilter] | None = Field(
        default=None,
        description="Filter by audited integration name. Values: github, github_enterprise_server, gitlab",
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

    # Normalize every list-shaped filter to a list before the strong field types
    # validate it. Accepts single values, lists, and comma-separated strings.
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
    def _coerce(cls, value: Any) -> list[Any] | None:
        return coerce_to_list(value)


def build_api_params(params: IncidentFilterParams) -> dict[str, Any]:
    """Build the ``/incidents-for-mcp`` query parameters from the shared filters.

    The ``mine`` resolution (it needs the authenticated member) stays in the
    calling tool, which resolves it to an ``assignee_id`` before this builder
    runs.
    """
    api_params: dict[str, Any] = {}

    if params.assignee_id is not None:
        api_params["assignee_id"] = params.assignee_id

    if params.search:
        api_params["search"] = params.search

    # Basic filters
    if params.status:
        api_params["status"] = params.status
    if params.severity:
        api_params["severity"] = params.severity
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
    if params.source_ids:
        api_params["source"] = params.source_ids
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

    return api_params


def build_filter_info(params: IncidentFilterParams) -> dict[str, Any]:
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
