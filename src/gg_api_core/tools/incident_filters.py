"""Shared parameter validation and filter mapping for internal incidents."""

from typing import Any

from pydantic import BaseModel, Field, field_validator

from gg_api_core.client import GitGuardianClient, _serialize_enum_filter, _to_date_only


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


# Default filters to reduce noise - exclude test files, false positives, and low-priority incidents
DEFAULT_EXCLUDED_TAGS = [
    "TEST_FILE",
    "FALSE_POSITIVE",
    "CHECK_RUN_SKIP_FALSE_POSITIVE",
    "CHECK_RUN_SKIP_LOW_RISK",
    "CHECK_RUN_SKIP_TEST_CRED",
]
DEFAULT_SEVERITIES: list[str | int] = [
    SeverityValues.CRITICAL,
    SeverityValues.HIGH,
    SeverityValues.MEDIUM,
    SeverityValues.UNKNOWN,
]  # Exclude LOW and INFO
DEFAULT_STATUSES = [
    IncidentStatus.TRIGGERED,
    IncidentStatus.ASSIGNED,
    IncidentStatus.RESOLVED,
]  # Exclude IGNORED
DEFAULT_VALIDITIES = [
    "valid",
    "failed_to_check",
    "no_checker",
    "not_checked",
]  # Exclude INVALID


class IncidentFilters(BaseModel):
    """Shared filters for the MCP incident list and count endpoints."""

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
        description="Filter by source ID(s). Can be obtained using the list_sources tool.",
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


def build_filter_info(params: IncidentFilters) -> dict[str, Any]:
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


async def resolve_assignee(client: GitGuardianClient, params: IncidentFilters) -> tuple[int | None, str | None]:
    """The member id to filter on, from mine and assignee_id, or the error when they conflict."""
    if params.mine:
        member = await client.get_current_member()
        current_user_id = member["id"]
        if params.assignee_id is not None and params.assignee_id != current_user_id:
            return None, (
                f"Conflict: 'mine=True' implies assignee_id={current_user_id}, "
                f"but assignee_id={params.assignee_id} was explicitly provided. "
                "Please use either 'mine=True' or an explicit 'assignee_id', not both."
            )
        return current_user_id, None
    return params.assignee_id, None


def _severity_values(severities: list[str | int]) -> list[int | str]:
    """Severity names to the API's numeric values; numbers and unknown names pass through."""
    values: list[int | str] = []
    for sev in severities:
        if isinstance(sev, int):
            values.append(sev)
        elif isinstance(sev, str) and sev.lower() in SEVERITY_NAME_TO_VALUE:
            values.append(SEVERITY_NAME_TO_VALUE[sev.lower()])
        else:
            try:
                values.append(int(str(sev)))
            except ValueError:
                values.append(str(sev))
    return values


def build_incident_query(params: IncidentFilters, assignee_id: int | None) -> dict[str, Any]:
    """Translate the shared filters into the /incidents-for-mcp query.

    Multi-value filters are comma-joined under ``<name>__in``. The key order is
    the order the API has always received them in.
    """
    query: dict[str, Any] = {}

    def add_list(key: str, values: list[Any] | None) -> None:
        if values:
            query[key] = _serialize_enum_filter(values)

    if params.search:
        query["search"] = params.search
    add_list("status__in", params.status)
    if assignee_id is not None:
        # A member id: the endpoint resolves it to the user. assignee__in expects
        # a user id and would silently match nothing.
        query["assignee_member_id"] = _serialize_enum_filter(assignee_id)
    if params.severity:
        add_list("severity__in", _severity_values(params.severity))
    if params.score_min is not None:
        query["score__ge"] = params.score_min
    if params.score_max is not None:
        query["score__le"] = params.score_max
    add_list("validity__in", params.validity)
    for name in (
        "detector_group_name",
        "detector_type",
        "detector_category",
        "issue_name",
        "secret_category",
        "secret_family",
        "secret_provider",
    ):
        add_list(f"{name}__in", getattr(params, name))
    add_list("source__in", params.source_ids)
    add_list("source_type__in", params.source_type)
    add_list("source_criticality__in", params.source_criticality)
    if params.occurrence_count_min is not None:
        query["occurrence_count"] = f">={params.occurrence_count_min}"
    add_list("presence__in", params.presence)
    if params.opened_for_days is not None:
        query["opened_for"] = f">={params.opened_for_days}"
    add_list("tags__in", params.tags)
    for name in ("public_exposure", "integration", "issue_tracker"):
        add_list(f"{name}__in", getattr(params, name))
    for name in ("has_related_issues", "location", "feedback", "publicly_shared"):
        value = getattr(params, name)
        if value is not None:
            query[name] = str(value).lower()
    for name in ("secret_manager_type", "secret_manager_instance", "nhi_env", "nhi_policy", "teams"):
        add_list(f"{name}__in", getattr(params, name))
    if params.similar_to is not None:
        query["similar_to"] = params.similar_to
    if params.date_before:
        query["date__le"] = _to_date_only(params.date_before)
    if params.date_after:
        query["date__ge"] = _to_date_only(params.date_after)
    for name in ("secret_scope", "analyzer_status", "custom_tags"):
        add_list(f"{name}__in", getattr(params, name))
    if params.exclude_tags:
        query["tags__nin"] = ",".join(params.exclude_tags)
    return query
