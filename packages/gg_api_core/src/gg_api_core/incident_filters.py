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


# Filters whose ``/incidents-for-mcp`` parameter name differs from the field name.
_API_WIRE_NAMES = {"score_min": "score__ge", "score_max": "score__le", "source_ids": "source"}

# Filters build_api_params does not forward verbatim: ``mine`` is resolved to an
# assignee_id by the calling tool, and the rest need a value transform below.
_API_HANDLED_SEPARATELY = frozenset({"mine", "exclude_tags", "occurrence_count_min", "opened_for_days"})

# ``mine`` describes how assignee_id was chosen, so it is not itself a filter.
_INFO_EXCLUDED = frozenset({"mine"})


def _is_applied(value: Any) -> bool:
    """Whether a filter field carries a value worth sending.

    Strings and collections are absent when empty. Scalars keep their falsy
    values, because ``score_min=0`` and ``location=False`` are real filters
    while ``severity=[]`` and ``search=""`` are simply unset.
    """
    if value is None:
        return False
    if isinstance(value, (str, bytes, list, tuple, set, dict)):
        return bool(value)
    return True


def _applied_fields(params: IncidentFilterParams, exclude: frozenset[str]) -> dict[str, Any]:
    """The shared filter fields that carry a value, in declaration order.

    Iterating the base model's fields keeps subclass pagination and ordering
    fields out, which is why this takes the field names from
    ``IncidentFilterParams`` rather than dumping the instance.
    """
    applied: dict[str, Any] = {}
    for name in IncidentFilterParams.model_fields:
        if name in exclude:
            continue
        value = getattr(params, name)
        if _is_applied(value):
            applied[name] = value
    return applied


def build_api_params(params: IncidentFilterParams) -> dict[str, Any]:
    """Build the ``/incidents-for-mcp`` query parameters from the shared filters.

    The ``mine`` resolution (it needs the authenticated member) stays in the
    calling tool, which resolves it to an ``assignee_id`` before this builder
    runs.
    """
    api_params: dict[str, Any] = {
        _API_WIRE_NAMES.get(name, name): value
        for name, value in _applied_fields(params, _API_HANDLED_SEPARATELY).items()
    }

    # Range filters the API expects as a comparison string.
    if params.occurrence_count_min is not None:
        api_params["occurrence_count"] = f">={params.occurrence_count_min}"
    if params.opened_for_days is not None:
        api_params["opened_for"] = f">={params.opened_for_days}"

    # Tag exclusion goes through the 'nin' operator rather than a plain filter.
    if params.exclude_tags:
        api_params["custom_filters"] = {"tags__nin": ",".join(params.exclude_tags)}

    return api_params


def build_filter_info(params: IncidentFilterParams) -> dict[str, Any]:
    """Build a dictionary describing the filters applied to the query."""
    return _applied_fields(params, _INFO_EXCLUDED)
