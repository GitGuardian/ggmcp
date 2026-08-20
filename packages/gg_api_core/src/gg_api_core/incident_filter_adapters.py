"""Translate canonical public incident filters to endpoint-specific wire values."""

from collections.abc import Mapping, Sequence
from typing import Literal, TypeAlias, TypeVar

from gg_api_core.generated_filter_vocabulary import (
    IncidentSeverityFilter,
    IncidentSourceTypeFilter,
    IncidentStatusFilter,
    IncidentValidityFilter,
)

IncidentIntegrationFilter: TypeAlias = Literal[
    "github",
    "github_enterprise_server",
    "gitlab",
]

MCP_INTEGRATION_VALUES: dict[IncidentIntegrationFilter, str] = {
    "github": "gh",
    "github_enterprise_server": "ghe",
    "gitlab": "gl",
}
MCP_SEVERITY_VALUES: dict[IncidentSeverityFilter, int] = {
    "critical": 10,
    "high": 20,
    "medium": 30,
    "low": 40,
    "info": 50,
    "unknown": 100,
}
MCP_SOURCE_TYPE_VALUES: dict[IncidentSourceTypeFilter, str] = {
    "bitbucket": "bb_repository",
    "bitbucket_cloud": "bb_cloud_repository",
    "github": "gh_repository",
    "gitlab": "gl_project",
    "azure_devops": "ado_repository",
    "slack": "slack_channel",
    "jira_cloud": "jira_cloud_project",
    "confluence_cloud": "confluence_cloud_space",
    "microsoft_teams": "microsoft_teams_channel",
    "confluence_data_center": "confluence_data_center_space",
    "jira_data_center": "jira_data_center_project",
    "aws_ecr": "aws_ecr_repository",
    "azure_cr": "azure_cr_repository",
    "google_artifact": "google_artifact_repository",
    "jfrog_artifact": "jfrog_artifact_repository",
    "docker_hub": "docker_hub_repository",
    "servicenow": "servicenow_table",
    "sharepoint_online": "sharepoint_online_drive",
    "sharepoint_online_drive": "sharepoint_online_drive",
    "sharepoint_online_pages": "sharepoint_online_pages",
    "microsoft_onedrive": "microsoft_onedrive",
    "custom_source": "custom_source",
}
MCP_STATUS_VALUES: dict[IncidentStatusFilter, str] = {
    "IGNORED": "IGNORED",
    "TRIGGERED": "TRIGGERED",
    "ASSIGNED": "ASSIGNED",
    "RESOLVED": "RESOLVED",
}
MCP_VALIDITY_VALUES: dict[IncidentValidityFilter, str] = {
    "valid": "valid",
    "invalid": "invalid",
    "failed_to_check": "failed_to_check",
    "no_checker": "no_checker",
    "unknown": "not_checked",
}

_CanonicalValue = TypeVar("_CanonicalValue", bound=str)
_WireValue = TypeVar("_WireValue", str, int)


def _translate(
    field: str,
    value: str | Sequence[str],
    mapping: Mapping[_CanonicalValue, _WireValue],
) -> list[_WireValue]:
    """Translate one or more canonical values and report the field's allowed values."""
    values = [value] if isinstance(value, str) else value
    translated: list[_WireValue] = []
    for candidate in values:
        try:
            translated.append(mapping[candidate])  # type: ignore[index]
        except KeyError:
            allowed = ", ".join(mapping)
            raise ValueError(f"Invalid {field} value {candidate!r}. Allowed values: {allowed}") from None
    return translated


def to_mcp_integration(
    value: IncidentIntegrationFilter | Sequence[IncidentIntegrationFilter],
) -> list[str]:
    """Translate canonical integration names to /incidents-for-mcp codes."""
    return _translate("integration", value, MCP_INTEGRATION_VALUES)


def to_mcp_severity(value: IncidentSeverityFilter | Sequence[IncidentSeverityFilter]) -> list[int]:
    """Translate public severity names to /incidents-for-mcp numeric values."""
    return _translate("severity", value, MCP_SEVERITY_VALUES)


def to_mcp_source_type(value: IncidentSourceTypeFilter | Sequence[IncidentSourceTypeFilter]) -> list[str]:
    """Translate public source types to /incidents-for-mcp model names."""
    return _translate("source_type", value, MCP_SOURCE_TYPE_VALUES)


def to_mcp_status(value: IncidentStatusFilter | Sequence[IncidentStatusFilter]) -> list[str]:
    """Validate statuses before sending them to /incidents-for-mcp."""
    return _translate("status", value, MCP_STATUS_VALUES)


def to_mcp_validity(value: IncidentValidityFilter | Sequence[IncidentValidityFilter]) -> list[str]:
    """Translate public validity names to /incidents-for-mcp spellings."""
    return _translate("validity", value, MCP_VALIDITY_VALUES)
