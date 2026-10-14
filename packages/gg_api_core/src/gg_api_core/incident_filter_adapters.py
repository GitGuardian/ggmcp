"""Translate canonical public incident filters to endpoint-specific wire values."""

from collections.abc import Mapping, Sequence
from typing import Any, Literal, TypeAlias

IncidentIntegrationFilter: TypeAlias = Literal[
    "github",
    "github_enterprise_server",
    "gitlab",
]


# Canonical -> wire value for the private /incidents-for-mcp endpoint. Kept
# explicit as a plain dict (string key, str/int value) because this endpoint is
# not part of the public OpenAPI specification that generates the vocabulary.
MCP_INTEGRATION_VALUES: dict[str, str] = {
    "github": "gh",
    "github_enterprise_server": "ghe",
    "gitlab": "gl",
}
MCP_SEVERITY_VALUES: dict[str, int] = {
    "critical": 10,
    "high": 20,
    "medium": 30,
    "low": 40,
    "info": 50,
    "unknown": 100,
}
MCP_SOURCE_TYPE_VALUES: dict[str, str] = {
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
MCP_STATUS_VALUES: dict[str, str] = {
    "IGNORED": "IGNORED",
    "TRIGGERED": "TRIGGERED",
    "ASSIGNED": "ASSIGNED",
    "RESOLVED": "RESOLVED",
}
MCP_VALIDITY_VALUES: dict[str, str] = {
    "valid": "valid",
    "invalid": "invalid",
    "failed_to_check": "failed_to_check",
    "no_checker": "no_checker",
    "unknown": "not_checked",
}

# Field name -> canonical-to-wire mapping, so a single dispatcher serves them all.
_MAPPINGS: dict[str, Mapping[str, Any]] = {
    "integration": MCP_INTEGRATION_VALUES,
    "severity": MCP_SEVERITY_VALUES,
    "source_type": MCP_SOURCE_TYPE_VALUES,
    "status": MCP_STATUS_VALUES,
    "validity": MCP_VALIDITY_VALUES,
}


def to_mcp(field: str, value: str | Sequence[str]) -> list[Any]:
    """Translate one or more canonical values for ``field`` to /incidents-for-mcp wire values.

    Raises :class:`ValueError` naming the field's allowed canonical values when an
    unsupported value is passed, so callers reject bad agent input before a request.
    """
    mapping = _MAPPINGS[field]
    values = [value] if isinstance(value, str) else value
    translated: list[Any] = []
    for candidate in values:
        try:
            translated.append(mapping[candidate])
        except KeyError:
            allowed = ", ".join(mapping)
            raise ValueError(f"Invalid {field} value {candidate!r}. Allowed values: {allowed}") from None
    return translated
