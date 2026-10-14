"""Contract tests for OpenAPI-generated incident filter vocabularies."""

from typing import Any, get_args

import pytest
from gg_api_core.generated_filter_vocabulary import (
    IncidentSeverityFilter,
    IncidentSourceTypeFilter,
    IncidentStatusFilter,
    IncidentValidityFilter,
)
from gg_api_core.incident_filter_adapters import (
    MCP_SEVERITY_VALUES,
    MCP_SOURCE_TYPE_VALUES,
    MCP_STATUS_VALUES,
    MCP_VALIDITY_VALUES,
    IncidentIntegrationFilter,
)
from gg_api_core.tools.count_incidents import CountIncidentsParams
from gg_api_core.tools.list_incidents import ListIncidentsParams
from gg_api_core.tools.list_public_incidents import ListPublicIncidentsParams
from gg_api_core.tools.list_public_occurrences import ListPublicOccurrencesParams
from gg_api_core.tools.list_repo_occurrences import ListRepoOccurrencesParams
from gg_api_core.tools.list_sources import ListSourcesParams
from pydantic import BaseModel, ValidationError

FILTER_MODELS = [
    ListIncidentsParams,
    CountIncidentsParams,
    ListRepoOccurrencesParams,
    ListPublicIncidentsParams,
    ListPublicOccurrencesParams,
]
EXPECTED_VALUES = {
    "severity": set(get_args(IncidentSeverityFilter)),
    "status": set(get_args(IncidentStatusFilter)),
    "validity": set(get_args(IncidentValidityFilter)),
}


def _field_values(model: type[BaseModel], field: str) -> set[str]:
    """Extract a list field's allowed values from its generated JSON schema."""
    field_schema = model.model_json_schema()["properties"][field]
    array_schema = next(option for option in field_schema["anyOf"] if option.get("type") == "array")
    return set(array_schema["items"]["enum"])


def _model_input(model: type[BaseModel], **values: Any) -> dict[str, Any]:
    """Add fields required by only one of the filter models."""
    if model is ListPublicOccurrencesParams:
        return {"incident_id": 1, **values}
    return values


class TestSharedFilterVocabulary:
    """Every incident tool must expose the same generated public vocabulary."""

    @pytest.mark.parametrize("model", FILTER_MODELS)
    @pytest.mark.parametrize("field", ["severity", "status", "validity"])
    def test_schema_exposes_generated_values(self, model, field):
        """
        GIVEN an incident tool filter generated from public OpenAPI values
        WHEN inspecting its MCP JSON schema
        THEN it exposes exactly the generated canonical vocabulary
        """
        assert _field_values(model, field) == EXPECTED_VALUES[field]

    @pytest.mark.parametrize("model", FILTER_MODELS)
    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("severity", "catastrophic"),
            ("status", "OPENED"),
            ("validity", "not_checked"),
        ],
    )
    def test_noncanonical_values_are_rejected_before_the_tool_runs(self, model, field, value):
        """
        GIVEN a value outside the OpenAPI vocabulary
        WHEN Pydantic constructs tool parameters
        THEN validation names the field and rejects the value before any API call
        """
        with pytest.raises(ValidationError) as exc_info:
            model(**_model_input(model, **{field: [value]}))

        assert field in str(exc_info.value)
        for allowed in EXPECTED_VALUES[field]:
            assert allowed in str(exc_info.value)


class TestSourceTypeVocabulary:
    """Source filters reuse the public API's generated source-type vocabulary."""

    @pytest.mark.parametrize("model", [ListIncidentsParams, CountIncidentsParams])
    def test_incident_schema_exposes_generated_source_types(self, model):
        """
        GIVEN an MCP-optimized incident tool
        WHEN inspecting its source_type schema
        THEN it exposes public source names rather than internal model names
        """
        assert _field_values(model, "source_type") == set(get_args(IncidentSourceTypeFilter))

    def test_list_sources_uses_the_same_generated_source_types(self):
        """
        GIVEN the public list_sources tool
        WHEN comparing its source type schema to incident tools
        THEN both advertise the same OpenAPI-generated values
        """
        type_schema = ListSourcesParams.model_json_schema()["properties"]["type"]
        enum_schema = next(option for option in type_schema["anyOf"] if "enum" in option)

        assert set(enum_schema["enum"]) == set(get_args(IncidentSourceTypeFilter))


class TestPrivateEndpointOnlyVocabulary:
    """Private-only filters expose audited canonical names rather than wire values."""

    @pytest.mark.parametrize("model", [ListIncidentsParams, CountIncidentsParams])
    def test_integration_schema_exposes_only_audited_names(self, model):
        """
        GIVEN the private endpoint's integration filter
        WHEN inspecting its MCP schema
        THEN it exposes only audited canonical names
        """
        assert _field_values(model, "integration") == set(get_args(IncidentIntegrationFilter))

    @pytest.mark.parametrize("model", [ListIncidentsParams, CountIncidentsParams])
    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("integration", "endpoints"),
            ("source_type", "gh_repository"),
        ],
    )
    def test_private_wire_values_are_rejected_at_validation(self, model, field, value):
        """
        GIVEN a private wire value or unsupported integration
        WHEN constructing public MCP tool parameters
        THEN Pydantic rejects it and identifies the filter field
        """
        with pytest.raises(ValidationError) as exc_info:
            model(**{field: [value]})

        assert field in str(exc_info.value)


class TestPrivateEndpointMappings:
    """Private endpoint adapters must cover every generated canonical value."""

    @pytest.mark.parametrize(
        ("generated_type", "mapping"),
        [
            (IncidentSeverityFilter, MCP_SEVERITY_VALUES),
            (IncidentSourceTypeFilter, MCP_SOURCE_TYPE_VALUES),
            (IncidentStatusFilter, MCP_STATUS_VALUES),
            (IncidentValidityFilter, MCP_VALIDITY_VALUES),
        ],
    )
    def test_mapping_is_exhaustive(self, generated_type, mapping):
        """
        GIVEN a generated public API vocabulary
        WHEN comparing it with the /incidents-for-mcp adapter
        THEN every canonical value has an intentional wire mapping
        """
        assert set(mapping) == set(get_args(generated_type))
