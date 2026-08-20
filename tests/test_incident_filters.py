"""Parametrized tests for the shared incident-filter model, coercion and builders."""

import pytest
from gg_api_core.incident_filters import (
    DEFAULT_SEVERITIES,
    DEFAULT_STATUSES,
    DEFAULT_VALIDITIES,
    IncidentFilterParams,
    build_api_params,
    build_filter_info,
    coerce_to_list,
)
from gg_api_core.tools.count_incidents import CountIncidentsParams
from gg_api_core.tools.list_incidents import ListIncidentsParams


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, None),
        ("critical", ["critical"]),
        (["critical", "high"], ["critical", "high"]),
        ("critical, high, medium", ["critical", "high", "medium"]),
        ("a, b ,c", ["a", "b", "c"]),
        (["a", "b"], ["a", "b"]),
    ],
)
def test_coerce_to_list_shapes(raw, expected):
    """
    GIVEN a raw filter value of any accepted shape (None, scalar, list, CSV string)
    WHEN normalizing it with coerce_to_list
    THEN it becomes the canonical list (or None)
    """
    assert coerce_to_list(raw) == expected


@pytest.mark.parametrize(
    ("params_cls"),
    [ListIncidentsParams, CountIncidentsParams],
)
@pytest.mark.parametrize(
    ("field", "raw", "expected"),
    [
        ("severity", "critical,high", ["critical", "high"]),
        ("status", "TRIGGERED,ASSIGNED", ["TRIGGERED", "ASSIGNED"]),
        ("validity", "valid,unknown", ["valid", "unknown"]),
        ("integration", "github,gitlab", ["github", "gitlab"]),
        ("source_ids", "1, 2, 3", [1, 2, 3]),
        ("severity", "critical", ["critical"]),
        ("status", ["TRIGGERED", "IGNORED"], ["TRIGGERED", "IGNORED"]),
    ],
)
def test_csv_and_single_value_coercion_shared_by_list_and_count(params_cls, field, raw, expected):
    """
    GIVEN a single value, a list, or a comma-separated string for a list-shaped filter
    WHEN building either the list or the count tool params
    THEN the value is normalized to a canonical list, identically for both tools
    """
    params = params_cls(**{field: raw})
    assert getattr(params, field) == expected


@pytest.mark.parametrize(
    ("params_cls"),
    [ListIncidentsParams, CountIncidentsParams],
)
@pytest.mark.parametrize(
    ("field", "raw"),
    [
        ("severity", "bogus"),
        ("status", "OPENED"),
        ("validity", "not_checked"),
        ("source_type", "unknown"),
        ("integration", "ghe"),
        ("severity", "critical,bogus"),
    ],
)
def test_unsupported_enum_values_are_rejected_by_list_and_count(params_cls, field, raw):
    """
    GIVEN an unsupported canonical value for an enum-typed filter
    WHEN building the list or count tool params
    THEN pydantic raises a ValidationError naming the allowed values
    """
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc_info:
        params_cls(**{field: raw})
    assert field in str(exc_info.value)


@pytest.mark.parametrize("params_cls", [ListIncidentsParams, CountIncidentsParams])
def test_default_filters_shared_by_list_and_count(params_cls):
    """
    GIVEN no explicit filters
    WHEN building list or count params
    THEN both share the same canonical defaults
    """
    params = params_cls()
    assert params.status == DEFAULT_STATUSES
    assert params.severity == DEFAULT_SEVERITIES
    assert params.validity == DEFAULT_VALIDITIES


def test_build_api_params_maps_canonical_filters_to_wire_keys():
    """
    GIVEN a set of canonical filters
    WHEN building the /incidents-for-mcp query parameters
    THEN the shared builder emits the expected wire keys and values
    """
    params = IncidentFilterParams(
        status="TRIGGERED,ASSIGNED",
        severity="critical,unknown",
        validity="valid,unknown",
        source_type="github,gitlab",
        integration="github,github_enterprise_server,gitlab",
        exclude_tags="TEST_FILE,REGRESSION",
        occurrence_count_min=10,
    )
    api = build_api_params(params)
    assert api["status"] == ["TRIGGERED", "ASSIGNED"]
    assert api["severity"] == ["critical", "unknown"]
    assert api["validity"] == ["valid", "unknown"]
    assert api["source_type"] == ["github", "gitlab"]
    assert api["integration"] == ["github", "github_enterprise_server", "gitlab"]
    assert api["custom_filters"]["tags__nin"] == "TEST_FILE,REGRESSION"
    assert api["occurrence_count"] == ">=10"


def test_mine_conflict_is_kept_out_of_shared_builder():
    """
    GIVEN a mine flag is set (no resolved member id yet)
    WHEN building query params
    THEN the shared builder leaves mine resolution to the calling tool
    """
    params = IncidentFilterParams(mine=True)
    api = build_api_params(params)
    assert "mine" not in api
    assert "assignee_id" not in api


@pytest.mark.parametrize(
    ("field", "raw", "expected"),
    [
        ("status", "TRIGGERED", ["TRIGGERED"]),
        ("severity", "critical,high", ["critical", "high"]),
        ("source_ids", [1, 2], [1, 2]),
    ],
)
def test_build_filter_info_reflects_applied_filters(field, raw, expected):
    """
    GIVEN an applied filter
    WHEN building the applied_filters description
    THEN the canonical values are reported back
    """
    params = IncidentFilterParams(**{field: raw})
    info = build_filter_info(params)
    assert info[field] == expected
