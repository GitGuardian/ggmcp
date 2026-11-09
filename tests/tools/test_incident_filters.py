"""Public schema guarantees for the shared internal-incident filters."""

import typing

import pytest

from gg_api_core.tools.count_incidents import CountIncidentsParams
from gg_api_core.tools.incident_filters import IncidentFilters
from gg_api_core.tools.list_incidents import ListIncidentsParams


def _list_filters():
    for name, field in IncidentFilters.model_fields.items():
        for arg in typing.get_args(field.annotation):
            if typing.get_origin(arg) is list:
                item_type = typing.get_args(arg)[0]
                yield pytest.param(name, 1 if item_type is int else "x", id=name)
                break


@pytest.mark.parametrize(("field", "value"), list(_list_filters()))
def test_every_list_filter_accepts_a_single_value(field, value):
    """
    GIVEN a single value for a list filter, as LLM callers often send
    WHEN the shared incident filters are validated
    THEN the value becomes a one-item list
    """
    assert getattr(IncidentFilters(**{field: value}), field) == [value]


def test_list_and_count_preserve_their_tool_specific_schemas():
    """
    GIVEN shared incident filter definitions
    WHEN the two public input schemas are generated
    THEN list keeps pagination and its three distinct field descriptions
    """
    list_schema = ListIncidentsParams.model_json_schema()
    count_schema = CountIncidentsParams.model_json_schema()
    list_fields = list_schema["properties"]
    count_fields = count_schema["properties"]
    assert list_schema["title"] == "ListIncidentsParams"
    assert count_schema["title"] == "CountIncidentsParams"
    assert list_fields.keys() - count_fields.keys() == {"page", "page_size", "get_all", "ordering"}
    assert list(list_fields)[:4] == ["page", "page_size", "get_all", "ordering"]
    assert not count_fields.keys() - list_fields.keys()

    descriptions = {
        "status": (
            "Filter by status. Values: TRIGGERED (unassigned active), ASSIGNED (assigned active), RESOLVED, IGNORED. Default excludes IGNORED.",
            " Note that OPENED is not a valid status but means 'TRIGGERED OR ASSIGNED'.",
        ),
        "score_min": (
            "Filter incidents with a score greater than or equal to this value (0-100).",
            " Higher scores indicate higher priority incidents.",
        ),
    }
    for name, (common_description, list_suffix) in descriptions.items():
        assert count_fields[name]["description"] == common_description
        assert list_fields[name]["description"] == common_description + list_suffix
    assert count_fields["mine"]["description"] == (
        "If True, count only incidents assigned to the current user. Overrides assignee_id."
    )
    assert list_fields["mine"]["description"] == (
        "If True, fetch only incidents assigned to the current user. Overrides assignee_id."
    )
    for name, field in count_fields.items():
        if name not in {"status", "mine", "score_min"}:
            assert list_fields[name] == field
