"""
Tests that every incident filter tool exposes the same strict filter vocabularies.
"""

import pytest
from gg_api_core.tools.count_incidents import CountIncidentsParams
from gg_api_core.tools.list_incidents import ListIncidentsParams
from gg_api_core.tools.list_repo_occurrences import ListRepoOccurrencesParams
from pydantic import BaseModel, ValidationError

CANONICAL_VALIDITIES = ["failed_to_check", "invalid", "no_checker", "unknown", "valid"]

PARAMS_MODELS = [ListIncidentsParams, CountIncidentsParams, ListRepoOccurrencesParams]


def _validity_values(model: type[BaseModel]) -> list[str]:
    """Extract the validity values a params model accepts from its JSON schema."""
    field_schema = model.model_json_schema()["properties"]["validity"]
    array_schema = next(option for option in field_schema["anyOf"] if option.get("type") == "array")
    return sorted(array_schema["items"]["enum"])


class TestValidityVocabulary:
    """The three tools must advertise one validity vocabulary: the public API's."""

    @pytest.mark.parametrize("model", PARAMS_MODELS)
    def test_schema_exposes_the_canonical_vocabulary(self, model):
        """
        GIVEN: A tool exposing a validity filter
        WHEN: Inspecting its JSON schema
        THEN: Exactly the canonical validity values are allowed
        """
        assert _validity_values(model) == CANONICAL_VALIDITIES

    def test_all_tools_agree_on_the_vocabulary(self):
        """
        GIVEN: The three tools that filter on validity
        WHEN: Comparing their schemas
        THEN: They document the same values, so a value valid for one is valid for all
        """
        vocabularies = {model.__name__: _validity_values(model) for model in PARAMS_MODELS}

        assert len(set(map(tuple, vocabularies.values()))) == 1, vocabularies

    @pytest.mark.parametrize("model", PARAMS_MODELS)
    @pytest.mark.parametrize("value", ["nonsense", "not_checked", "NOT_CHECKED"])
    def test_invalid_validity_is_rejected_and_error_names_allowed_values(self, model, value):
        """
        GIVEN: A validity value outside the canonical vocabulary
        WHEN: Building the tool's params
        THEN: Validation fails and the error names every allowed value

        'not_checked' is the /incidents-for-mcp dialect, never a caller-facing value.
        """
        with pytest.raises(ValidationError) as exc_info:
            model(validity=[value])

        message = str(exc_info.value)
        for allowed in CANONICAL_VALIDITIES:
            assert allowed in message
