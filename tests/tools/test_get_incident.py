import pytest

from gg_api_core.tools.get_incident import GetIncidentParams


class TestGetIncident:
    """Tests for the get_incident tool."""

    def test_get_incident_params_validation(self):
        """
        GIVEN: Invalid parameter values
        WHEN: Creating GetIncidentParams
        THEN: Validation errors are raised
        """
        # with_occurrences below minimum
        with pytest.raises(ValueError):
            GetIncidentParams(incident_id=1, with_occurrences=-1)

        # with_occurrences above maximum
        with pytest.raises(ValueError):
            GetIncidentParams(incident_id=1, with_occurrences=101)
