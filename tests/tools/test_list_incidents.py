"""
Tests for the list_incidents tool.
"""

from gg_api_core.tools.list_incidents import (
    ListIncidentsParams,
    SeverityValues,
)


class TestListIncidentsParamsDefaults:
    """Tests for ListIncidentsParams default filters."""

    def test_can_override_default_exclude_tags_with_empty_list(self):
        """
        GIVEN: An empty exclude_tags list is specified
        WHEN: Creating ListIncidentsParams
        THEN: No tags are excluded (empty list)
        """
        params = ListIncidentsParams(exclude_tags=[])

        assert params.exclude_tags == []

    def test_can_override_default_exclude_tags_with_custom_tags(self):
        """
        GIVEN: A custom exclude_tags list is specified
        WHEN: Creating ListIncidentsParams
        THEN: The custom tags override the default
        """
        params = ListIncidentsParams(exclude_tags=["CUSTOM_TAG"])

        assert params.exclude_tags == ["CUSTOM_TAG"]


class TestListIncidentsParamsCoercion:
    """Tests for ListIncidentsParams coerce_to_list validator.

    LLMs often pass single values instead of lists for array parameters.
    These tests verify that single values are correctly coerced to lists.
    """

    def test_coerce_single_detector_group_name_to_list(self):
        """
        GIVEN: A single detector_group_name value (not a list)
        WHEN: Creating ListIncidentsParams
        THEN: The detector_group_name is coerced to a list
        """
        params = ListIncidentsParams(detector_group_name="AWS Keys")

        assert params.detector_group_name == ["AWS Keys"]

    def test_coerce_single_source_ids_to_list(self):
        """
        GIVEN: A single source_ids value (not a list)
        WHEN: Creating ListIncidentsParams
        THEN: The source_ids is coerced to a list
        """
        params = ListIncidentsParams(source_ids=123)

        assert params.source_ids == [123]

    def test_coerce_single_tags_to_list(self):
        """
        GIVEN: A single tags value (not a list)
        WHEN: Creating ListIncidentsParams
        THEN: The tags is coerced to a list
        """
        params = ListIncidentsParams(tags="REGRESSION")

        assert params.tags == ["REGRESSION"]

    def test_coerce_single_exclude_tags_to_list(self):
        """
        GIVEN: A single exclude_tags value (not a list)
        WHEN: Creating ListIncidentsParams
        THEN: The exclude_tags is coerced to a list
        """
        params = ListIncidentsParams(exclude_tags="TEST_FILE")

        assert params.exclude_tags == ["TEST_FILE"]

    def test_coerce_single_teams_to_list(self):
        """
        GIVEN: A single teams value (not a list)
        WHEN: Creating ListIncidentsParams
        THEN: The teams is coerced to a list
        """
        params = ListIncidentsParams(teams=1)

        assert params.teams == [1]

    def test_coerce_single_custom_tags_to_list(self):
        """
        GIVEN: A single custom_tags value (not a list)
        WHEN: Creating ListIncidentsParams
        THEN: The custom_tags is coerced to a list
        """
        params = ListIncidentsParams(custom_tags=42)

        assert params.custom_tags == [42]

    def test_coerce_single_secret_manager_type_to_list(self):
        """
        GIVEN: A single secret_manager_type value (not a list)
        WHEN: Creating ListIncidentsParams
        THEN: The secret_manager_type is coerced to a list
        """
        params = ListIncidentsParams(secret_manager_type="hashicorpvault")

        assert params.secret_manager_type == ["hashicorpvault"]

    def test_coerce_single_public_exposure_to_list(self):
        """
        GIVEN: A single public_exposure value (not a list)
        WHEN: Creating ListIncidentsParams
        THEN: The public_exposure is coerced to a list
        """
        params = ListIncidentsParams(public_exposure="source_publicly_visible")

        assert params.public_exposure == ["source_publicly_visible"]

    def test_coerce_single_integration_to_list(self):
        """
        GIVEN: A single integration value (not a list)
        WHEN: Creating ListIncidentsParams
        THEN: The integration is coerced to a list
        """
        params = ListIncidentsParams(integration="github")

        assert params.integration == ["github"]

    def test_coerce_single_issue_tracker_to_list(self):
        """
        GIVEN: A single issue_tracker value (not a list)
        WHEN: Creating ListIncidentsParams
        THEN: The issue_tracker is coerced to a list
        """
        params = ListIncidentsParams(issue_tracker="jira_cloud_notifier")

        assert params.issue_tracker == ["jira_cloud_notifier"]

    def test_coerce_single_analyzer_status_to_list(self):
        """
        GIVEN: A single analyzer_status value (not a list)
        WHEN: Creating ListIncidentsParams
        THEN: The analyzer_status is coerced to a list
        """
        params = ListIncidentsParams(analyzer_status="checked")

        assert params.analyzer_status == ["checked"]

    def test_coerce_single_nhi_env_to_list(self):
        """
        GIVEN: A single nhi_env value (not a list)
        WHEN: Creating ListIncidentsParams
        THEN: The nhi_env is coerced to a list
        """
        params = ListIncidentsParams(nhi_env="production")

        assert params.nhi_env == ["production"]

    def test_coerce_single_nhi_policy_to_list(self):
        """
        GIVEN: A single nhi_policy value (not a list)
        WHEN: Creating ListIncidentsParams
        THEN: The nhi_policy is coerced to a list
        """
        params = ListIncidentsParams(nhi_policy="rotation_required")

        assert params.nhi_policy == ["rotation_required"]

    def test_coerce_single_secret_scope_to_list(self):
        """
        GIVEN: A single secret_scope value (not a list)
        WHEN: Creating ListIncidentsParams
        THEN: The secret_scope is coerced to a list
        """
        params = ListIncidentsParams(secret_scope="my_scope")

        assert params.secret_scope == ["my_scope"]

    def test_coerce_multiple_single_values(self):
        """
        GIVEN: Multiple single values (not lists) passed to various fields
        WHEN: Creating ListIncidentsParams
        THEN: All values are coerced to lists

        This is the most realistic LLM tool call scenario.
        """
        params = ListIncidentsParams(
            status="TRIGGERED",
            severity=SeverityValues.CRITICAL,
            validity="valid",
            presence="present",
            source_type="github",
            source_criticality="high",
        )

        assert params.status == ["TRIGGERED"]
        assert params.severity == [SeverityValues.CRITICAL]
        assert params.validity == ["valid"]
        assert params.presence == ["present"]
        assert params.source_type == ["github"]
        assert params.source_criticality == ["high"]
