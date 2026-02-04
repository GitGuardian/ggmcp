"""
Tests for the list_incidents tool.
"""

from gg_api_core.tools.list_incidents import (
    DEFAULT_EXCLUDED_TAGS,
    DEFAULT_SEVERITIES,
    DEFAULT_STATUSES,
    DEFAULT_VALIDITIES,
    ListIncidentsParams,
    SeverityValues,
)


class TestListIncidentsParamsDefaults:
    """Tests for ListIncidentsParams default filters."""

    def test_default_status_excludes_ignored(self):
        """
        GIVEN: No status filter is specified
        WHEN: Creating ListIncidentsParams
        THEN: Default status excludes IGNORED (includes TRIGGERED, ASSIGNED, RESOLVED)
        """
        params = ListIncidentsParams()

        assert params.status == DEFAULT_STATUSES
        assert "TRIGGERED" in params.status
        assert "ASSIGNED" in params.status
        assert "RESOLVED" in params.status
        assert "IGNORED" not in params.status

    def test_default_severity_excludes_low_and_info(self):
        """
        GIVEN: No severity filter is specified
        WHEN: Creating ListIncidentsParams
        THEN: Default severity excludes LOW (40) and INFO (50)
        """
        params = ListIncidentsParams()

        assert params.severity == DEFAULT_SEVERITIES
        assert SeverityValues.CRITICAL in params.severity
        assert SeverityValues.HIGH in params.severity
        assert SeverityValues.MEDIUM in params.severity
        assert SeverityValues.UNKNOWN in params.severity
        assert SeverityValues.LOW not in params.severity
        assert SeverityValues.INFO not in params.severity

    def test_default_validity_excludes_invalid(self):
        """
        GIVEN: No validity filter is specified
        WHEN: Creating ListIncidentsParams
        THEN: Default validity excludes 'invalid'

        Note: /incidents-for-mcp endpoint uses 'not_checked' not 'unknown'
        """
        params = ListIncidentsParams()

        assert params.validity == DEFAULT_VALIDITIES
        assert "valid" in params.validity
        assert "failed_to_check" in params.validity
        assert "no_checker" in params.validity
        assert "not_checked" in params.validity
        assert "invalid" not in params.validity

    def test_default_exclude_tags_filters_noise(self):
        """
        GIVEN: No exclude_tags filter is specified
        WHEN: Creating ListIncidentsParams
        THEN: Default excludes TEST_FILE, FALSE_POSITIVE, and CHECK_RUN_SKIP_* tags
        """
        params = ListIncidentsParams()

        assert params.exclude_tags == DEFAULT_EXCLUDED_TAGS
        assert "TEST_FILE" in params.exclude_tags
        assert "FALSE_POSITIVE" in params.exclude_tags
        assert "CHECK_RUN_SKIP_FALSE_POSITIVE" in params.exclude_tags
        assert "CHECK_RUN_SKIP_LOW_RISK" in params.exclude_tags
        assert "CHECK_RUN_SKIP_TEST_CRED" in params.exclude_tags

    def test_can_override_default_status(self):
        """
        GIVEN: A custom status filter is specified
        WHEN: Creating ListIncidentsParams
        THEN: The custom status overrides the default
        """
        params = ListIncidentsParams(status=["IGNORED"])

        assert params.status == ["IGNORED"]

    def test_can_override_default_severity(self):
        """
        GIVEN: A custom severity filter is specified
        WHEN: Creating ListIncidentsParams
        THEN: The custom severity overrides the default
        """
        params = ListIncidentsParams(severity=[SeverityValues.LOW, SeverityValues.INFO])

        assert params.severity == [SeverityValues.LOW, SeverityValues.INFO]

    def test_can_override_default_validity(self):
        """
        GIVEN: A custom validity filter is specified
        WHEN: Creating ListIncidentsParams
        THEN: The custom validity overrides the default
        """
        params = ListIncidentsParams(validity=["invalid"])

        assert params.validity == ["invalid"]

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


class TestListIncidentsParamsOtherDefaults:
    """Tests for other default values in ListIncidentsParams."""

    def test_default_pagination(self):
        """
        GIVEN: No pagination parameters are specified
        WHEN: Creating ListIncidentsParams
        THEN: Default pagination is page=1, page_size=20, get_all=False
        """
        params = ListIncidentsParams()

        assert params.page == 1
        assert params.page_size == 20
        assert params.get_all is False

    def test_default_ordering(self):
        """
        GIVEN: No ordering is specified
        WHEN: Creating ListIncidentsParams
        THEN: Default ordering is '-date' (newest first)
        """
        params = ListIncidentsParams()

        assert params.ordering == "-date"

    def test_default_mine_is_false(self):
        """
        GIVEN: mine parameter is not specified
        WHEN: Creating ListIncidentsParams
        THEN: mine defaults to False (not filtering by current user)
        """
        params = ListIncidentsParams()

        assert params.mine is False


class TestListIncidentsParamsCoercion:
    """Tests for ListIncidentsParams coerce_to_list validator.

    LLMs often pass single values instead of lists for array parameters.
    These tests verify that single values are correctly coerced to lists.
    """

    def test_coerce_single_status_to_list(self):
        """
        GIVEN: A single status value (not a list)
        WHEN: Creating ListIncidentsParams
        THEN: The status is coerced to a list
        """
        params = ListIncidentsParams(status="TRIGGERED")

        assert params.status == ["TRIGGERED"]

    def test_coerce_single_severity_to_list(self):
        """
        GIVEN: A single severity value (not a list)
        WHEN: Creating ListIncidentsParams
        THEN: The severity is coerced to a list
        """
        params = ListIncidentsParams(severity=SeverityValues.CRITICAL)

        assert params.severity == [SeverityValues.CRITICAL]

    def test_coerce_single_validity_to_list(self):
        """
        GIVEN: A single validity value (not a list)
        WHEN: Creating ListIncidentsParams
        THEN: The validity is coerced to a list
        """
        params = ListIncidentsParams(validity="valid")

        assert params.validity == ["valid"]

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

    def test_coerce_single_presence_to_list(self):
        """
        GIVEN: A single presence value (not a list)
        WHEN: Creating ListIncidentsParams
        THEN: The presence is coerced to a list
        """
        params = ListIncidentsParams(presence="present")

        assert params.presence == ["present"]

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

    def test_coerce_single_source_type_to_list(self):
        """
        GIVEN: A single source_type value (not a list)
        WHEN: Creating ListIncidentsParams
        THEN: The source_type is coerced to a list
        """
        params = ListIncidentsParams(source_type="github")

        assert params.source_type == ["github"]

    def test_coerce_single_source_criticality_to_list(self):
        """
        GIVEN: A single source_criticality value (not a list)
        WHEN: Creating ListIncidentsParams
        THEN: The source_criticality is coerced to a list
        """
        params = ListIncidentsParams(source_criticality="critical")

        assert params.source_criticality == ["critical"]

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

    def test_coerce_preserves_list_input(self):
        """
        GIVEN: A list value for status
        WHEN: Creating ListIncidentsParams
        THEN: The list is preserved as-is
        """
        params = ListIncidentsParams(status=["TRIGGERED", "ASSIGNED"])

        assert params.status == ["TRIGGERED", "ASSIGNED"]

    def test_coerce_preserves_none_input(self):
        """
        GIVEN: None value for a list field
        WHEN: Creating ListIncidentsParams
        THEN: None is preserved (or default is applied if field has default)
        """
        params = ListIncidentsParams(detector_group_name=None)

        assert params.detector_group_name is None

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
