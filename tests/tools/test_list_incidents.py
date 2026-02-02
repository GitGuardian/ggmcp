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
        """
        params = ListIncidentsParams()

        assert params.validity == DEFAULT_VALIDITIES
        assert "valid" in params.validity
        assert "failed_to_check" in params.validity
        assert "no_checker" in params.validity
        assert "unknown" in params.validity
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
