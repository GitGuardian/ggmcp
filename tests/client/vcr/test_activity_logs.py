"""
VCR tests for GitGuardianClient incident activity-log methods.

These cover the read-only activity-log listings, which return both user notes
and system actions for an incident:
- list_incident_activity_logs (internal incidents)
- list_public_incident_activity_logs (public incidents)
"""

import pytest


def _assert_activity_log_entry(entry: dict, expected_incident_id: int) -> None:
    """Assert an entry matches the public activity-log envelope + content union."""
    assert entry["incident_id"] == expected_incident_id
    assert isinstance(entry["id"], int)
    assert {"id", "incident_id", "member", "api_token_id", "created_at", "updated_at", "content"} <= entry.keys()

    content = entry["content"]
    if content["type"] == "note":
        assert isinstance(content["comment"], str)
    else:
        assert content["type"] == "action"
        assert isinstance(content["content_key"], str)


class TestIncidentActivityLogs:
    """Tests for listing the activity log of an internal secret incident."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incident_activity_logs(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key and an internal incident with activity
        WHEN we list its activity log
        THEN we receive a standardized ListResponse of note/action entries
        """
        with use_cassette("test_list_incident_activity_logs"):
            result = await real_client.list_incident_activity_logs(21460)

            assert "data" in result
            assert "cursor" in result
            assert "has_more" in result

            entries = result["data"]
            assert entries, "expected at least one activity-log entry"
            for entry in entries:
                _assert_activity_log_entry(entry, expected_incident_id=21460)

            # This incident has more than one page of activity; the client
            # surfaces the next cursor so callers can paginate.
            assert result["has_more"] is True
            assert result["cursor"] is not None


class TestPublicIncidentActivityLogs:
    """Tests for listing the activity log of a public secret incident."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incident_activity_logs(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key and a public incident with a note and an action
        WHEN we list its activity log
        THEN we receive a standardized ListResponse mixing note and action entries
        """
        with use_cassette("test_list_public_incident_activity_logs"):
            result = await real_client.list_public_incident_activity_logs(3759)

            assert "data" in result
            assert "cursor" in result
            assert "has_more" in result

            entries = result["data"]
            assert entries, "expected at least one activity-log entry"
            for entry in entries:
                _assert_activity_log_entry(entry, expected_incident_id=3759)

            # The public incident's log mixes a user note and a system action.
            content_types = {entry["content"]["type"] for entry in entries}
            assert content_types == {"note", "action"}
