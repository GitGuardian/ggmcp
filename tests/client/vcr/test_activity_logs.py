"""
VCR tests for GitGuardianClient incident activity-log methods.

These cover the read-only activity-log listings, which return both user notes
and system actions for an incident:
- list_incident_activity_logs (internal incidents)
- list_public_incident_activity_logs (public incidents)

NOTE: the /activity-logs endpoints are not deployed in production yet, so these
cassettes are hand-authored to match the public API response shape and cannot be
re-recorded against prod until the endpoints ship.
"""

import pytest


class TestIncidentActivityLogs:
    """Tests for listing the activity log of an internal secret incident."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_incident_activity_logs(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key and an internal incident with notes and actions
        WHEN we list its activity log
        THEN we receive a standardized ListResponse mixing note and action entries
        """
        with use_cassette("test_list_incident_activity_logs"):
            result = await real_client.list_incident_activity_logs(21460)

            assert "data" in result
            assert "cursor" in result
            assert "has_more" in result

            entries = result["data"]
            assert {entry["id"] for entry in entries} == {9001, 9002}
            assert all(entry["incident_id"] == 21460 for entry in entries)

            contents_by_id = {entry["id"]: entry["content"] for entry in entries}
            assert contents_by_id[9001] == {
                "type": "note",
                "comment": "Investigating this incident via MCP",
            }
            assert contents_by_id[9002]["type"] == "action"
            assert contents_by_id[9002]["content_key"] == "RESOLVE"


class TestPublicIncidentActivityLogs:
    """Tests for listing the activity log of a public secret incident."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incident_activity_logs(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key and a public incident with notes and actions
        WHEN we list its activity log
        THEN we receive a standardized ListResponse mixing note and action entries
        """
        with use_cassette("test_list_public_incident_activity_logs"):
            result = await real_client.list_public_incident_activity_logs(3759)

            assert "data" in result
            assert "cursor" in result
            assert "has_more" in result

            entries = result["data"]
            assert {entry["id"] for entry in entries} == {7101, 7102}
            assert all(entry["incident_id"] == 3759 for entry in entries)

            note_entry = next(e for e in entries if e["content"]["type"] == "note")
            assert note_entry["content"]["comment"] == "Reported the leak to the actor"

            action_entry = next(e for e in entries if e["content"]["type"] == "action")
            assert action_entry["content"]["content_key"] == "TRIGGER"
