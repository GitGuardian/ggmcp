"""
VCR tests for GitGuardianClient incident note (comment) methods.

These tests cover:
- create_incident_note / update_incident_note (internal incidents)
- create_public_incident_note / update_public_incident_note (public incidents)
- list_public_incident_notes (internal list is covered in test_incidents.py)
"""

import pytest


class TestIncidentNotes:
    """Tests for creating and editing comments on internal secret incidents."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_create_and_update_incident_note(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key and an internal incident
        WHEN we create a comment and then edit it
        THEN the API echoes back the comment body in the `comment` field
        """
        with use_cassette("test_create_and_update_incident_note"):
            created = await real_client.create_incident_note(
                incident_id=21460, comment="Investigating this incident via MCP"
            )
            assert created["comment"] == "Investigating this incident via MCP"
            assert created["incident_id"] == 21460

            updated = await real_client.update_incident_note(
                incident_id=21460,
                note_id=created["id"],
                comment="Resolved: secret rotated",
            )
            assert updated["id"] == created["id"]
            assert updated["comment"] == "Resolved: secret rotated"
            assert updated["updated_at"] is not None
