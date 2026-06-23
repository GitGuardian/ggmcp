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


class TestPublicIncidentNotes:
    """Tests for creating, editing and listing comments on public secret incidents."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_create_and_update_public_incident_note(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key and a public incident
        WHEN we create a comment and then edit it
        THEN the API echoes back the comment body in the `comment` field
        """
        with use_cassette("test_create_and_update_public_incident_note"):
            created = await real_client.create_public_incident_note(
                incident_id=3759, comment="Reported the leak to the actor"
            )
            assert created["comment"] == "Reported the leak to the actor"
            assert created["incident_id"] == 3759

            updated = await real_client.update_public_incident_note(
                incident_id=3759,
                note_id=created["id"],
                comment="Actor confirmed rotation",
            )
            assert updated["id"] == created["id"]
            assert updated["comment"] == "Actor confirmed rotation"

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incident_notes(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key and a public incident
        WHEN we list its comments
        THEN we receive a standardized ListResponse
        """
        with use_cassette("test_list_public_incident_notes"):
            result = await real_client.list_public_incident_notes(3759)

            assert "data" in result
            assert isinstance(result["data"], list)
            assert "cursor" in result
            assert "has_more" in result
