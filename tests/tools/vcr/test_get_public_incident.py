"""
VCR tests for the get_public_incident tool.

These tests exercise the MCP tool wrapper (not just the low-level client) against
recorded HTTP interactions. Run with a valid GITGUARDIAN_API_KEY to record cassettes:
    make test-vcr-with-env
"""

from unittest.mock import patch

import pytest
from fastmcp.exceptions import ToolError
from gg_api_core.tools.get_public_incident import (
    GetPublicIncidentParams,
    GetPublicIncidentResult,
    get_public_incident,
)


class TestGetPublicIncidentVCR:
    """VCR tests for the get_public_incident tool."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_public_incident_basic(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key and at least one public incident on the workspace
        WHEN: Calling get_public_incident with that id
        THEN: The tool returns a GetPublicIncidentResult whose incident payload matches the id
            and carries the documented core fields (status, severity, validity, detector)
        """
        with use_cassette("test_get_public_incident_basic"):
            with patch(
                "gg_api_core.tools.get_public_incident.get_client",
                return_value=real_client,
            ):
                page = await real_client.list_public_incidents(per_page=1)
                if not page["data"]:
                    pytest.skip("No public incidents available on the recording workspace")
                incident_id = page["data"][0]["id"]

                result = await get_public_incident(GetPublicIncidentParams(incident_id=incident_id))

                assert isinstance(result, GetPublicIncidentResult)
                assert result.incident["id"] == incident_id
                # Core contract fields documented on GET /v1/public-incidents/secrets/{id}
                for key in ("status", "severity", "validity", "detector", "date", "occurrences_count"):
                    assert key in result.incident, f"missing {key} on public incident payload"

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_public_incident_unknown_id_raises(self, real_client, use_cassette):
        """
        GIVEN: An incident id that does not exist
        WHEN: Calling get_public_incident
        THEN: A ToolError is raised (wrapping the underlying 404)
        """
        with use_cassette("test_get_public_incident_unknown_id"):
            with patch(
                "gg_api_core.tools.get_public_incident.get_client",
                return_value=real_client,
            ):
                with pytest.raises(ToolError):
                    await get_public_incident(GetPublicIncidentParams(incident_id=999999999))
