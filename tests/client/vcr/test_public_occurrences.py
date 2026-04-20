"""
VCR tests for GitGuardianClient public-occurrence methods.

These tests cover every query parameter of:
- list_public_occurrences(incident_id, ...)
"""

import pytest

# Placeholder incident used across cassettes. Replace during cassette recording
# with a real public incident id available on the recording workspace.
_INCIDENT_ID = 3759


async def _find_incident_with_occurrence_where(real_client, predicate):
    """Scan public incidents and return the first (incident_id, occurrence) pair
    whose first occurrence satisfies `predicate`. Returns (None, None) if not found.

    Used to discover a real value (sha, filepath, source id, etc.) before filtering,
    so the follow-up request hits actual data instead of fabricated IDs.
    """
    incidents = await real_client.list_public_incidents(per_page=20)
    for inc in incidents.get("data", []):
        if inc.get("occurrences_count", 0) == 0:
            continue
        occurrences = await real_client.list_public_occurrences(incident_id=inc["id"], per_page=5)
        for occ in occurrences.get("data", []):
            if predicate(occ):
                return inc["id"], occ
    return None, None


class TestListPublicOccurrences:
    """Tests for listing public secret occurrences with various filters."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_occurrences_basic(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key with incidents:read scope
        WHEN we request the list of occurrences for a public incident
        THEN we should receive a list response with occurrence data
        """
        with use_cassette("test_list_public_occurrences_basic"):
            result = await real_client.list_public_occurrences(incident_id=_INCIDENT_ID, per_page=5)

            assert result is not None
            assert "data" in result
            assert isinstance(result["data"], list)
            assert "cursor" in result
            assert "has_more" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_occurrences_with_date_filter(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public occurrences with a broad date_after window
        THEN occurrences are returned and all fall inside the window
        """
        with use_cassette("test_list_public_occurrences_with_date_filter"):
            cutoff = "2020-01-01T00:00:00Z"
            result = await real_client.list_public_occurrences(
                incident_id=_INCIDENT_ID,
                date_after=cutoff,
                per_page=5,
            )

            assert result["data"], "expected at least one occurrence for a broad date_after window"
            for occ in result["data"]:
                assert occ["date"] >= cutoff

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_occurrences_with_source_id(self, real_client, use_cassette):
        """
        GIVEN at least one public incident whose first occurrence has a source
        WHEN we filter occurrences by that real source_id
        THEN every returned occurrence shares that source
        """
        with use_cassette("test_list_public_occurrences_with_source_id"):
            incident_id, occ = await _find_incident_with_occurrence_where(
                real_client, lambda o: bool(o.get("source") and o["source"].get("id"))
            )
            if occ is None:
                pytest.skip("No public occurrence with a source available")
            source_id = occ["source"]["id"]

            result = await real_client.list_public_occurrences(
                incident_id=incident_id,
                source_id=source_id,
                per_page=5,
            )

            assert result["data"]
            for o in result["data"]:
                assert o["source"]["id"] == source_id

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_occurrences_with_presence(self, real_client, use_cassette):
        """
        GIVEN at least one public occurrence with presence=present
        WHEN we filter occurrences by presence=present on its parent incident
        THEN every returned occurrence has presence=present
        """
        with use_cassette("test_list_public_occurrences_with_presence"):
            incident_id, _ = await _find_incident_with_occurrence_where(
                real_client, lambda o: o.get("presence") == "present"
            )
            if incident_id is None:
                pytest.skip("No present public occurrence available")

            result = await real_client.list_public_occurrences(
                incident_id=incident_id,
                presence="present",
                per_page=5,
            )

            assert result["data"]
            for o in result["data"]:
                assert o["presence"] == "present"

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_occurrences_with_sha(self, real_client, use_cassette):
        """
        GIVEN a public occurrence with a commit sha
        WHEN we filter by a real sha prefix (>=3 chars)
        THEN every returned occurrence has a sha starting with that prefix
        """
        with use_cassette("test_list_public_occurrences_with_sha"):
            incident_id, occ = await _find_incident_with_occurrence_where(
                real_client, lambda o: bool(o.get("sha")) and len(o["sha"]) >= 3
            )
            if occ is None:
                pytest.skip("No public occurrence with a sha available")
            sha_prefix = occ["sha"][:10]

            result = await real_client.list_public_occurrences(
                incident_id=incident_id,
                sha=sha_prefix,
                per_page=5,
            )

            assert result["data"]
            for o in result["data"]:
                assert o["sha"].startswith(sha_prefix)

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_occurrences_with_filepath(self, real_client, use_cassette):
        """
        GIVEN a public occurrence with a filepath
        WHEN we filter by a real filepath substring (>=3 chars)
        THEN every returned occurrence has a matching filepath
        """
        with use_cassette("test_list_public_occurrences_with_filepath"):
            incident_id, occ = await _find_incident_with_occurrence_where(
                real_client, lambda o: bool(o.get("filepath")) and len(o["filepath"]) >= 3
            )
            if occ is None:
                pytest.skip("No public occurrence with a filepath available")
            filepath_needle = occ["filepath"][:20]

            result = await real_client.list_public_occurrences(
                incident_id=incident_id,
                filepath=filepath_needle,
                per_page=5,
            )

            assert result["data"]
            for o in result["data"]:
                assert filepath_needle in o["filepath"]

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_occurrences_with_attachment_reason(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public occurrences filtered by attachment_reason
        THEN we should receive occurrences (filter applied)
        """
        with use_cassette("test_list_public_occurrences_with_attachment_reason"):
            result = await real_client.list_public_occurrences(
                incident_id=_INCIDENT_ID,
                attachment_reason="by_dev_from_perimeter,on_github_org_in_perimeter",
                per_page=5,
            )

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_occurrences_with_severity(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public occurrences filtered by related-incident severity
        THEN we should receive occurrences (filter applied)
        """
        with use_cassette("test_list_public_occurrences_with_severity"):
            result = await real_client.list_public_occurrences(
                incident_id=_INCIDENT_ID,
                severity="critical,high",
                per_page=5,
            )

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_occurrences_with_status(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public occurrences filtered by related-incident status
        THEN we should receive occurrences (filter applied)
        """
        with use_cassette("test_list_public_occurrences_with_status"):
            result = await real_client.list_public_occurrences(
                incident_id=_INCIDENT_ID,
                status="TRIGGERED,ASSIGNED",
                per_page=5,
            )

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_occurrences_with_validity(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public occurrences filtered by related-secret validity
        THEN we should receive occurrences (filter applied)
        """
        with use_cassette("test_list_public_occurrences_with_validity"):
            result = await real_client.list_public_occurrences(
                incident_id=_INCIDENT_ID,
                validity="valid,invalid,no_checker",
                per_page=5,
            )

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_occurrences_with_tags(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public occurrences filtered by tags
        THEN we should receive occurrences (filter applied)
        """
        with use_cassette("test_list_public_occurrences_with_tags"):
            result = await real_client.list_public_occurrences(
                incident_id=_INCIDENT_ID,
                tags="FROM_HISTORICAL_SCAN,INTERNALLY_LEAKED",
                per_page=5,
            )

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_occurrences_with_ordering(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public occurrences ordered by -date
        THEN we should receive occurrences (ordering applied)
        """
        with use_cassette("test_list_public_occurrences_with_ordering"):
            result = await real_client.list_public_occurrences(
                incident_id=_INCIDENT_ID,
                ordering="-date",
                per_page=5,
            )

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_occurrences_with_cursor(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key and a public incident with several occurrences
        WHEN we request a first page, then pass the returned cursor on a second request
        THEN the second request succeeds (cursor honoured by the API)
        """
        with use_cassette("test_list_public_occurrences_with_cursor"):
            # Find an incident that actually has occurrences to paginate through.
            incidents = await real_client.list_public_incidents(per_page=20)
            incident_id = None
            for inc in incidents["data"]:
                if inc.get("occurrences_count", 0) > 1:
                    incident_id = inc["id"]
                    break
            if incident_id is None:
                pytest.skip("No public incident with multiple occurrences available")

            first = await real_client.list_public_occurrences(incident_id=incident_id, per_page=1)
            if not first.get("cursor"):
                pytest.skip("Not enough occurrences to test cursor pagination")

            result = await real_client.list_public_occurrences(
                incident_id=incident_id,
                cursor=first["cursor"],
                per_page=1,
            )

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_occurrences_get_all(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public occurrences with get_all=True
        THEN we should receive a PaginatedResult with data and has_more flag
        """
        with use_cassette("test_list_public_occurrences_get_all"):
            result = await real_client.list_public_occurrences(incident_id=_INCIDENT_ID, get_all=True, per_page=5)

            assert result is not None
            assert "data" in result
            assert isinstance(result["data"], list)
            assert "has_more" in result
            assert isinstance(result["has_more"], bool)
            assert "cursor" in result
