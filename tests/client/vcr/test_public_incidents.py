"""
VCR tests for GitGuardianClient public-incident methods.

These tests cover every query parameter of:
- list_public_incidents(...)
- get_public_incident(incident_id)
- assign_public_incident(incident_id, ...)
- resolve_public_incident(incident_id, resolve_reason)
- ignore_public_incident(incident_id, ignore_reason)
- reopen_public_incident(incident_id)
"""

import pytest


class TestGetPublicIncident:
    """Tests for retrieving a single public secret incident."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_get_public_incident_returns_same_id(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key and at least one public incident
        WHEN we retrieve it by id via get_public_incident
        THEN the returned payload's id matches and carries the documented core fields
        """
        with use_cassette("test_get_public_incident_returns_same_id"):
            page = await real_client.list_public_incidents(per_page=1)
            if not page["data"]:
                pytest.skip("No public incidents available")
            incident_id = page["data"][0]["id"]

            result = await real_client.get_public_incident(incident_id=incident_id)

            assert result["id"] == incident_id
            for key in ("status", "severity", "validity", "detector", "date", "occurrences_count"):
                assert key in result


class TestListPublicIncidents:
    """Tests for listing public secret incidents with various filters."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_basic(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key with incidents:read scope
        WHEN we request the list of public incidents
        THEN we should receive a list response with incident data
        """
        with use_cassette("test_list_public_incidents_basic"):
            result = await real_client.list_public_incidents(per_page=5)

            assert result is not None
            assert "data" in result
            assert isinstance(result["data"], list)
            assert "cursor" in result
            assert "has_more" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_with_status_filter(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public incidents with status=TRIGGERED
        THEN we should receive only triggered incidents
        """
        with use_cassette("test_list_public_incidents_with_status_filter"):
            result = await real_client.list_public_incidents(status="TRIGGERED", per_page=5)

            assert result is not None
            for incident in result["data"]:
                assert incident.get("status") == "TRIGGERED"

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_with_severity_filter(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public incidents with severity=high
        THEN we should receive incidents (filter applied)
        """
        with use_cassette("test_list_public_incidents_with_severity_filter"):
            result = await real_client.list_public_incidents(severity="high", per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_with_validity_filter(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public incidents with validity=valid
        THEN we should receive incidents (filter applied)
        """
        with use_cassette("test_list_public_incidents_with_validity_filter"):
            result = await real_client.list_public_incidents(validity="valid", per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_multi_value_status(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public incidents with status=[TRIGGERED, ASSIGNED] (multi-value filter)
        THEN the API accepts comma-separated values and every returned incident has one of those statuses
        """
        with use_cassette("test_list_public_incidents_multi_value_status"):
            result = await real_client.list_public_incidents(
                status=["TRIGGERED", "ASSIGNED"],
                per_page=20,
            )

            assert result is not None
            assert "data" in result
            for incident in result["data"]:
                assert incident.get("status") in {"TRIGGERED", "ASSIGNED"}

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_multi_value_severity(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public incidents with severity=[critical, high] (multi-value filter)
        THEN the API accepts comma-separated values and every returned incident has one of those severities
        """
        with use_cassette("test_list_public_incidents_multi_value_severity"):
            result = await real_client.list_public_incidents(
                severity=["critical", "high"],
                per_page=20,
            )

            assert result is not None
            assert "data" in result
            for incident in result["data"]:
                assert incident.get("severity") in {"critical", "high"}

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_multi_value_validity(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public incidents with validity=[valid, failed_to_check] (multi-value filter)
        THEN the API accepts comma-separated values and every returned incident has one of those validities
        """
        with use_cassette("test_list_public_incidents_multi_value_validity"):
            result = await real_client.list_public_incidents(
                validity=["valid", "failed_to_check"],
                per_page=20,
            )

            assert result is not None
            assert "data" in result
            for incident in result["data"]:
                assert incident.get("validity") in {"valid", "failed_to_check"}

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_with_date_filter(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public incidents within a date range
        THEN we should receive incidents (filter applied)
        """
        with use_cassette("test_list_public_incidents_with_date_filter"):
            result = await real_client.list_public_incidents(
                date_before="2026-01-01T00:00:00Z",
                date_after="2024-01-01T00:00:00Z",
                per_page=5,
            )

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_with_triggered_at_filter(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public incidents with triggered_at date bounds
        THEN we should receive incidents (filter applied)
        """
        with use_cassette("test_list_public_incidents_with_triggered_at_filter"):
            result = await real_client.list_public_incidents(
                triggered_at_before="2026-01-01T00:00:00Z",
                triggered_at_after="2024-01-01T00:00:00Z",
                per_page=5,
            )

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_with_assignee_filter(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key and at least one incident that has an assignee
        WHEN we filter by that assignee's id
        THEN every returned incident is assigned to that user
        """
        with use_cassette("test_list_public_incidents_with_assignee_filter"):
            page = await real_client.list_public_incidents(
                status="ASSIGNED",
                per_page=20,
            )
            assignee_id = next(
                (inc["assignee_id"] for inc in page["data"] if inc.get("assignee_id")),
                None,
            )
            if assignee_id is None:
                pytest.skip("No public incident with an assignee available to exercise the filter")

            result = await real_client.list_public_incidents(assignee_id=assignee_id, per_page=5)

            assert result["data"], "expected at least one incident for a known assignee"
            for inc in result["data"]:
                assert inc["assignee_id"] == assignee_id

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_with_tags_filter(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key and at least one tagged public incident
        WHEN we filter by a real tag value observed on that incident
        THEN every returned incident carries the filter tag
        """
        with use_cassette("test_list_public_incidents_with_tags_filter"):
            page = await real_client.list_public_incidents(per_page=20)
            known_tag = next(
                (tag for inc in page["data"] for tag in (inc.get("tags") or [])),
                None,
            )
            if known_tag is None:
                pytest.skip("No tagged public incident available to exercise the tags filter")

            result = await real_client.list_public_incidents(tags=known_tag, per_page=5)

            assert result["data"], f"expected at least one incident with tag {known_tag}"
            for inc in result["data"]:
                assert known_tag in (inc.get("tags") or [])

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_with_detector_group_name(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public incidents filtered by detector group name
        THEN we should receive incidents (filter applied)
        """
        with use_cassette("test_list_public_incidents_with_detector_group_name"):
            result = await real_client.list_public_incidents(
                detector_group_name="slackbot_token",
                per_page=5,
            )

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_with_ignorer_filter(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key and at least one incident ignored by a real user
        WHEN we filter by that user's ignorer_id
        THEN every returned incident was ignored by that user
        """
        with use_cassette("test_list_public_incidents_with_ignorer_filter"):
            page = await real_client.list_public_incidents(status="IGNORED", per_page=20)
            ignorer_id = next(
                (inc["ignorer_id"] for inc in page["data"] if inc.get("ignorer_id")),
                None,
            )
            if ignorer_id is None:
                pytest.skip("No public incident with an ignorer available")

            result = await real_client.list_public_incidents(ignorer_id=ignorer_id, per_page=5)

            assert result["data"]
            for inc in result["data"]:
                assert inc["ignorer_id"] == ignorer_id

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_with_resolver_filter(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key and at least one incident resolved by a real user
        WHEN we filter by that user's resolver_id
        THEN every returned incident was resolved by that user
        """
        with use_cassette("test_list_public_incidents_with_resolver_filter"):
            page = await real_client.list_public_incidents(status="RESOLVED", per_page=20)
            resolver_id = next(
                (inc["resolver_id"] for inc in page["data"] if inc.get("resolver_id")),
                None,
            )
            if resolver_id is None:
                pytest.skip("No public incident with a resolver available")

            result = await real_client.list_public_incidents(resolver_id=resolver_id, per_page=5)

            assert result["data"]
            for inc in result["data"]:
                assert inc["resolver_id"] == resolver_id

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_with_feedback(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public incidents filtered by feedback=True
        THEN we should receive incidents (filter applied)
        """
        with use_cassette("test_list_public_incidents_with_feedback"):
            result = await real_client.list_public_incidents(feedback=True, per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_with_declarative_secret_status(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public incidents filtered by declarative secret status
        THEN we should receive incidents (filter applied)
        """
        with use_cassette("test_list_public_incidents_with_declarative_secret_status"):
            result = await real_client.list_public_incidents(
                declarative_secret_status="revoked",
                per_page=5,
            )

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_with_risk_score(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public incidents with risk score bounds
        THEN we should receive incidents (filter applied)
        """
        with use_cassette("test_list_public_incidents_with_risk_score"):
            result = await real_client.list_public_incidents(
                risk_score_min=50,
                risk_score_max=100,
                per_page=5,
            )

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_with_ordering(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public incidents ordered by -risk_score
        THEN we should receive incidents (ordering applied)
        """
        with use_cassette("test_list_public_incidents_with_ordering"):
            result = await real_client.list_public_incidents(ordering="-risk_score", per_page=5)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_with_cursor(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request a first page, then pass the returned cursor on a second request
        THEN the second request succeeds (cursor honoured by the API)
        """
        with use_cassette("test_list_public_incidents_with_cursor"):
            first = await real_client.list_public_incidents(per_page=1)
            if not first.get("cursor"):
                pytest.skip("Not enough public incidents to test cursor pagination")

            result = await real_client.list_public_incidents(cursor=first["cursor"], per_page=1)

            assert result is not None
            assert "data" in result

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_public_incidents_get_all(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key
        WHEN we request public incidents with get_all=True
        THEN we should receive a PaginatedResult with data and has_more flag
        """
        with use_cassette("test_list_public_incidents_get_all"):
            result = await real_client.list_public_incidents(get_all=True, per_page=5)

            assert result is not None
            assert "data" in result
            assert isinstance(result["data"], list)
            assert "has_more" in result
            assert isinstance(result["has_more"], bool)
            assert "cursor" in result


class TestAssignPublicIncident:
    """Tests for assigning a public secret incident to a workspace member."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_assign_public_incident_by_member_id(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key with incidents:write scope and a public incident
        WHEN we assign it to a member by member_id
        THEN the API returns the updated incident with assignee_id set to that member
        """
        with use_cassette("test_assign_public_incident_by_member_id"):
            token_info = await real_client.get_current_token_info()
            assignee_id = token_info["member_id"]

            page = await real_client.list_public_incidents(per_page=1)
            if not page["data"]:
                pytest.skip("No public incidents available")
            incident_id = page["data"][0]["id"]

            result = await real_client.assign_public_incident(
                incident_id=incident_id,
                assignee_id=assignee_id,
            )

            assert result["id"] == incident_id
            assert result["assignee_id"] == assignee_id

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_assign_public_incident_by_email(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key and a public incident
        WHEN we assign it by email
        THEN the API resolves the member and returns the incident with the right assignee_email
        """
        with use_cassette("test_assign_public_incident_by_email"):
            token_info = await real_client.get_current_token_info()
            current_member = await real_client.get_current_member()
            email = current_member["email"]

            page = await real_client.list_public_incidents(per_page=1)
            if not page["data"]:
                pytest.skip("No public incidents available")
            incident_id = page["data"][0]["id"]

            result = await real_client.assign_public_incident(
                incident_id=incident_id,
                email=email,
            )

            assert result["id"] == incident_id
            assert result["assignee_email"] == email
            assert result["assignee_id"] == token_info["member_id"]

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_assign_public_incident_send_email_false(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key and a public incident
        WHEN we assign it with send_email=False
        THEN the assignment succeeds (the API accepts the query parameter)
        """
        with use_cassette("test_assign_public_incident_send_email_false"):
            token_info = await real_client.get_current_token_info()
            assignee_id = token_info["member_id"]

            page = await real_client.list_public_incidents(per_page=1)
            if not page["data"]:
                pytest.skip("No public incidents available")
            incident_id = page["data"][0]["id"]

            result = await real_client.assign_public_incident(
                incident_id=incident_id,
                assignee_id=assignee_id,
                send_email=False,
            )

            assert result["id"] == incident_id
            assert result["assignee_id"] == assignee_id

    @pytest.mark.asyncio
    async def test_assign_public_incident_rejects_both_email_and_id(self, real_client):
        """
        GIVEN a real client
        WHEN we call assign_public_incident with both email and assignee_id
        THEN a ValueError is raised before any HTTP call is made
        """
        with pytest.raises(ValueError, match="either email or assignee_id"):
            await real_client.assign_public_incident(
                incident_id=1,
                assignee_id=42,
                email="user@example.com",
            )

    @pytest.mark.asyncio
    async def test_assign_public_incident_rejects_neither_email_nor_id(self, real_client):
        """
        GIVEN a real client
        WHEN we call assign_public_incident without an assignee
        THEN a ValueError is raised before any HTTP call is made
        """
        with pytest.raises(ValueError, match="either email or assignee_id"):
            await real_client.assign_public_incident(incident_id=1)


class TestResolvePublicIncident:
    """Tests for resolving a public secret incident."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_resolve_public_incident_with_revoked(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key with incidents:write scope and an open public incident
        WHEN we resolve it with resolve_reason='revoked'
        THEN the API returns the updated incident with status=RESOLVED
        """
        with use_cassette("test_resolve_public_incident_with_revoked"):
            page = await real_client.list_public_incidents(status="TRIGGERED", per_page=1)
            if not page["data"]:
                pytest.skip("No open public incident available to resolve")
            incident_id = page["data"][0]["id"]

            result = await real_client.resolve_public_incident(
                incident_id=incident_id,
                resolve_reason="revoked",
            )

            assert result["id"] == incident_id
            assert result["status"] == "RESOLVED"
            assert result["resolve_reason"] == "revoked"


class TestIgnorePublicIncident:
    """Tests for ignoring a public secret incident."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_ignore_public_incident_with_test_credential(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key with incidents:write scope and an open public incident
        WHEN we ignore it with ignore_reason='test_credential'
        THEN the API returns the updated incident with status=IGNORED
        """
        with use_cassette("test_ignore_public_incident_with_test_credential"):
            page = await real_client.list_public_incidents(status="TRIGGERED", per_page=1)
            if not page["data"]:
                pytest.skip("No open public incident available to ignore")
            incident_id = page["data"][0]["id"]

            result = await real_client.ignore_public_incident(
                incident_id=incident_id,
                ignore_reason="test_credential",
            )

            assert result["id"] == incident_id
            assert result["status"] == "IGNORED"
            assert result["ignore_reason"] == "test_credential"


class TestReopenPublicIncident:
    """Tests for reopening a public secret incident."""

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_reopen_public_incident(self, real_client, use_cassette):
        """
        GIVEN a valid GitGuardian API key and a public incident that was previously
              resolved or ignored
        WHEN we reopen it via reopen_public_incident
        THEN the API returns the updated incident with status=TRIGGERED
        """
        with use_cassette("test_reopen_public_incident"):
            page = await real_client.list_public_incidents(status=["RESOLVED", "IGNORED"], per_page=1)
            if not page["data"]:
                pytest.skip("No resolved or ignored public incident available to reopen")
            incident_id = page["data"][0]["id"]

            result = await real_client.reopen_public_incident(incident_id=incident_id)

            assert result["id"] == incident_id
            assert result["status"] == "TRIGGERED"
