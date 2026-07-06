from unittest.mock import AsyncMock, patch

import pytest
from gg_api_core.tools.list_remediation_targets import (
    ListRemediationTargetsParams,
    ListRemediationTargetsResult,
    ListRepoOccurrencesParamsForTargets,
    RemediationTarget,
    list_remediation_targets,
)
from gg_api_core.tools.list_repo_occurrences import (
    ListRepoOccurrencesError,
    ListRepoOccurrencesResult,
)


def _occurrence(occ_id, incident_id, filename, detector="AWS Access Key", **incident_extra):
    incident = {"id": incident_id, "detector": {"name": detector}, **incident_extra}
    return {
        "id": occ_id,
        "filepath": filename,
        "matches": [
            {
                "type": "apikey",
                "match": {
                    "filename": filename,
                    "line_start": 10,
                    "line_end": 10,
                    "index_start": 15,
                    "index_end": 35,
                },
            }
        ],
        "incident": incident,
    }


def _occurrences_result(occurrences, has_more=False):
    return ListRepoOccurrencesResult(
        occurrences=occurrences,
        occurrences_count=len(occurrences),
        cursor=None,
        has_more=has_more,
        applied_filters={},
        suggestion="",
    )


class TestListRemediationTargetsParams:
    """Tests for ListRemediationTargetsParams validation."""

    def test_params_with_source_id(self):
        params = ListRemediationTargetsParams(source_id="source_123")
        assert params.source_id == "source_123"
        assert params.incident_id is None

    def test_params_default_caps(self):
        params = ListRemediationTargetsParams()
        assert params.source_id is None
        assert params.max_incidents == 20
        assert params.max_occurrences_per_incident == 10
        assert params.list_repo_occurrences_params is not None

    def test_underlying_query_defaults_to_recent_first_default_branch(self):
        params = ListRemediationTargetsParams(source_id="source_123")
        assert params.list_repo_occurrences_params.ordering == "-date"
        assert params.list_repo_occurrences_params.tags == ["DEFAULT_BRANCH"]

    def test_params_with_nested_list_repo_occurrences_params(self):
        params = ListRemediationTargetsParams(
            source_id="source_123",
            list_repo_occurrences_params=ListRepoOccurrencesParamsForTargets(source_id="source_123", per_page=20),
        )
        assert params.list_repo_occurrences_params.per_page == 20
        assert params.list_repo_occurrences_params.source_id == "source_123"


class TestOverview:
    """Tests for the repo overview (no incident_id)."""

    @pytest.mark.asyncio
    async def test_groups_occurrences_by_incident(self, mock_gitguardian_client):
        """
        GIVEN: Occurrences spanning multiple incidents
        WHEN: Listing remediation targets
        THEN: They are grouped into one target per incident
        """
        occurrences = [
            _occurrence("occ_1", 101, "a.py"),
            _occurrence("occ_2", 101, "b.py"),
            _occurrence("occ_3", 202, "c.py", detector="Generic API Key"),
        ]

        with patch(
            "gg_api_core.tools.list_remediation_targets.list_repo_occurrences",
            AsyncMock(return_value=_occurrences_result(occurrences)),
        ):
            result = await list_remediation_targets(ListRemediationTargetsParams(source_id="source_123"))

        assert isinstance(result, ListRemediationTargetsResult)
        assert result.incident_count == 2
        assert result.total_incident_count == 2
        assert result.truncated is False

        by_id = {t.incident_id: t for t in result.incidents}
        assert by_id[101].occurrence_count_in_view == 2
        assert len(by_id[101].occurrences) == 2
        assert by_id[101].detector == "AWS Access Key"
        assert by_id[202].occurrence_count_in_view == 1
        assert by_id[202].detector == "Generic API Key"

    @pytest.mark.asyncio
    async def test_preserves_incident_order(self, mock_gitguardian_client):
        """
        GIVEN: Occurrences arriving most-recent-first
        WHEN: Grouping into incidents
        THEN: Incident order follows first appearance (i.e. most recent)
        """
        occurrences = [
            _occurrence("occ_1", 300, "a.py"),
            _occurrence("occ_2", 100, "b.py"),
            _occurrence("occ_3", 300, "c.py"),
        ]

        with patch(
            "gg_api_core.tools.list_remediation_targets.list_repo_occurrences",
            AsyncMock(return_value=_occurrences_result(occurrences)),
        ):
            result = await list_remediation_targets(ListRemediationTargetsParams(source_id="source_123"))

        assert [t.incident_id for t in result.incidents] == [300, 100]

    @pytest.mark.asyncio
    async def test_caps_occurrences_per_incident_and_flags_truncation(self, mock_gitguardian_client):
        """
        GIVEN: An incident with more occurrences than the per-incident cap
        WHEN: Listing remediation targets
        THEN: Occurrences are capped, the true count is reported, and truncation is flagged
        """
        occurrences = [_occurrence(f"occ_{i}", 101, f"f{i}.py") for i in range(5)]

        with patch(
            "gg_api_core.tools.list_remediation_targets.list_repo_occurrences",
            AsyncMock(return_value=_occurrences_result(occurrences)),
        ):
            result = await list_remediation_targets(
                ListRemediationTargetsParams(source_id="source_123", max_occurrences_per_incident=2)
            )

        target = result.incidents[0]
        assert target.occurrence_count_in_view == 5
        assert len(target.occurrences) == 2
        assert target.occurrences_truncated is True

    @pytest.mark.asyncio
    async def test_caps_number_of_incidents(self, mock_gitguardian_client):
        """
        GIVEN: More distinct incidents than max_incidents
        WHEN: Listing remediation targets
        THEN: Incidents are capped, total_incident_count reflects the true total, truncated=True
        """
        occurrences = [_occurrence(f"occ_{i}", 100 + i, f"f{i}.py") for i in range(5)]

        with patch(
            "gg_api_core.tools.list_remediation_targets.list_repo_occurrences",
            AsyncMock(return_value=_occurrences_result(occurrences)),
        ):
            result = await list_remediation_targets(
                ListRemediationTargetsParams(source_id="source_123", max_incidents=3)
            )

        assert result.incident_count == 3
        assert result.total_incident_count == 5
        assert result.truncated is True

    @pytest.mark.asyncio
    async def test_surfaces_total_occurrence_count_from_incident(self, mock_gitguardian_client):
        """
        GIVEN: The embedded incident reports a larger occurrences_count than what was fetched
        WHEN: Listing remediation targets
        THEN: total_occurrence_count reflects the incident's true total
        """
        occurrences = [_occurrence("occ_1", 101, "a.py", occurrences_count=42)]

        with patch(
            "gg_api_core.tools.list_remediation_targets.list_repo_occurrences",
            AsyncMock(return_value=_occurrences_result(occurrences)),
        ):
            result = await list_remediation_targets(ListRemediationTargetsParams(source_id="source_123"))

        assert result.incidents[0].total_occurrence_count == 42

    @pytest.mark.asyncio
    async def test_guidance_is_rotation_first(self, mock_gitguardian_client):
        """
        GIVEN: Incidents are found
        WHEN: Listing remediation targets
        THEN: The fallback guidance leads with rotation, defers to a skill,
              and gates history rewriting behind unpushed commits
        """
        with patch(
            "gg_api_core.tools.list_remediation_targets.list_repo_occurrences",
            AsyncMock(return_value=_occurrences_result([_occurrence("occ_1", 101, "a.py")])),
        ):
            result = await list_remediation_targets(ListRemediationTargetsParams(source_id="source_123"))

        guidance = result.guidance.lower()
        assert "rotate" in guidance
        assert guidance.index("rotate") < guidance.index("history")
        assert "skill" in guidance or "workflow" in guidance
        assert "pushed" in guidance

    @pytest.mark.asyncio
    async def test_no_incidents(self, mock_gitguardian_client):
        with patch(
            "gg_api_core.tools.list_remediation_targets.list_repo_occurrences",
            AsyncMock(return_value=_occurrences_result([])),
        ):
            result = await list_remediation_targets(ListRemediationTargetsParams(source_id="source_123"))

        assert result.incident_count == 0
        assert result.total_incident_count == 0
        assert "No secret incidents found" in result.guidance

    @pytest.mark.asyncio
    async def test_truncated_when_underlying_query_has_more(self, mock_gitguardian_client):
        with patch(
            "gg_api_core.tools.list_remediation_targets.list_repo_occurrences",
            AsyncMock(return_value=_occurrences_result([_occurrence("occ_1", 101, "a.py")], has_more=True)),
        ):
            result = await list_remediation_targets(ListRemediationTargetsParams(source_id="source_123"))

        assert result.truncated is True

    @pytest.mark.asyncio
    async def test_error_propagates(self, mock_gitguardian_client):
        with patch(
            "gg_api_core.tools.list_remediation_targets.list_repo_occurrences",
            AsyncMock(return_value=ListRepoOccurrencesError(error="API connection failed")),
        ):
            result = await list_remediation_targets(ListRemediationTargetsParams(source_id="source_123"))

        assert hasattr(result, "error")
        assert "API connection failed" in result.error
        assert "list_repo_occurrences" in result.sub_tools_results

    @pytest.mark.asyncio
    async def test_mine_filters_by_assignee(self, mock_gitguardian_client):
        occurrences = [
            _occurrence("occ_1", 101, "a.py", assignee_id="user1"),
            _occurrence("occ_2", 202, "b.py", assignee_id="user2"),
        ]
        mock_gitguardian_client.get_current_token_info = AsyncMock(return_value={"member_id": "user1"})

        with patch(
            "gg_api_core.tools.list_remediation_targets.list_repo_occurrences",
            AsyncMock(return_value=_occurrences_result(occurrences)),
        ):
            result = await list_remediation_targets(ListRemediationTargetsParams(source_id="source_123", mine=True))

        assert result.incident_count == 1
        assert result.incidents[0].incident_id == 101


class TestDrilldown:
    """Tests for single-incident drill-down (incident_id provided)."""

    @pytest.mark.asyncio
    async def test_returns_complete_occurrence_set(self, mock_gitguardian_client):
        """
        GIVEN: An incident_id
        WHEN: Listing remediation targets
        THEN: The single incident's complete occurrence set is returned via get_incident
        """
        incident = {
            "id": 101,
            "detector": {"display_name": "AWS Key", "name": "aws_key"},
            "severity": "high",
            "status": "TRIGGERED",
            "gitguardian_url": "https://dashboard/incidents/101",
            "occurrences_count": 3,
            "occurrences": [
                {"id": "occ_1", "filepath": "a.py"},
                {"id": "occ_2", "filepath": "b.py"},
                {"id": "occ_3", "filepath": "c.py"},
            ],
        }
        mock_gitguardian_client.get_incident = AsyncMock(return_value=incident)

        result = await list_remediation_targets(ListRemediationTargetsParams(source_id="source_123", incident_id=101))

        # get_incident was asked for the complete set (100), not the occurrences API
        mock_gitguardian_client.get_incident.assert_awaited_once_with(incident_id=101, with_occurrences=100)

        assert isinstance(result, ListRemediationTargetsResult)
        assert result.incident_count == 1
        target = result.incidents[0]
        assert target.incident_id == 101
        assert target.detector == "AWS Key"
        assert target.total_occurrence_count == 3
        assert target.occurrence_count_in_view == 3
        assert target.occurrences_truncated is False
        assert len(target.occurrences) == 3

    @pytest.mark.asyncio
    async def test_flags_truncation_when_incident_exceeds_100(self, mock_gitguardian_client):
        incident = {
            "id": 101,
            "detector": {"name": "aws_key"},
            "occurrences_count": 150,
            "occurrences": [{"id": f"occ_{i}"} for i in range(100)],
        }
        mock_gitguardian_client.get_incident = AsyncMock(return_value=incident)

        result = await list_remediation_targets(ListRemediationTargetsParams(incident_id=101))

        target = result.incidents[0]
        assert target.occurrence_count_in_view == 100
        assert target.total_occurrence_count == 150
        assert target.occurrences_truncated is True

    @pytest.mark.asyncio
    async def test_error_propagates(self, mock_gitguardian_client):
        mock_gitguardian_client.get_incident = AsyncMock(side_effect=Exception("boom"))

        result = await list_remediation_targets(ListRemediationTargetsParams(incident_id=999))

        assert hasattr(result, "error")
        assert "999" in result.error


class TestListRemediationTargetsResultSerialization:
    """Tests for ListRemediationTargetsResult Pydantic serialization."""

    def test_nested_targets_serialize(self):
        result = ListRemediationTargetsResult(
            guidance="Test guidance",
            incidents=[
                RemediationTarget(
                    incident_id=101,
                    detector="AWS Access Key",
                    occurrence_count_in_view=2,
                    total_occurrence_count=2,
                    occurrences=[{"id": "occ_1", "filepath": "a.py"}, {"id": "occ_2", "filepath": "b.py"}],
                )
            ],
            incident_count=1,
            total_incident_count=1,
        )

        serialized = result.model_dump()
        assert serialized["incident_count"] == 1
        incident = serialized["incidents"][0]
        assert incident["incident_id"] == 101
        assert incident["detector"] == "AWS Access Key"
        assert len(incident["occurrences"]) == 2
        assert incident["occurrences"][0]["id"] == "occ_1"

    def test_json_serialization(self):
        import json

        result = ListRemediationTargetsResult(
            guidance="Fix the secrets",
            incidents=[RemediationTarget(incident_id=101, occurrences=[{"id": "occ_1", "filepath": "secret.py"}])],
            incident_count=1,
            total_incident_count=1,
        )

        parsed = json.loads(result.model_dump_json())
        assert parsed["incidents"][0]["occurrences"][0]["id"] == "occ_1"
