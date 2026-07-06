from unittest.mock import AsyncMock, patch

import pytest
from gg_api_core.tools.list_remediation_targets import (
    ListRemediationTargetsParams,
    ListRemediationTargetsResult,
    ListRepoOccurrencesParamsForTargets,
    list_remediation_targets,
)
from gg_api_core.tools.list_repo_occurrences import (
    ListRepoOccurrencesError,
    ListRepoOccurrencesResult,
)


class TestListRemediationTargetsParams:
    """Tests for ListRemediationTargetsParams validation."""

    def test_params_with_source_id(self):
        """
        GIVEN: ListRemediationTargetsParams with source_id provided
        WHEN: Creating the params
        THEN: Validation should pass
        """
        params = ListRemediationTargetsParams(source_id="source_123")
        assert params.source_id == "source_123"

    def test_params_with_no_source_id(self):
        """
        GIVEN: ListRemediationTargetsParams with no source_id provided
        WHEN: Creating the params
        THEN: Validation should pass and return all occurrences
        """
        params = ListRemediationTargetsParams()
        assert params.source_id is None
        assert params.list_repo_occurrences_params is not None

    def test_params_with_nested_list_repo_occurrences_params(self):
        """
        GIVEN: ListRemediationTargetsParams with nested list_repo_occurrences_params
        WHEN: Creating the params
        THEN: Nested params should be properly set
        """
        params = ListRemediationTargetsParams(
            source_id="source_123",
            list_repo_occurrences_params=ListRepoOccurrencesParamsForTargets(source_id="source_123", per_page=20),
        )
        assert params.list_repo_occurrences_params.per_page == 20
        assert params.list_repo_occurrences_params.source_id == "source_123"


def _single_occurrence():
    return ListRepoOccurrencesResult(
        occurrences=[
            {
                "id": "occ_1",
                "matches": [
                    {
                        "type": "apikey",
                        "match": {
                            "filename": "config.py",
                            "line_start": 10,
                            "line_end": 10,
                            "index_start": 15,
                            "index_end": 35,
                        },
                    }
                ],
                "incident": {
                    "id": "incident_1",
                    "detector": {"name": "AWS Access Key"},
                    "assignee_id": "user1",
                },
            }
        ],
        occurrences_count=1,
        applied_filters={},
        suggestion="",
    )


class TestListRemediationTargets:
    """Tests for the list_remediation_targets tool."""

    @pytest.mark.asyncio
    async def test_success(self, mock_gitguardian_client):
        """
        GIVEN: Occurrences with exact match locations
        WHEN: Listing remediation targets
        THEN: Occurrence data and fallback guidance are returned
        """
        mock_occurrences = _single_occurrence()

        # Mock get_current_token_info for filtering by assignee
        mock_gitguardian_client.get_current_token_info = AsyncMock(return_value={"member_id": "user1"})

        with patch(
            "gg_api_core.tools.list_remediation_targets.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            result = await list_remediation_targets(ListRemediationTargetsParams(source_id="source_123"))

            # Verify response structure
            assert result.guidance is not None
            assert result.occurrences_count == 1
            assert result.suggested_occurrences_count == 1
            assert result.sub_tools_results is not None
            assert "list_repo_occurrences" in result.sub_tools_results

            # Verify sub_tools_results contains the occurrences
            sub_result = result.sub_tools_results["list_repo_occurrences"]
            assert sub_result.occurrences_count == 1
            assert len(sub_result.occurrences) == 1

    @pytest.mark.asyncio
    async def test_guidance_is_rotation_first(self, mock_gitguardian_client):
        """
        GIVEN: Occurrences are found
        WHEN: Listing remediation targets
        THEN: The fallback guidance leads with rotation, defers to a skill,
              and gates history rewriting behind unpushed commits
        """
        mock_gitguardian_client.get_current_token_info = AsyncMock(return_value={"member_id": "user1"})

        with patch(
            "gg_api_core.tools.list_remediation_targets.list_repo_occurrences",
            AsyncMock(return_value=_single_occurrence()),
        ):
            result = await list_remediation_targets(ListRemediationTargetsParams(source_id="source_123"))

        guidance = result.guidance.lower()
        # Rotation is mentioned and appears before any git-history rewriting
        assert "rotate" in guidance
        assert guidance.index("rotate") < guidance.index("history")
        # Defers to a remediation skill/workflow when present
        assert "skill" in guidance or "workflow" in guidance
        # History rewriting is gated behind unpushed commits
        assert "pushed" in guidance

    @pytest.mark.asyncio
    async def test_no_occurrences(self, mock_gitguardian_client):
        """
        GIVEN: No occurrences found for the repository
        WHEN: Listing remediation targets
        THEN: A message indicating no occurrences is returned
        """
        mock_occurrences = ListRepoOccurrencesResult(
            occurrences=[],
            occurrences_count=0,
            applied_filters={"tags_exclude": ["TEST_FILE"]},
            suggestion="No occurrences matched the applied filters.",
        )

        with patch(
            "gg_api_core.tools.list_remediation_targets.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            result = await list_remediation_targets(ListRemediationTargetsParams(source_id="source_123"))

            assert result.guidance is not None
            assert "No secret occurrences found" in result.guidance
            assert result.occurrences_count == 0
            assert result.suggested_occurrences_count == 0
            assert "list_repo_occurrences" in result.sub_tools_results

    @pytest.mark.asyncio
    async def test_error(self, mock_gitguardian_client):
        """
        GIVEN: list_repo_occurrences returns an error
        WHEN: Listing remediation targets
        THEN: The error is propagated in the response
        """
        mock_occurrences = ListRepoOccurrencesError(error="API connection failed")

        with patch(
            "gg_api_core.tools.list_remediation_targets.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            result = await list_remediation_targets(ListRemediationTargetsParams(source_id="source_123"))

            assert hasattr(result, "error")
            assert "API connection failed" in result.error
            assert "list_repo_occurrences" in result.sub_tools_results

    @pytest.mark.asyncio
    async def test_mine_false(self, mock_gitguardian_client):
        """
        GIVEN: mine=False flag to include all incidents
        WHEN: Listing remediation targets
        THEN: All occurrences are included regardless of assignee
        """
        mock_occurrences = ListRepoOccurrencesResult(
            occurrences=[
                {
                    "id": "occ_1",
                    "matches": [
                        {
                            "type": "apikey",
                            "match": {
                                "filename": "config.py",
                                "line_start": 10,
                                "line_end": 10,
                                "index_start": 15,
                                "index_end": 35,
                            },
                        }
                    ],
                    "incident": {
                        "id": "incident_1",
                        "detector": {"name": "AWS Access Key"},
                        "assignee_id": "user2",
                    },
                }
            ],
            occurrences_count=1,
            applied_filters={},
            suggestion="",
        )

        with patch(
            "gg_api_core.tools.list_remediation_targets.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            result = await list_remediation_targets(ListRemediationTargetsParams(source_id="source_123", mine=False))

            # Verify all occurrences are included (not filtered by assignee)
            assert result.occurrences_count == 1
            assert result.suggested_occurrences_count == 1

    @pytest.mark.asyncio
    async def test_multiple_files(self, mock_gitguardian_client):
        """
        GIVEN: Occurrences across multiple files
        WHEN: Listing remediation targets
        THEN: All occurrences are returned as targets
        """
        mock_occurrences = ListRepoOccurrencesResult(
            occurrences=[
                {
                    "id": "occ_1",
                    "matches": [
                        {
                            "type": "apikey",
                            "match": {
                                "filename": "config.py",
                                "line_start": 10,
                                "line_end": 10,
                                "index_start": 15,
                                "index_end": 35,
                            },
                        }
                    ],
                    "incident": {
                        "id": "incident_1",
                        "detector": {"name": "AWS Access Key"},
                    },
                },
                {
                    "id": "occ_2",
                    "matches": [
                        {
                            "type": "apikey",
                            "match": {
                                "filename": "settings.py",
                                "line_start": 5,
                                "line_end": 5,
                                "index_start": 20,
                                "index_end": 40,
                            },
                        }
                    ],
                    "incident": {
                        "id": "incident_2",
                        "detector": {"name": "Generic API Key"},
                    },
                },
            ],
            occurrences_count=2,
            applied_filters={},
            suggestion="",
        )

        mock_gitguardian_client.get_current_token_info = AsyncMock(return_value={"member_id": "user1"})

        with patch(
            "gg_api_core.tools.list_remediation_targets.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            result = await list_remediation_targets(ListRemediationTargetsParams(source_id="source_123", mine=False))

            assert result.occurrences_count == 2
            assert result.suggested_occurrences_count == 2
            sub_tool_result = result.sub_tools_results.get("list_repo_occurrences")
            assert sub_tool_result.occurrences_count == 2
            assert len(sub_tool_result.occurrences) == 2


class TestListRemediationTargetsResultSerialization:
    """Tests for ListRemediationTargetsResult Pydantic serialization."""

    def test_sub_tools_results_serialization(self):
        """
        GIVEN: A ListRemediationTargetsResult with a nested ListRepoOccurrencesResult
        WHEN: Serializing the result using model_dump()
        THEN: The nested result should be fully serialized, not an empty dict

        This test ensures that the SerializeAsAny annotation works correctly
        to serialize nested BaseModel instances in sub_tools_results.
        """
        nested_result = ListRepoOccurrencesResult(
            occurrences_count=2,
            occurrences=[
                {"id": "occ_1", "filepath": "config.py"},
                {"id": "occ_2", "filepath": "settings.py"},
            ],
            cursor="next_cursor",
            has_more=True,
            applied_filters={"status": ["TRIGGERED"]},
            suggestion="Some suggestion",
        )

        result = ListRemediationTargetsResult(
            guidance="Test guidance",
            occurrences_count=2,
            suggested_occurrences_count=2,
            sub_tools_results={"list_repo_occurrences": nested_result},
        )

        serialized = result.model_dump()

        # Verify sub_tools_results is not empty
        assert serialized["sub_tools_results"] != {}
        assert "list_repo_occurrences" in serialized["sub_tools_results"]

        # Verify the nested result is fully serialized
        nested_serialized = serialized["sub_tools_results"]["list_repo_occurrences"]
        assert nested_serialized != {}
        assert nested_serialized["occurrences_count"] == 2
        assert len(nested_serialized["occurrences"]) == 2
        assert nested_serialized["occurrences"][0]["id"] == "occ_1"
        assert nested_serialized["cursor"] == "next_cursor"
        assert nested_serialized["has_more"] is True
        assert nested_serialized["applied_filters"] == {"status": ["TRIGGERED"]}
        assert nested_serialized["suggestion"] == "Some suggestion"

    def test_sub_tools_results_json_serialization(self):
        """
        GIVEN: A ListRemediationTargetsResult with a nested ListRepoOccurrencesResult
        WHEN: Serializing the result using model_dump_json()
        THEN: The JSON should contain the full nested result data
        """
        import json

        nested_result = ListRepoOccurrencesResult(
            occurrences_count=1,
            occurrences=[{"id": "occ_1", "filepath": "secret.py"}],
        )

        result = ListRemediationTargetsResult(
            guidance="Fix the secrets",
            occurrences_count=1,
            suggested_occurrences_count=1,
            sub_tools_results={"list_repo_occurrences": nested_result},
        )

        json_str = result.model_dump_json()
        parsed = json.loads(json_str)

        nested_json = parsed["sub_tools_results"]["list_repo_occurrences"]
        assert nested_json["occurrences_count"] == 1
        assert nested_json["occurrences"][0]["id"] == "occ_1"
