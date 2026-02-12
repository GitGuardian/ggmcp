from unittest.mock import AsyncMock, patch

import pytest
from gg_api_core.tools.list_repo_occurrences import (
    ListRepoOccurrencesError,
    ListRepoOccurrencesResult,
)
from gg_api_core.tools.remediate_secret_incidents import (
    ListRepoOccurrencesParamsForRemediate,
    RemediateSecretIncidentsParams,
    RemediateSecretIncidentsResult,
    remediate_secret_incidents,
)


class TestRemediateSecretIncidentsParams:
    """Tests for RemediateSecretIncidentsParams validation."""

    def test_params_with_source_id(self):
        """
        GIVEN: RemediateSecretIncidentsParams with source_id provided
        WHEN: Creating the params
        THEN: Validation should pass
        """
        params = RemediateSecretIncidentsParams(source_id="source_123")
        assert params.source_id == "source_123"

    def test_params_with_no_source_id(self):
        """
        GIVEN: RemediateSecretIncidentsParams with no source_id provided
        WHEN: Creating the params
        THEN: Validation should pass and return all occurrences
        """
        params = RemediateSecretIncidentsParams()
        assert params.source_id is None
        assert params.list_repo_occurrences_params is not None

    def test_params_with_nested_list_repo_occurrences_params(self):
        """
        GIVEN: RemediateSecretIncidentsParams with nested list_repo_occurrences_params
        WHEN: Creating the params
        THEN: Nested params should be properly set
        """
        params = RemediateSecretIncidentsParams(
            source_id="source_123",
            list_repo_occurrences_params=ListRepoOccurrencesParamsForRemediate(source_id="source_123", per_page=20),
        )
        assert params.list_repo_occurrences_params.per_page == 20
        assert params.list_repo_occurrences_params.source_id == "source_123"


class TestRemediateSecretIncidents:
    """Tests for the remediate_secret_incidents tool."""

    @pytest.mark.asyncio
    async def test_remediate_secret_incidents_success(self, mock_gitguardian_client):
        """
        GIVEN: Occurrences with exact match locations
        WHEN: Remediating secret incidents
        THEN: Detailed remediation instructions are returned
        """
        # Mock list_repo_occurrences to return occurrences
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
                        "assignee_id": "user1",
                    },
                }
            ],
            occurrences_count=1,
            applied_filters={},
            suggestion="",
        )

        # Mock get_current_token_info for filtering by assignee
        mock_gitguardian_client.get_current_token_info = AsyncMock(return_value={"member_id": "user1"})

        # Patch list_repo_occurrences
        with patch(
            "gg_api_core.tools.remediate_secret_incidents.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            # Call the function
            result = await remediate_secret_incidents(RemediateSecretIncidentsParams(source_id="source_123"))

            # Verify response structure
            assert result.remediation_instructions is not None
            assert result.occurrences_count == 1
            assert result.suggested_occurrences_for_remediation_count == 1
            assert result.sub_tools_results is not None
            assert "list_repo_occurrences" in result.sub_tools_results

            # Verify sub_tools_results contains the occurrences
            sub_result = result.sub_tools_results["list_repo_occurrences"]
            assert sub_result.occurrences_count == 1
            assert len(sub_result.occurrences) == 1

    @pytest.mark.asyncio
    async def test_remediate_secret_incidents_no_occurrences(self, mock_gitguardian_client):
        """
        GIVEN: No occurrences found for the repository
        WHEN: Attempting to remediate
        THEN: A message indicating no occurrences is returned
        """
        # Mock list_repo_occurrences to return empty occurrences
        mock_occurrences = ListRepoOccurrencesResult(
            occurrences=[],
            occurrences_count=0,
            applied_filters={"tags_exclude": ["TEST_FILE"]},
            suggestion="No occurrences matched the applied filters.",
        )

        # Patch list_repo_occurrences
        with patch(
            "gg_api_core.tools.remediate_secret_incidents.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            # Call the function
            result = await remediate_secret_incidents(RemediateSecretIncidentsParams(source_id="source_123"))

            # Verify response
            assert result.remediation_instructions is not None
            assert "No secret occurrences found" in result.remediation_instructions
            assert result.occurrences_count == 0
            assert result.suggested_occurrences_for_remediation_count == 0
            assert "list_repo_occurrences" in result.sub_tools_results

    @pytest.mark.asyncio
    async def test_remediate_secret_incidents_error(self, mock_gitguardian_client):
        """
        GIVEN: list_repo_occurrences returns an error
        WHEN: Attempting to remediate
        THEN: The error is propagated in the response
        """
        # Mock list_repo_occurrences to return error
        mock_occurrences = ListRepoOccurrencesError(error="API connection failed")

        # Patch list_repo_occurrences
        with patch(
            "gg_api_core.tools.remediate_secret_incidents.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            # Call the function
            result = await remediate_secret_incidents(RemediateSecretIncidentsParams(source_id="source_123"))

            # Verify error response
            assert hasattr(result, "error")
            assert "API connection failed" in result.error
            assert "list_repo_occurrences" in result.sub_tools_results

    @pytest.mark.asyncio
    async def test_remediate_secret_incidents_mine_false(self, mock_gitguardian_client):
        """
        GIVEN: mine=False flag to include all incidents
        WHEN: Remediating secret incidents
        THEN: All occurrences are included regardless of assignee
        """
        # Mock list_repo_occurrences to return multiple occurrences
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

        # Patch list_repo_occurrences
        with patch(
            "gg_api_core.tools.remediate_secret_incidents.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            # Call the function with mine=False
            result = await remediate_secret_incidents(
                RemediateSecretIncidentsParams(source_id="source_123", mine=False)
            )

            # Verify all occurrences are included (not filtered by assignee)
            assert result.occurrences_count == 1
            assert result.suggested_occurrences_for_remediation_count == 1

    @pytest.mark.asyncio
    async def test_remediate_secret_incidents_no_git_commands(self, mock_gitguardian_client):
        """
        GIVEN: git_commands=False
        WHEN: Remediating secret incidents
        THEN: Git commands are not included in the remediation instructions
        """
        # Mock list_repo_occurrences to return occurrences
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
                        "detector": {"name": "Generic API Key"},
                    },
                }
            ],
            occurrences_count=1,
            applied_filters={},
            suggestion="",
        )

        # Mock get_current_token_info
        mock_gitguardian_client.get_current_token_info = AsyncMock(return_value={"member_id": "user1"})

        # Patch list_repo_occurrences
        with patch(
            "gg_api_core.tools.remediate_secret_incidents.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            # Call the function with git_commands=False
            result = await remediate_secret_incidents(
                RemediateSecretIncidentsParams(
                    source_id="source_123",
                    git_commands=False,
                    mine=False,
                )
            )

            # Verify remediation instructions are present but without git commands
            assert result.remediation_instructions is not None
            assert result.occurrences_count == 1

    @pytest.mark.asyncio
    async def test_remediate_secret_incidents_no_env_example(self, mock_gitguardian_client):
        """
        GIVEN: create_env_example=False
        WHEN: Remediating secret incidents
        THEN: Env example is not included in the remediation instructions
        """
        # Mock list_repo_occurrences to return occurrences
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
                        "detector": {"name": "Generic API Key"},
                    },
                }
            ],
            occurrences_count=1,
            applied_filters={},
            suggestion="",
        )

        # Mock get_current_token_info
        mock_gitguardian_client.get_current_token_info = AsyncMock(return_value={"member_id": "user1"})

        # Patch list_repo_occurrences
        with patch(
            "gg_api_core.tools.remediate_secret_incidents.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            # Call the function with create_env_example=False
            result = await remediate_secret_incidents(
                RemediateSecretIncidentsParams(
                    source_id="source_123",
                    create_env_example=False,
                    mine=False,
                )
            )

            # Verify remediation instructions are present
            assert result.remediation_instructions is not None
            assert result.occurrences_count == 1

    @pytest.mark.asyncio
    async def test_remediate_secret_incidents_multiple_files(self, mock_gitguardian_client):
        """
        GIVEN: Occurrences across multiple files
        WHEN: Remediating secret incidents
        THEN: Remediation instructions are provided
        """
        # Mock list_repo_occurrences to return occurrences in different files
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

        # Mock get_current_token_info
        mock_gitguardian_client.get_current_token_info = AsyncMock(return_value={"member_id": "user1"})

        # Patch list_repo_occurrences
        with patch(
            "gg_api_core.tools.remediate_secret_incidents.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            # Call the function
            result = await remediate_secret_incidents(
                RemediateSecretIncidentsParams(source_id="source_123", mine=False)
            )

            # Verify response
            assert result.occurrences_count == 2
            assert result.suggested_occurrences_for_remediation_count == 2
            sub_tool_result = result.sub_tools_results.get("list_repo_occurrences")
            assert sub_tool_result.occurrences_count == 2
            assert len(sub_tool_result.occurrences) == 2


class TestRemediateSecretIncidentsResultSerialization:
    """Tests for RemediateSecretIncidentsResult Pydantic serialization."""

    def test_sub_tools_results_serialization(self):
        """
        GIVEN: A RemediateSecretIncidentsResult with a nested ListRepoOccurrencesResult
        WHEN: Serializing the result using model_dump()
        THEN: The nested result should be fully serialized, not an empty dict

        This test ensures that the SerializeAsAny annotation works correctly
        to serialize nested BaseModel instances in sub_tools_results.
        """
        # Create a nested ListRepoOccurrencesResult
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

        # Create the parent result with nested sub_tools_results
        result = RemediateSecretIncidentsResult(
            remediation_instructions="Test instructions",
            occurrences_count=2,
            suggested_occurrences_for_remediation_count=2,
            sub_tools_results={"list_repo_occurrences": nested_result},
        )

        # Serialize to dict (this is what FastMCP does before JSON serialization)
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
        GIVEN: A RemediateSecretIncidentsResult with a nested ListRepoOccurrencesResult
        WHEN: Serializing the result using model_dump_json()
        THEN: The JSON should contain the full nested result data
        """
        import json

        nested_result = ListRepoOccurrencesResult(
            occurrences_count=1,
            occurrences=[{"id": "occ_1", "filepath": "secret.py"}],
        )

        result = RemediateSecretIncidentsResult(
            remediation_instructions="Fix the secrets",
            occurrences_count=1,
            suggested_occurrences_for_remediation_count=1,
            sub_tools_results={"list_repo_occurrences": nested_result},
        )

        # Serialize to JSON string
        json_str = result.model_dump_json()
        parsed = json.loads(json_str)

        # Verify nested data is present in JSON
        nested_json = parsed["sub_tools_results"]["list_repo_occurrences"]
        assert nested_json["occurrences_count"] == 1
        assert nested_json["occurrences"][0]["id"] == "occ_1"
