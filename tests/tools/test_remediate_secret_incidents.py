from unittest.mock import AsyncMock, patch

import pytest
from gg_api_core.tools.list_repo_occurrences import ListRepoOccurrencesError, ListRepoOccurrencesResult
from gg_api_core.tools.remediate_secret_incidents import (
    ListRepoOccurrencesParamsForRemediate,
    RemediateSecretIncidentsParams,
    remediate_secret_incidents,
)


class TestRemediateSecretIncidentsParams:
    """Tests for RemediateSecretIncidentsParams validation."""

    def test_params_with_repository_name(self):
        """
        GIVEN: RemediateSecretIncidentsParams with repository_name provided
        WHEN: Creating the params
        THEN: Validation should pass
        """
        params = RemediateSecretIncidentsParams(repository_name="GitGuardian/test-repo")
        assert params.repository_name == "GitGuardian/test-repo"
        assert params.source_id is None

    def test_params_with_source_id(self):
        """
        GIVEN: RemediateSecretIncidentsParams with source_id provided
        WHEN: Creating the params
        THEN: Validation should pass
        """
        params = RemediateSecretIncidentsParams(source_id="source_123")
        assert params.source_id == "source_123"
        assert params.repository_name is None

    def test_params_with_both_repository_name_and_source_id(self):
        """
        GIVEN: RemediateSecretIncidentsParams with both repository_name and source_id provided
        WHEN: Creating the params
        THEN: Validation should pass
        """
        params = RemediateSecretIncidentsParams(repository_name="GitGuardian/test-repo", source_id="source_123")
        assert params.repository_name == "GitGuardian/test-repo"
        assert params.source_id == "source_123"

    def test_params_with_neither_repository_name_nor_source_id(self):
        """
        GIVEN: RemediateSecretIncidentsParams with neither repository_name nor source_id provided
        WHEN: Creating the params
        THEN: Validation should pass and return all occurrences
        """
        params = RemediateSecretIncidentsParams()
        assert params.repository_name is None
        assert params.source_id is None
        assert params.list_repo_occurrences_params is not None

    def test_params_with_nested_list_repo_occurrences_params(self):
        """
        GIVEN: RemediateSecretIncidentsParams with nested list_repo_occurrences_params
        WHEN: Creating the params
        THEN: Nested params should be properly set
        """
        params = RemediateSecretIncidentsParams(
            repository_name="GitGuardian/test-repo",
            list_repo_occurrences_params=ListRepoOccurrencesParamsForRemediate(
                repository_name="GitGuardian/test-repo", per_page=20
            ),
        )
        assert params.list_repo_occurrences_params.per_page == 20
        assert params.list_repo_occurrences_params.repository_name == "GitGuardian/test-repo"


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
        mock_gitguardian_client.get_current_token_info = AsyncMock(return_value={"user_id": "user1"})

        # Patch list_repo_occurrences
        with patch(
            "gg_api_core.tools.remediate_secret_incidents.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            # Call the function
            result = await remediate_secret_incidents(
                RemediateSecretIncidentsParams(repository_name="GitGuardian/test-repo")
            )

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
            result = await remediate_secret_incidents(
                RemediateSecretIncidentsParams(repository_name="GitGuardian/test-repo")
            )

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
            result = await remediate_secret_incidents(
                RemediateSecretIncidentsParams(repository_name="GitGuardian/test-repo")
            )

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
                RemediateSecretIncidentsParams(repository_name="GitGuardian/test-repo", mine=False)
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
        mock_gitguardian_client.get_current_token_info = AsyncMock(return_value={"user_id": "user1"})

        # Patch list_repo_occurrences
        with patch(
            "gg_api_core.tools.remediate_secret_incidents.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            # Call the function with git_commands=False
            result = await remediate_secret_incidents(
                RemediateSecretIncidentsParams(
                    repository_name="GitGuardian/test-repo",
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
        mock_gitguardian_client.get_current_token_info = AsyncMock(return_value={"user_id": "user1"})

        # Patch list_repo_occurrences
        with patch(
            "gg_api_core.tools.remediate_secret_incidents.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            # Call the function with create_env_example=False
            result = await remediate_secret_incidents(
                RemediateSecretIncidentsParams(
                    repository_name="GitGuardian/test-repo",
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
        mock_gitguardian_client.get_current_token_info = AsyncMock(return_value={"user_id": "user1"})

        # Patch list_repo_occurrences
        with patch(
            "gg_api_core.tools.remediate_secret_incidents.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            # Call the function
            result = await remediate_secret_incidents(
                RemediateSecretIncidentsParams(repository_name="GitGuardian/test-repo", mine=False)
            )

            # Verify response
            assert result.occurrences_count == 2
            assert result.suggested_occurrences_for_remediation_count == 2
            sub_tool_result = result.sub_tools_results.get("list_repo_occurrences")
            assert sub_tool_result.occurrences_count == 2
            assert len(sub_tool_result.occurrences) == 2
