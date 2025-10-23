from unittest.mock import AsyncMock, patch

import pytest
from pydantic import ValidationError
from gg_api_core.tools.remediate_secret_incidents import (
    remediate_secret_incidents,
    _process_occurrences_for_remediation,
    RemediateSecretIncidentsParams,
)


class TestRemediateSecretIncidentsParams:
    """Tests for RemediateSecretIncidentsParams validation."""

    def test_params_with_repository_name(self):
        """
        GIVEN: RemediateSecretIncidentsParams with repository_name provided
        WHEN: Creating the params
        THEN: Validation should pass
        """
        params = RemediateSecretIncidentsParams(
            repository_name="GitGuardian/test-repo"
        )
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
        params = RemediateSecretIncidentsParams(
            repository_name="GitGuardian/test-repo", source_id="source_123"
        )
        assert params.repository_name == "GitGuardian/test-repo"
        assert params.source_id == "source_123"

    def test_params_with_neither_repository_name_nor_source_id(self):
        """
        GIVEN: RemediateSecretIncidentsParams with neither repository_name nor source_id provided
        WHEN: Creating the params
        THEN: Validation should fail with ValueError
        """
        with pytest.raises(ValidationError) as exc_info:
            RemediateSecretIncidentsParams()

        # Verify the error message
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert "Either 'source_id' or 'repository_name' must be provided" in str(
            errors[0]
        )


class TestRemediateSecretIncidents:
    """Tests for the remediate_secret_incidents tool."""

    @pytest.mark.asyncio
    async def test_remediate_secret_incidents_success(self, mock_gitguardian_client):
        """
        GIVEN: Occurrences with exact match locations
        WHEN: Remediating secret incidents
        THEN: Detailed remediation steps with file locations are returned
        """
        # Mock list_repo_occurrences to return occurrences
        mock_occurrences = {
            "occurrences": [
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
            "applied_filters": {},
            "suggestion": "",
        }

        # Mock get_current_token_info for filtering by assignee
        mock_gitguardian_client.get_current_token_info = AsyncMock(
            return_value={"user_id": "user1"}
        )

        # Patch list_repo_occurrences
        with patch(
            "gg_api_core.tools.remediate_secret_incidents.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            # Call the function
            result = await remediate_secret_incidents(
                RemediateSecretIncidentsParams(
                    repository_name="GitGuardian/test-repo"
                )
            )

            # Verify response structure
            assert result.repository_info is not None
            assert result.summary is not None
            assert result.remediation_steps is not None
            assert result.env_example_content is not None
            assert result.git_commands is not None

            # Verify summary
            assert result.summary["total_occurrences"] == 1
            assert result.summary["affected_files"] == 1
            assert "AWS Access Key" in result.summary["secret_types"]

            # Verify remediation steps
            assert len(result.remediation_steps) == 1
            assert result.remediation_steps[0]["file"] == "config.py"
            assert len(result.remediation_steps[0]["matches"]) == 1

    @pytest.mark.asyncio
    async def test_remediate_secret_incidents_no_occurrences(
        self, mock_gitguardian_client
    ):
        """
        GIVEN: No occurrences found for the repository
        WHEN: Attempting to remediate
        THEN: A message indicating no occurrences is returned
        """
        # Mock list_repo_occurrences to return empty occurrences
        mock_occurrences = {
            "occurrences": [],
            "applied_filters": {"tags_exclude": ["TEST_FILE"]},
            "suggestion": "No occurrences matched the applied filters.",
        }

        # Patch list_repo_occurrences
        with patch(
            "gg_api_core.tools.remediate_secret_incidents.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            # Call the function
            result = await remediate_secret_incidents(
                RemediateSecretIncidentsParams(
                    repository_name="GitGuardian/test-repo"
                )
            )

            # Verify response
            assert result.message is not None
            assert "No secret occurrences found" in result.message
            assert result.remediation_steps == []
            assert result.applied_filters is not None
            assert result.suggestion is not None

    @pytest.mark.asyncio
    async def test_remediate_secret_incidents_error(self, mock_gitguardian_client):
        """
        GIVEN: list_repo_occurrences returns an error
        WHEN: Attempting to remediate
        THEN: The error is propagated in the response
        """
        # Mock list_repo_occurrences to return error
        mock_occurrences = {"error": "API connection failed"}

        # Patch list_repo_occurrences
        with patch(
            "gg_api_core.tools.remediate_secret_incidents.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            # Call the function
            result = await remediate_secret_incidents(
                RemediateSecretIncidentsParams(
                    repository_name="GitGuardian/test-repo"
                )
            )

            # Verify error response
            assert hasattr(result, "error")
            assert "API connection failed" in result.error

    @pytest.mark.asyncio
    async def test_remediate_secret_incidents_mine_false(
        self, mock_gitguardian_client
    ):
        """
        GIVEN: mine=False flag to include all incidents
        WHEN: Remediating secret incidents
        THEN: All occurrences are included regardless of assignee
        """
        # Mock list_repo_occurrences to return multiple occurrences
        mock_occurrences = {
            "occurrences": [
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
            "applied_filters": {},
            "suggestion": "",
        }

        # Patch list_repo_occurrences
        with patch(
            "gg_api_core.tools.remediate_secret_incidents.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            # Call the function with mine=False
            result = await remediate_secret_incidents(
                RemediateSecretIncidentsParams(
                    repository_name="GitGuardian/test-repo", mine=False
                )
            )

            # Verify all occurrences are included (not filtered by assignee)
            assert result.summary["total_occurrences"] == 1

    @pytest.mark.asyncio
    async def test_remediate_secret_incidents_no_git_commands(
        self, mock_gitguardian_client
    ):
        """
        GIVEN: include_git_commands=False
        WHEN: Remediating secret incidents
        THEN: Git commands are not included in the response
        """
        # Mock list_repo_occurrences to return occurrences
        mock_occurrences = {
            "occurrences": [
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
            "applied_filters": {},
            "suggestion": "",
        }

        # Mock get_current_token_info
        mock_gitguardian_client.get_current_token_info = AsyncMock(
            return_value={"user_id": "user1"}
        )

        # Patch list_repo_occurrences
        with patch(
            "gg_api_core.tools.remediate_secret_incidents.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            # Call the function with include_git_commands=False
            result = await remediate_secret_incidents(
                RemediateSecretIncidentsParams(
                    repository_name="GitGuardian/test-repo",
                    include_git_commands=False,
                    mine=False,
                )
            )

            # Verify git commands are not included
            assert result.git_commands is None

    @pytest.mark.asyncio
    async def test_remediate_secret_incidents_no_env_example(
        self, mock_gitguardian_client
    ):
        """
        GIVEN: create_env_example=False
        WHEN: Remediating secret incidents
        THEN: Env example content is not included in the response
        """
        # Mock list_repo_occurrences to return occurrences
        mock_occurrences = {
            "occurrences": [
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
            "applied_filters": {},
            "suggestion": "",
        }

        # Mock get_current_token_info
        mock_gitguardian_client.get_current_token_info = AsyncMock(
            return_value={"user_id": "user1"}
        )

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

            # Verify env example is not included
            assert result.env_example_content is None

    @pytest.mark.asyncio
    async def test_remediate_secret_incidents_multiple_files(
        self, mock_gitguardian_client
    ):
        """
        GIVEN: Occurrences across multiple files
        WHEN: Remediating secret incidents
        THEN: Remediation steps are provided for each file
        """
        # Mock list_repo_occurrences to return occurrences in different files
        mock_occurrences = {
            "occurrences": [
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
            "applied_filters": {},
            "suggestion": "",
        }

        # Mock get_current_token_info
        mock_gitguardian_client.get_current_token_info = AsyncMock(
            return_value={"user_id": "user1"}
        )

        # Patch list_repo_occurrences
        with patch(
            "gg_api_core.tools.remediate_secret_incidents.list_repo_occurrences",
            AsyncMock(return_value=mock_occurrences),
        ):
            # Call the function
            result = await remediate_secret_incidents(
                RemediateSecretIncidentsParams(
                    repository_name="GitGuardian/test-repo", mine=False
                )
            )

            # Verify response
            assert result.summary["total_occurrences"] == 2
            assert result.summary["affected_files"] == 2
            assert len(result.remediation_steps) == 2

    @pytest.mark.asyncio
    async def test_process_occurrences_for_remediation(self):
        """
        GIVEN: Occurrences with match locations
        WHEN: Processing for remediation
        THEN: Structured remediation steps with file details are returned
        """
        # Sample occurrences
        occurrences = [
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
            }
        ]

        # Call the helper function
        result = await _process_occurrences_for_remediation(
            occurrences=occurrences,
            repository_name="GitGuardian/test-repo",
            include_git_commands=True,
            create_env_example=True,
        )

        # Verify response structure
        assert "repository_info" in result
        assert "summary" in result
        assert "remediation_steps" in result
        assert "env_example_content" in result
        assert "git_commands" in result

        # Verify remediation steps are sorted bottom-to-top
        step = result["remediation_steps"][0]
        assert step["file"] == "config.py"
        assert len(step["matches"]) == 1

    @pytest.mark.asyncio
    async def test_process_occurrences_for_remediation_sorting(self):
        """
        GIVEN: Multiple matches in the same file
        WHEN: Processing for remediation
        THEN: Matches are sorted from bottom to top for safe removal
        """
        # Sample occurrences with multiple matches in same file
        occurrences = [
            {
                "id": "occ_1",
                "matches": [
                    {
                        "type": "apikey",
                        "match": {
                            "filename": "config.py",
                            "line_start": 5,
                            "line_end": 5,
                            "index_start": 10,
                            "index_end": 30,
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
                            "filename": "config.py",
                            "line_start": 15,
                            "line_end": 15,
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
        ]

        # Call the helper function
        result = await _process_occurrences_for_remediation(
            occurrences=occurrences,
            repository_name="GitGuardian/test-repo",
            include_git_commands=False,
            create_env_example=False,
        )

        # Verify matches are sorted bottom to top (line 15 before line 5)
        step = result["remediation_steps"][0]
        assert step["matches"][0]["line_start"] == 15
        assert step["matches"][1]["line_start"] == 5
