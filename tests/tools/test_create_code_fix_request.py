from unittest.mock import AsyncMock

import pytest
from gg_api_core.tools.create_code_fix_request import (
    CreateCodeFixRequestParams,
    LocationToFix,
    create_code_fix_request,
)
from mcp.server.fastmcp.exceptions import ToolError


class TestCreateCodeFixRequest:
    """Tests for the create_code_fix_request tool."""

    @pytest.mark.asyncio
    async def test_create_code_fix_request_single_issue_success(self, mock_gitguardian_client):
        """
        GIVEN: A single issue with multiple locations
        WHEN: Creating a code fix request
        THEN: The API creates a code fix request and returns success message
        """
        # Mock the client response
        mock_response = {"message": "Created 1 code fix requests for 3 locations"}
        mock_gitguardian_client.create_code_fix_request = AsyncMock(return_value=mock_response)

        # Call the function with single issue
        result = await create_code_fix_request(
            CreateCodeFixRequestParams(locations=[LocationToFix(issue_id=12345, location_ids=[67890, 67891, 67892])])
        )

        # Verify client was called with correct parameters
        mock_gitguardian_client.create_code_fix_request.assert_called_once_with(
            locations=[
                {
                    "issue_id": 12345,
                    "location_ids": [67890, 67891, 67892],
                }
            ]
        )

        # Verify response
        assert result.success is True
        assert result.message == "Created 1 code fix requests for 3 locations"

    @pytest.mark.asyncio
    async def test_create_code_fix_request_multiple_issues_success(self, mock_gitguardian_client):
        """
        GIVEN: Multiple issues from different sources
        WHEN: Creating a code fix request
        THEN: The API creates multiple code fix requests and returns success message
        """
        # Mock the client response
        mock_response = {"message": "Created 2 code fix requests for 5 locations"}
        mock_gitguardian_client.create_code_fix_request = AsyncMock(return_value=mock_response)

        # Call the function with multiple issues
        result = await create_code_fix_request(
            CreateCodeFixRequestParams(
                locations=[
                    LocationToFix(issue_id=12345, location_ids=[67890]),
                    LocationToFix(issue_id=12346, location_ids=[67893, 67894]),
                ]
            )
        )

        # Verify client was called with correct parameters
        mock_gitguardian_client.create_code_fix_request.assert_called_once_with(
            locations=[
                {"issue_id": 12345, "location_ids": [67890]},
                {"issue_id": 12346, "location_ids": [67893, 67894]},
            ]
        )

        # Verify response
        assert result.success is True
        assert result.message == "Created 2 code fix requests for 5 locations"

    @pytest.mark.asyncio
    async def test_create_code_fix_request_feature_disabled(self, mock_gitguardian_client):
        """
        GIVEN: Code fixing feature is not enabled
        WHEN: Creating a code fix request
        THEN: A ToolError is raised with appropriate message
        """
        # Mock the client to raise an exception with "not enabled" message
        mock_gitguardian_client.create_code_fix_request = AsyncMock(
            side_effect=Exception("Code fixing feature is not enabled")
        )

        # Call the function and expect a ToolError
        with pytest.raises(ToolError) as excinfo:
            await create_code_fix_request(
                CreateCodeFixRequestParams(locations=[LocationToFix(issue_id=12345, location_ids=[67890])])
            )

        # Verify error message
        assert "not enabled" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_create_code_fix_request_too_many_locations(self, mock_gitguardian_client):
        """
        GIVEN: Too many locations in the request
        WHEN: Creating a code fix request
        THEN: A ToolError is raised with appropriate message
        """
        # Mock the client to raise an exception
        mock_gitguardian_client.create_code_fix_request = AsyncMock(
            side_effect=Exception("Too many elements in the request")
        )

        # Call the function and expect a ToolError
        with pytest.raises(ToolError) as excinfo:
            await create_code_fix_request(
                CreateCodeFixRequestParams(locations=[LocationToFix(issue_id=12345, location_ids=[67890])])
            )

        # Verify error message
        assert "Too many locations" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_create_code_fix_request_no_valid_locations(self, mock_gitguardian_client):
        """
        GIVEN: No valid locations found for the given criteria
        WHEN: Creating a code fix request
        THEN: A ToolError is raised with appropriate message
        """
        # Mock the client to raise an exception
        mock_gitguardian_client.create_code_fix_request = AsyncMock(
            side_effect=Exception("No valid locations found for the given criteria")
        )

        # Call the function and expect a ToolError
        with pytest.raises(ToolError) as excinfo:
            await create_code_fix_request(
                CreateCodeFixRequestParams(locations=[LocationToFix(issue_id=12345, location_ids=[67890])])
            )

        # Verify error message
        assert "No valid locations" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_create_code_fix_request_already_being_fixed(self, mock_gitguardian_client):
        """
        GIVEN: Some locations already have open pull requests
        WHEN: Creating a code fix request
        THEN: A ToolError is raised with appropriate message
        """
        # Mock the client to raise an exception
        mock_gitguardian_client.create_code_fix_request = AsyncMock(
            side_effect=Exception("Some locations already have open pull requests")
        )

        # Call the function and expect a ToolError
        with pytest.raises(ToolError) as excinfo:
            await create_code_fix_request(
                CreateCodeFixRequestParams(locations=[LocationToFix(issue_id=12345, location_ids=[67890])])
            )

        # Verify error message
        assert "already have open pull requests" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_create_code_fix_request_insufficient_permissions(self, mock_gitguardian_client):
        """
        GIVEN: User lacks required permissions
        WHEN: Creating a code fix request
        THEN: A ToolError is raised with appropriate message
        """
        # Mock the client to raise a 403 error
        mock_gitguardian_client.create_code_fix_request = AsyncMock(
            side_effect=Exception("403 Forbidden: You do not have permission")
        )

        # Call the function and expect a ToolError
        with pytest.raises(ToolError) as excinfo:
            await create_code_fix_request(
                CreateCodeFixRequestParams(locations=[LocationToFix(issue_id=12345, location_ids=[67890])])
            )

        # Verify error message mentions permissions
        assert "permission" in str(excinfo.value).lower()

    @pytest.mark.asyncio
    async def test_create_code_fix_request_api_key_not_configured(self, mock_gitguardian_client):
        """
        GIVEN: API key is not configured (on-prem only)
        WHEN: Creating a code fix request
        THEN: A ToolError is raised with appropriate message
        """
        # Mock the client to raise a 404 error
        mock_gitguardian_client.create_code_fix_request = AsyncMock(
            side_effect=Exception("404 Not Found: Code fixing API key is not set")
        )

        # Call the function and expect a ToolError
        with pytest.raises(ToolError) as excinfo:
            await create_code_fix_request(
                CreateCodeFixRequestParams(locations=[LocationToFix(issue_id=12345, location_ids=[67890])])
            )

        # Verify error message mentions API key
        assert "API key" in str(excinfo.value) or "404" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_create_code_fix_request_generic_error(self, mock_gitguardian_client):
        """
        GIVEN: An unexpected API error occurs
        WHEN: Creating a code fix request
        THEN: A ToolError is raised with the original error message
        """
        # Mock the client to raise a generic exception
        error_message = "Unexpected API error"
        mock_gitguardian_client.create_code_fix_request = AsyncMock(side_effect=Exception(error_message))

        # Call the function and expect a ToolError
        with pytest.raises(ToolError) as excinfo:
            await create_code_fix_request(
                CreateCodeFixRequestParams(locations=[LocationToFix(issue_id=12345, location_ids=[67890])])
            )

        # Verify error message contains the original error
        assert error_message in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_create_code_fix_request_validates_empty_locations(self):
        """
        GIVEN: Empty locations list
        WHEN: Creating params
        THEN: Validation error is raised
        """
        # Attempt to create params with empty locations
        with pytest.raises(Exception):  # Pydantic will raise ValidationError
            CreateCodeFixRequestParams(locations=[])

    @pytest.mark.asyncio
    async def test_create_code_fix_request_validates_empty_location_ids(self):
        """
        GIVEN: Empty location_ids list
        WHEN: Creating a LocationToFix
        THEN: Validation error is raised
        """
        # Attempt to create LocationToFix with empty location_ids
        with pytest.raises(Exception):  # Pydantic will raise ValidationError
            LocationToFix(issue_id=123, location_ids=[])

    @pytest.mark.asyncio
    async def test_create_code_fix_request_response_without_message(self, mock_gitguardian_client):
        """
        GIVEN: API response doesn't include a message field
        WHEN: Creating a code fix request
        THEN: A default success message is returned
        """
        # Mock the client response without message field
        mock_response = {"status": "success"}
        mock_gitguardian_client.create_code_fix_request = AsyncMock(return_value=mock_response)

        # Call the function
        result = await create_code_fix_request(
            CreateCodeFixRequestParams(locations=[LocationToFix(issue_id=12345, location_ids=[67890])])
        )

        # Verify response has default message
        assert result.success is True
        assert "Created code fix requests for 1 issue" in result.message

    @pytest.mark.asyncio
    async def test_create_code_fix_request_with_many_locations(self, mock_gitguardian_client):
        """
        GIVEN: Many locations across multiple issues
        WHEN: Creating a code fix request
        THEN: All locations are correctly included in the request
        """
        # Mock the client response
        mock_response = {"message": "Created 5 code fix requests for 15 locations"}
        mock_gitguardian_client.create_code_fix_request = AsyncMock(return_value=mock_response)

        # Create params with many locations
        locations = [LocationToFix(issue_id=100 + i, location_ids=[1000 + i, 2000 + i, 3000 + i]) for i in range(5)]

        # Call the function
        result = await create_code_fix_request(CreateCodeFixRequestParams(locations=locations))

        # Verify client was called
        assert mock_gitguardian_client.create_code_fix_request.called
        call_args = mock_gitguardian_client.create_code_fix_request.call_args
        assert len(call_args.kwargs["locations"]) == 5

        # Verify response
        assert result.success is True
        assert "15 locations" in result.message
