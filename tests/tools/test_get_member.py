from unittest.mock import AsyncMock

import pytest
from fastmcp.exceptions import ToolError
from gg_api_core.tools.get_member import GetMemberParams, get_member


class TestGetMember:
    """Tests for the get_member tool."""

    @pytest.mark.asyncio
    async def test_get_member_success(self, mock_gitguardian_client):
        """
        GIVEN: A member exists in GitGuardian
        WHEN: Retrieving the member by ID
        THEN: The API returns the member details
        """
        mock_response = {
            "id": 3252,
            "name": "John Smith",
            "email": "john.smith@example.org",
            "role": "owner",
            "access_level": "owner",
            "active": True,
            "created_at": "2023-06-28T16:40:26.897Z",
            "last_login": "2023-06-28T16:40:26.897Z",
        }
        mock_gitguardian_client.get_member = AsyncMock(return_value=mock_response)

        result = await get_member(GetMemberParams(member_id=3252))

        mock_gitguardian_client.get_member.assert_called_once_with(member_id=3252)
        assert result.member is not None
        assert result.member["id"] == 3252
        assert result.member["name"] == "John Smith"
        assert result.member["email"] == "john.smith@example.org"
        assert result.member["role"] == "owner"
        assert result.member["active"] is True

    @pytest.mark.asyncio
    async def test_get_member_manager_role(self, mock_gitguardian_client):
        """
        GIVEN: A member with manager role exists
        WHEN: Retrieving the member by ID
        THEN: The API returns the member with manager role
        """
        mock_response = {
            "id": 1234,
            "name": "Jane Doe",
            "email": "jane.doe@example.org",
            "role": "manager",
            "access_level": "manager",
            "active": True,
            "created_at": "2023-01-15T10:00:00.000Z",
            "last_login": "2024-01-20T14:30:00.000Z",
        }
        mock_gitguardian_client.get_member = AsyncMock(return_value=mock_response)

        result = await get_member(GetMemberParams(member_id=1234))

        assert result.member["role"] == "manager"
        assert result.member["access_level"] == "manager"

    @pytest.mark.asyncio
    async def test_get_member_inactive(self, mock_gitguardian_client):
        """
        GIVEN: An inactive member exists
        WHEN: Retrieving the member by ID
        THEN: The API returns the member with active=False
        """
        mock_response = {
            "id": 5678,
            "name": "Inactive User",
            "email": "inactive@example.org",
            "role": "member",
            "access_level": "member",
            "active": False,
            "created_at": "2022-01-01T00:00:00.000Z",
            "last_login": None,
        }
        mock_gitguardian_client.get_member = AsyncMock(return_value=mock_response)

        result = await get_member(GetMemberParams(member_id=5678))

        assert result.member["active"] is False
        assert result.member["last_login"] is None

    @pytest.mark.asyncio
    async def test_get_member_not_found(self, mock_gitguardian_client):
        """
        GIVEN: A member does not exist
        WHEN: Retrieving the member by ID
        THEN: A ToolError is raised
        """
        error_message = "Member not found"
        mock_gitguardian_client.get_member = AsyncMock(side_effect=Exception(error_message))

        with pytest.raises(ToolError) as excinfo:
            await get_member(GetMemberParams(member_id=99999))

        assert error_message in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_get_member_client_error(self, mock_gitguardian_client):
        """
        GIVEN: The client raises an exception
        WHEN: Retrieving a member
        THEN: A ToolError is raised
        """
        error_message = "API connection failed"
        mock_gitguardian_client.get_member = AsyncMock(side_effect=Exception(error_message))

        with pytest.raises(ToolError) as excinfo:
            await get_member(GetMemberParams(member_id=1234))

        assert error_message in str(excinfo.value)

    def test_get_member_params_required(self):
        """
        GIVEN: No member_id provided
        WHEN: Creating GetMemberParams
        THEN: Validation error is raised
        """
        with pytest.raises(ValueError):
            GetMemberParams()

    def test_get_member_params_valid(self):
        """
        GIVEN: A valid member_id
        WHEN: Creating GetMemberParams
        THEN: The params are created successfully
        """
        params = GetMemberParams(member_id=123)
        assert params.member_id == 123
