"""
VCR tests for list_users tool.

These tests use recorded HTTP interactions to verify tool behavior
without requiring a live API connection.

Note: These tests require VCR cassettes to be recorded. Run with a valid
GITGUARDIAN_API_KEY to record cassettes:
    make test-vcr-with-env
"""

from unittest.mock import patch

import pytest
from gg_api_core.tools.list_users import (
    ListUsersParams,
    ListUsersResult,
    list_users,
)


class TestListUsersVCR:
    """VCR tests for the list_users tool.

    These tests cover various parameter combinations for the list_users tool.
    The tool uses the /members endpoint to retrieve workspace members.
    """

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_users_basic(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with members:read scope
        WHEN: Calling list_users with minimal parameters
        THEN: Returns a list of workspace members with basic info

        Uses cassette: test_list_members.yaml (existing)
        """
        with use_cassette("test_list_members"):
            with patch(
                "gg_api_core.tools.list_users.get_client",
                return_value=real_client,
            ):
                # Match the cassette's query params: per_page=5
                params = ListUsersParams(
                    per_page=5,
                    get_all=False,
                )

                result = await list_users(params)

                assert result is not None
                assert isinstance(result, ListUsersResult)
                assert result.members is not None
                assert isinstance(result.members, list)
                assert result.total_count > 0
                # Verify member structure
                if result.members:
                    member = result.members[0]
                    assert "id" in member
                    assert "email" in member
                    assert "name" in member
                    assert "role" in member
                    assert "access_level" in member
                    assert "active" in member

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_users_with_search(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with members:read scope
        WHEN: Calling list_users with a search filter
        THEN: Returns members matching the search term

        Note: This test requires a cassette to be recorded with `make test-vcr-with-env`
        """
        with use_cassette("test_list_users_with_search"):
            with patch(
                "gg_api_core.tools.list_users.get_client",
                return_value=real_client,
            ):
                params = ListUsersParams(
                    search="gitguardian",
                    per_page=10,
                    get_all=False,
                )

                result = await list_users(params)

                assert result is not None
                assert isinstance(result, ListUsersResult)
                assert result.members is not None

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_users_with_access_level(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with members:read scope
        WHEN: Calling list_users filtered by access_level
        THEN: Returns only members with that access level

        Note: This test requires a cassette to be recorded with `make test-vcr-with-env`
        """
        with use_cassette("test_list_users_with_access_level"):
            with patch(
                "gg_api_core.tools.list_users.get_client",
                return_value=real_client,
            ):
                params = ListUsersParams(
                    access_level="manager",
                    per_page=10,
                    get_all=False,
                )

                result = await list_users(params)

                assert result is not None
                assert isinstance(result, ListUsersResult)
                assert result.members is not None
                # Verify all returned members have manager access level
                for member in result.members:
                    assert member.get("access_level") == "manager"

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_users_with_ordering(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with members:read scope
        WHEN: Calling list_users with ordering by created_at descending
        THEN: Returns members sorted by creation date (newest first)

        Note: This test requires a cassette to be recorded with `make test-vcr-with-env`
        """
        with use_cassette("test_list_users_with_ordering"):
            with patch(
                "gg_api_core.tools.list_users.get_client",
                return_value=real_client,
            ):
                params = ListUsersParams(
                    ordering="-created_at",
                    per_page=10,
                    get_all=False,
                )

                result = await list_users(params)

                assert result is not None
                assert isinstance(result, ListUsersResult)
                assert result.members is not None

    @pytest.mark.vcr_test
    @pytest.mark.asyncio
    async def test_list_users_with_active_filter(self, real_client, use_cassette):
        """
        GIVEN: A valid GitGuardian API key with members:read scope
        WHEN: Calling list_users filtered by active status
        THEN: Returns only active members

        Note: This test requires a cassette to be recorded with `make test-vcr-with-env`
        """
        with use_cassette("test_list_users_with_active_filter"):
            with patch(
                "gg_api_core.tools.list_users.get_client",
                return_value=real_client,
            ):
                params = ListUsersParams(
                    active=True,
                    per_page=10,
                    get_all=False,
                )

                result = await list_users(params)

                assert result is not None
                assert isinstance(result, ListUsersResult)
                assert result.members is not None
                # Verify all returned members are active
                for member in result.members:
                    assert member.get("active") is True
