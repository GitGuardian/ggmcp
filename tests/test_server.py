from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from gg_api_mcp_server import server


@pytest.fixture
def mock_gitguardian_client():
    """Fixture to create a mock GitGuardian client."""
    with patch("gg_api_mcp_server.server.get_gitguardian_client") as mock_get_client:
        client = MagicMock()
        mock_get_client.return_value = client
        yield client


class TestGenerateHoneytoken:
    """Tests for the generate_honeytoken tool."""

    @pytest.mark.asyncio
    async def test_generate_honeytoken_success(self, mock_gitguardian_client):
        """Test successful honeytoken generation."""
        # Mock the client response
        mock_response = {
            "id": "honeytoken_id",
            "name": "test_honeytoken",
            "token": "fake_token_value",
            "created_at": "2023-01-01T00:00:00Z",
            "status": "ACTIVE",
            "type": "AWS",
        }
        mock_gitguardian_client.create_honeytoken = AsyncMock(return_value=mock_response)

        # Call the function
        result = await server.generate_honeytoken(name="test_honeytoken", description="Test description")

        # Verify client was called with correct parameters
        mock_gitguardian_client.create_honeytoken.assert_called_once_with(
            name="test_honeytoken",
            description="Test description",
            custom_tags=[
                {"key": "source", "value": "auto-generated"},
                {"key": "type", "value": "aws"},
            ],
        )

        # Verify response
        assert result["id"] == "honeytoken_id"
        assert result["token"] == "fake_token_value"
        assert "injection_recommendations" in result
        assert "instructions" in result["injection_recommendations"]

    @pytest.mark.asyncio
    async def test_generate_honeytoken_missing_id(self, mock_gitguardian_client):
        """Test error when ID is missing from response."""
        # Mock the client response with missing ID
        mock_response = {
            "name": "test_honeytoken",
            "token": "fake_token_value",
            # ID is missing
        }
        mock_gitguardian_client.create_honeytoken = AsyncMock(return_value=mock_response)

        # Call the function and expect an error
        with pytest.raises(ToolError) as excinfo:
            await server.generate_honeytoken(name="test_honeytoken")

        # Verify error message
        assert "Failed to get honeytoken ID from GitGuardian API" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_generate_honeytoken_client_error(self, mock_gitguardian_client):
        """Test error handling when client raises an exception."""
        # Mock the client to raise an exception
        error_message = "API error"
        mock_gitguardian_client.create_honeytoken = AsyncMock(side_effect=Exception(error_message))

        # Call the function and expect an error
        with pytest.raises(ToolError) as excinfo:
            await server.generate_honeytoken(name="test_honeytoken")

        # Verify error message
        assert f"Failed to generate honeytoken: {error_message}" in str(excinfo.value)


class TestListIncidents:
    """Tests for the list_incidents tool."""

    @pytest.mark.asyncio
    async def test_list_incidents_success(self, mock_gitguardian_client):
        """Test successful incidents listing."""
        # Mock the client response
        mock_response = {
            "data": [{"id": "incident_1", "severity": "critical", "status": "TRIGGERED"}],
            "pagination": {"total_count": 1, "page": 1, "per_page": 20},
        }

        # Mock the client's list_incidents method to bypass validation
        async def mock_list_incidents(**kwargs):
            return mock_response

        mock_gitguardian_client.list_incidents = AsyncMock(side_effect=mock_list_incidents)

        # Call the function with string values
        result = await server.list_incidents(
            severity="critical",
            status="TRIGGERED",
            from_date="2023-01-01",
            to_date="2023-12-31",
            validity="valid",
            per_page=20,
            page=1,
        )

        # Verify client was called
        mock_gitguardian_client.list_incidents.assert_called_once()

        # Verify response
        assert result == mock_response


@pytest.mark.asyncio
async def test_list_all_incidents(mock_gitguardian_client):
    """Test the list_all_incidents function."""
    # Mock multiple pages of responses
    page1 = {
        "data": [{"id": "incident_1"}],
        "pagination": {"total_count": 2, "page": 1, "per_page": 1, "total_pages": 2},
    }
    page2 = {
        "data": [{"id": "incident_2"}],
        "pagination": {"total_count": 2, "page": 2, "per_page": 1, "total_pages": 2},
    }

    # Set up the mock to return different responses for different calls
    async def mock_list_incidents(*args, **kwargs):
        if kwargs.get("page") == 1:
            return page1
        else:
            return page2

    mock_gitguardian_client.list_incidents = AsyncMock(side_effect=mock_list_incidents)

    # Call the function
    result = await server.list_all_incidents(severity="critical", max_pages=2)

    # Verify client was called twice
    assert mock_gitguardian_client.list_incidents.call_count == 2

    # Verify combined response
    assert "data" in result
    assert len(result["data"]) == 2
    assert result["data"][0]["id"] == "incident_1"
    assert result["data"][1]["id"] == "incident_2"
