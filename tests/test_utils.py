"""Tests for the utils module."""

from pathlib import Path

import pytest

from .utils import create_mock_response, load_fixture


@pytest.fixture
def fixture_dir():
    """Create a temporary fixture directory for testing."""
    # Use the actual fixtures directory
    return Path(__file__).parent / "fixtures"


class TestLoadFixture:
    """Tests for the load_fixture function."""

    def test_load_fixture(self, fixture_dir):
        """Test loading a fixture."""
        # Verify the honeytoken fixture can be loaded
        honeytoken = load_fixture("honeytoken")
        assert honeytoken["id"] == "ht_abc123def456"
        assert honeytoken["name"] == "Test Honeytoken"
        assert honeytoken["token"] == "AKIAXXXXXXXXXXXXXXXX"

    def test_load_fixture_not_found(self, fixture_dir):
        """Test error when fixture is not found."""
        with pytest.raises(FileNotFoundError):
            load_fixture("non_existent_fixture")


class TestCreateMockResponse:
    """Tests for the create_mock_response function."""

    def test_create_mock_response_with_list(self):
        """Test creating a mock response with a list of data."""
        data = [{"id": 1}, {"id": 2}, {"id": 3}]
        response = create_mock_response(data)

        assert response["data"] == data
        assert response["status_code"] == 200
        assert response["pagination"]["total_count"] == 3
        assert response["pagination"]["page"] == 1
        assert response["pagination"]["per_page"] == 20

    def test_create_mock_response_with_dict(self):
        """Test creating a mock response with a dictionary."""
        data = {"id": 1, "name": "Test"}
        response = create_mock_response(data)

        assert response["data"] == data
        assert response["status_code"] == 200
        assert response["pagination"]["total_count"] == 1
        assert response["pagination"]["page"] == 1
        assert response["pagination"]["per_page"] == 20

    def test_create_mock_response_with_status_code(self):
        """Test creating a mock response with a custom status code."""
        data = {"id": 1}
        response = create_mock_response(data, status_code=201)

        assert response["data"] == data
        assert response["status_code"] == 201
