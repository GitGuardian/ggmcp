"""Test multi-account token storage functionality."""

import json
import tempfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from gg_api_core.oauth import FileTokenStorage, StoredOAuthToken


def test_save_and_load_single_account():
    """Test saving and loading a token for a single account."""
    with tempfile.TemporaryDirectory() as tmpdir:
        token_file = Path(tmpdir) / "tokens.json"
        storage = FileTokenStorage(token_file=token_file)

        # Save a token
        instance_url = "https://dashboard.gitguardian.com"
        account_id = 123
        token_data = {
            "access_token": "token_abc123",
            "expires_at": "2025-12-31T23:59:59+00:00",
            "token_name": "Test Token",
            "scopes": ["scan", "incidents:read"],
            "account_id": account_id,
        }

        storage.save_token(instance_url, account_id, token_data)

        # Load the token
        access_token, loaded_data = storage.get_token(instance_url, account_id)

        assert access_token == "token_abc123"
        assert loaded_data["account_id"] == account_id
        assert loaded_data["token_name"] == "Test Token"


def test_save_multiple_accounts():
    """Test saving tokens for multiple accounts on the same instance."""
    with tempfile.TemporaryDirectory() as tmpdir:
        token_file = Path(tmpdir) / "tokens.json"
        storage = FileTokenStorage(token_file=token_file)

        instance_url = "https://dashboard.gitguardian.com"

        # Save tokens for two different accounts
        account1_data = {
            "access_token": "token_account1",
            "expires_at": "2025-12-31T23:59:59+00:00",
            "token_name": "Account 1 Token",
            "scopes": ["scan"],
            "account_id": 123,
        }
        storage.save_token(instance_url, 123, account1_data)

        account2_data = {
            "access_token": "token_account2",
            "expires_at": "2025-12-31T23:59:59+00:00",
            "token_name": "Account 2 Token",
            "scopes": ["scan", "incidents:read"],
            "account_id": 456,
        }
        storage.save_token(instance_url, 456, account2_data)

        # Load tokens for both accounts
        token1, data1 = storage.get_token(instance_url, 123)
        token2, data2 = storage.get_token(instance_url, 456)

        assert token1 == "token_account1"
        assert data1["account_id"] == 123
        assert data1["token_name"] == "Account 1 Token"

        assert token2 == "token_account2"
        assert data2["account_id"] == 456
        assert data2["token_name"] == "Account 2 Token"


def test_account_selection_default():
    """Test that first valid account is selected when no account_id is specified."""
    with tempfile.TemporaryDirectory() as tmpdir:
        token_file = Path(tmpdir) / "tokens.json"
        storage = FileTokenStorage(token_file=token_file)

        instance_url = "https://dashboard.gitguardian.com"

        # Save tokens for two accounts
        storage.save_token(
            instance_url,
            123,
            {
                "access_token": "token1",
                "expires_at": "2025-12-31T23:59:59+00:00",
                "account_id": 123,
            },
        )
        storage.save_token(
            instance_url,
            456,
            {
                "access_token": "token2",
                "expires_at": "2025-12-31T23:59:59+00:00",
                "account_id": 456,
            },
        )

        # Get token without specifying account_id
        access_token, token_data = storage.get_token(instance_url)

        # Should return one of the tokens (first valid one)
        assert access_token in ["token1", "token2"]
        assert token_data["account_id"] in [123, 456]


def test_migrate_old_format_to_new():
    """Test migration from old single-account format to new multi-account format."""
    with tempfile.TemporaryDirectory() as tmpdir:
        token_file = Path(tmpdir) / "tokens.json"

        # Create old format token file
        old_format = {
            "https://dashboard.gitguardian.com": {
                "access_token": "old_token",
                "expires_at": "2025-12-31T23:59:59+00:00",
                "token_name": "Old Token",
                "scopes": ["scan"],
                "account_id": 789,
            }
        }

        with open(token_file, "w") as f:
            json.dump(old_format, f)

        # Load with FileTokenStorage (should trigger migration)
        storage = FileTokenStorage(token_file=token_file)
        tokens = storage.load_tokens()

        # Check that format was migrated
        assert "https://dashboard.gitguardian.com" in tokens
        instance_tokens = tokens["https://dashboard.gitguardian.com"]
        assert isinstance(instance_tokens, dict)
        assert "789" in instance_tokens
        assert instance_tokens["789"]["access_token"] == "old_token"


def test_migrate_old_format_without_account_id():
    """Test migration when old format doesn't have account_id."""
    with tempfile.TemporaryDirectory() as tmpdir:
        token_file = Path(tmpdir) / "tokens.json"

        # Create old format without account_id
        old_format = {
            "https://dashboard.gitguardian.com": {
                "access_token": "old_token",
                "expires_at": "2025-12-31T23:59:59+00:00",
                "token_name": "Old Token",
                "scopes": ["scan"],
            }
        }

        with open(token_file, "w") as f:
            json.dump(old_format, f)

        # Load with FileTokenStorage
        storage = FileTokenStorage(token_file=token_file)
        tokens = storage.load_tokens()

        # Check migration occurred with "unknown" account_id
        assert "https://dashboard.gitguardian.com" in tokens
        instance_tokens = tokens["https://dashboard.gitguardian.com"]
        assert isinstance(instance_tokens, dict)
        assert "unknown" in instance_tokens
        assert instance_tokens["unknown"]["access_token"] == "old_token"


def test_list_accounts():
    """Test listing all accounts for an instance."""
    with tempfile.TemporaryDirectory() as tmpdir:
        token_file = Path(tmpdir) / "tokens.json"
        storage = FileTokenStorage(token_file=token_file)

        instance_url = "https://dashboard.gitguardian.com"

        # Save tokens for multiple accounts
        storage.save_token(
            instance_url,
            123,
            {
                "access_token": "token1",
                "expires_at": "2025-12-31T23:59:59+00:00",
                "token_name": "Account 1",
                "scopes": ["scan"],
                "account_id": 123,
            },
        )
        storage.save_token(
            instance_url,
            456,
            {
                "access_token": "token2",
                "expires_at": "2025-12-31T23:59:59+00:00",
                "token_name": "Account 2",
                "scopes": ["scan", "incidents:read"],
                "account_id": 456,
            },
        )

        # List accounts
        accounts = storage.list_accounts(instance_url)

        assert len(accounts) == 2
        account_ids = [acc["account_id"] for acc in accounts]
        assert "123" in account_ids
        assert "456" in account_ids


def test_delete_token():
    """Test deleting a token for a specific account."""
    with tempfile.TemporaryDirectory() as tmpdir:
        token_file = Path(tmpdir) / "tokens.json"
        storage = FileTokenStorage(token_file=token_file)

        instance_url = "https://dashboard.gitguardian.com"

        # Save tokens
        storage.save_token(
            instance_url,
            123,
            {
                "access_token": "token1",
                "expires_at": "2025-12-31T23:59:59+00:00",
                "account_id": 123,
            },
        )
        storage.save_token(
            instance_url,
            456,
            {
                "access_token": "token2",
                "expires_at": "2025-12-31T23:59:59+00:00",
                "account_id": 456,
            },
        )

        # Delete one token
        storage.delete_token(instance_url, 123)

        # Verify deletion
        token1, _ = storage.get_token(instance_url, 123)
        token2, _ = storage.get_token(instance_url, 456)

        assert token1 is None
        assert token2 == "token2"


def test_expired_token_not_returned():
    """Test that expired tokens are not returned."""
    with tempfile.TemporaryDirectory() as tmpdir:
        token_file = Path(tmpdir) / "tokens.json"
        storage = FileTokenStorage(token_file=token_file)

        instance_url = "https://dashboard.gitguardian.com"

        # Save an expired token
        storage.save_token(
            instance_url,
            123,
            {
                "access_token": "expired_token",
                "expires_at": "2020-01-01T00:00:00+00:00",  # Expired
                "account_id": 123,
            },
        )

        # Try to get the token
        access_token, token_data = storage.get_token(instance_url, 123)

        # Should return None for expired token
        assert access_token is None
        assert token_data is None


# Pydantic Model Tests


def test_stored_oauth_token_valid():
    """Test creating a valid StoredOAuthToken."""
    token_data = {
        "access_token": "token_abc123",
        "expires_at": "2025-12-31T23:59:59+00:00",
        "token_name": "Test Token",
        "scopes": ["scan", "incidents:read"],
        "account_id": 123,
    }

    token = StoredOAuthToken(**token_data)
    assert token.access_token == "token_abc123"
    assert token.token_name == "Test Token"
    assert token.account_id == 123


def test_stored_oauth_token_minimal():
    """Test creating StoredOAuthToken with minimal required fields."""
    token_data = {
        "access_token": "token_abc",
        "token_name": "Minimal Token",
    }

    token = StoredOAuthToken(**token_data)
    assert token.access_token == "token_abc"
    assert token.token_name == "Minimal Token"
    assert token.expires_at is None
    assert token.scopes == []
    assert token.account_id is None


def test_stored_oauth_token_missing_required():
    """Test that StoredOAuthToken validation fails without required fields."""
    # Missing access_token
    with pytest.raises(ValidationError):
        StoredOAuthToken(token_name="Test")

    # Missing token_name
    with pytest.raises(ValidationError):
        StoredOAuthToken(access_token="token_abc")


def test_stored_oauth_token_account_id_types():
    """Test StoredOAuthToken with different account_id types."""
    # Integer account_id
    token1 = StoredOAuthToken(
        access_token="token1", token_name="Token 1", account_id=123
    )
    assert token1.account_id == 123

    # String account_id (for backward compatibility)
    token2 = StoredOAuthToken(
        access_token="token2", token_name="Token 2", account_id="456"
    )
    assert token2.account_id == "456"

    # String "unknown" for legacy tokens
    token3 = StoredOAuthToken(
        access_token="token3", token_name="Token 3", account_id="unknown"
    )
    assert token3.account_id == "unknown"


def test_file_token_storage_validate_token_data():
    """Test FileTokenStorage.validate_token_data method."""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = FileTokenStorage(token_file=Path(tmpdir) / "tokens.json")

        # Valid token data
        valid_data = {
            "access_token": "token_abc",
            "token_name": "Valid Token",
            "scopes": ["scan"],
            "account_id": 123,
        }
        is_valid, error_msg = storage.validate_token_data(valid_data)
        assert is_valid is True
        assert error_msg == ""

        # Invalid token data (missing required field)
        invalid_data = {"token_name": "Invalid Token"}
        is_valid, error_msg = storage.validate_token_data(invalid_data)
        assert is_valid is False
        assert "access_token" in error_msg


def test_file_token_storage_get_schema():
    """Test FileTokenStorage.get_schema method."""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = FileTokenStorage(token_file=Path(tmpdir) / "tokens.json")

        schema = storage.get_schema()
        assert isinstance(schema, dict)
        assert "properties" in schema
        assert "access_token" in schema["properties"]
        assert "token_name" in schema["properties"]
        assert "scopes" in schema["properties"]


def test_stored_oauth_token_model_validation():
    """Test StoredOAuthToken model validation."""
    # Test with model_validate
    data = {
        "access_token": "token_abc",
        "expires_at": "2025-12-31T23:59:59+00:00",
        "token_name": "Test",
        "scopes": ["scan"],
        "account_id": 123,
    }

    token = StoredOAuthToken.model_validate(data)
    assert token.access_token == "token_abc"

    # Test model_dump
    dumped = token.model_dump()
    assert dumped["access_token"] == "token_abc"
    assert dumped["account_id"] == 123


def test_file_token_storage_save_with_validation():
    """Test that save_token validates data before storing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        token_file = Path(tmpdir) / "tokens.json"
        storage = FileTokenStorage(token_file=token_file)

        instance_url = "https://dashboard.gitguardian.com"
        account_id = 123

        # Valid token data
        token_data = {
            "access_token": "token_abc",
            "expires_at": "2025-12-31T23:59:59+00:00",
            "token_name": "Test Token",
            "scopes": ["scan"],
            "account_id": account_id,
        }

        # Should not raise, just log warning if validation fails
        storage.save_token(instance_url, account_id, token_data)

        # Verify it was saved
        loaded_token, _ = storage.get_token(instance_url, account_id)
        assert loaded_token == "token_abc"


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
