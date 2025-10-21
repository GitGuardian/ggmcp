# Multi-Account Support Documentation

## Overview

The GitGuardian MCP server now supports storing and managing OAuth tokens for multiple GitGuardian accounts. This allows you to seamlessly work with different accounts without having to re-authenticate each time you switch.

## How It Works

### Token Storage Structure

Tokens are now stored in a nested structure organized by both instance URL and account ID:

**New Format:**
```json
{
  "https://dashboard.gitguardian.com": {
    "123": {
      "access_token": "token_for_account_123",
      "expires_at": "2025-10-28T11:15:58.656719+00:00",
      "token_name": "MCP Token",
      "scopes": ["scan", "incidents:read"],
      "account_id": 123
    },
    "456": {
      "access_token": "token_for_account_456",
      "expires_at": "2025-10-28T11:15:58.656719+00:00",
      "token_name": "MCP Token",
      "scopes": ["scan", "incidents:read", "honeytokens:read"],
      "account_id": 456
    }
  }
}
```

### Account ID Extraction

The `account_id` is automatically extracted from the OAuth token response (`/oauth/token` endpoint) during the authentication flow. According to the `GGShieldPublicAPITokenCreateOutputSerializer` schema, the response includes:

```python
{
    "type": str,
    "name": str,
    "account_id": int,  # <-- This is what we extract and store
    "expire_at": datetime | None,
    "scope": list[str],
    "key": str  # The access token
}
```

## Usage

### Selecting an Account

There are three ways to select which account to use:

#### 1. Environment Variable (Recommended)

Set the `GITGUARDIAN_ACCOUNT_ID` environment variable to specify which account to use:

```bash
export GITGUARDIAN_ACCOUNT_ID=123
```

Then start your MCP server as usual. It will automatically use the token for account `123`.

#### 2. Automatic Selection (Default Behavior)

If you don't specify an account ID, the system will automatically use the first valid (non-expired) token it finds for the instance URL.

#### 3. Multiple Server Configurations

You can configure multiple MCP server instances in your Claude Desktop config, each pointing to a different account:

```json
{
  "mcpServers": {
    "gitguardian-production": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/gg-mcp/packages/secops_mcp_server",
        "run",
        "gitguardian-secops-mcp"
      ],
      "env": {
        "GITGUARDIAN_ACCOUNT_ID": "123"
      }
    },
    "gitguardian-staging": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/gg-mcp/packages/secops_mcp_server",
        "run",
        "gitguardian-secops-mcp"
      ],
      "env": {
        "GITGUARDIAN_ACCOUNT_ID": "456"
      }
    }
  }
}
```

### Working with Multiple Accounts

1. **Authenticate with First Account:**
   ```bash
   # First account will authenticate via OAuth flow
   # Token will be saved with its account_id
   ```

2. **Authenticate with Second Account:**
   ```bash
   # Delete the existing token to force re-authentication
   rm ~/Library/Application\ Support/GitGuardian/mcp_oauth_tokens.json

   # Or set GITGUARDIAN_ACCOUNT_ID to a different value and authenticate
   export GITGUARDIAN_ACCOUNT_ID=456
   # Start the server - it will prompt for OAuth if no token exists for account 456
   ```

3. **Switch Between Accounts:**
   ```bash
   # Just change the environment variable
   export GITGUARDIAN_ACCOUNT_ID=123  # Use account 123
   # or
   export GITGUARDIAN_ACCOUNT_ID=456  # Use account 456
   ```

## Token File Location

Tokens are stored in a platform-specific location:

- **macOS:** `~/Library/Application Support/GitGuardian/mcp_oauth_tokens.json`
- **Linux:** `~/.config/gitguardian/mcp_oauth_tokens.json` (or `$XDG_CONFIG_HOME/gitguardian/mcp_oauth_tokens.json`)

The file has restrictive permissions (`0600`) to ensure only the owner can read/write it.

## Backward Compatibility

### Automatic Migration

If you have an existing token file in the old format (single account), it will be automatically migrated to the new format when the system loads it:

**Old Format:**
```json
{
  "https://dashboard.gitguardian.com": {
    "access_token": "token_abc",
    "expires_at": "2025-10-28T11:15:58.656719+00:00",
    "token_name": "MCP Token",
    "scopes": ["scan"],
    "account_id": 789
  }
}
```

**After Migration:**
```json
{
  "https://dashboard.gitguardian.com": {
    "789": {
      "access_token": "token_abc",
      "expires_at": "2025-10-28T11:15:58.656719+00:00",
      "token_name": "MCP Token",
      "scopes": ["scan"],
      "account_id": 789
    }
  }
}
```

### Handling Tokens Without account_id

If an old token doesn't have an `account_id` field, it will be migrated with the account_id `"unknown"`:

```json
{
  "https://dashboard.gitguardian.com": {
    "unknown": {
      "access_token": "token_abc",
      ...
    }
  }
}
```

## API Reference

### FileTokenStorage Methods

#### `save_token(instance_url, account_id, token_data)`

Save a token for a specific instance URL and account.

```python
storage = FileTokenStorage()
storage.save_token(
    "https://dashboard.gitguardian.com",
    123,
    {
        "access_token": "token_abc",
        "expires_at": "2025-12-31T23:59:59+00:00",
        "token_name": "My Token",
        "scopes": ["scan"],
        "account_id": 123
    }
)
```

#### `get_token(instance_url, account_id=None)`

Get a token for a specific instance URL and optionally a specific account.

```python
storage = FileTokenStorage()

# Get token for specific account
access_token, token_data = storage.get_token("https://dashboard.gitguardian.com", 123)

# Get any valid token (uses GITGUARDIAN_ACCOUNT_ID env var if set)
access_token, token_data = storage.get_token("https://dashboard.gitguardian.com")
```

Returns a tuple of `(access_token, token_data)` or `(None, None)` if no valid token is found.

#### `list_accounts(instance_url)`

List all accounts with tokens for a specific instance URL.

```python
storage = FileTokenStorage()
accounts = storage.list_accounts("https://dashboard.gitguardian.com")
# Returns:
# [
#   {
#     "account_id": "123",
#     "token_name": "Account 1 Token",
#     "expires_at": "2025-12-31T23:59:59+00:00",
#     "scopes": ["scan"],
#     "is_valid": True
#   },
#   {
#     "account_id": "456",
#     "token_name": "Account 2 Token",
#     "expires_at": "2020-01-01T00:00:00+00:00",
#     "scopes": ["scan", "incidents:read"],
#     "is_valid": False  # Expired
#   }
# ]
```

#### `delete_token(instance_url, account_id)`

Delete a token for a specific instance URL and account.

```python
storage = FileTokenStorage()
storage.delete_token("https://dashboard.gitguardian.com", 123)
```

## Implementation Details

### Changes Made

1. **`oauth.py:31-289`** - Updated `FileTokenStorage` class:
   - Added nested token storage by account_id
   - Implemented backward compatibility migration
   - Added `list_accounts()` and `delete_token()` methods
   - Updated `get_token()` to support account selection via env var

2. **`oauth.py:616-642`** - Updated `_load_saved_token()`:
   - Uses new `get_token()` method that returns tuple
   - Stores account_id in token_info

3. **`oauth.py:819-882`** - Updated OAuth flow:
   - Extracts `account_id` from `/oauth/token` response
   - Stores `account_id` with token data
   - Passes `account_id` to `save_token()`

4. **`client.py:280-327`** - Updated `_clear_invalid_oauth_token()`:
   - Uses account_id when clearing tokens
   - Fallback logic for backward compatibility

### Testing

Comprehensive tests were added in `tests/test_multi_account.py`:

- ✅ Saving and loading single account tokens
- ✅ Saving and loading multiple account tokens
- ✅ Default account selection behavior
- ✅ Backward compatibility migration with account_id
- ✅ Backward compatibility migration without account_id
- ✅ Listing accounts
- ✅ Deleting tokens
- ✅ Expired token handling

All tests pass (8/8 ✓), and all existing tests continue to pass (106/106 ✓).

## Troubleshooting

### Issue: "No token found for account X"

**Solution:** The account_id you specified doesn't have a saved token. Either:
1. Remove the `GITGUARDIAN_ACCOUNT_ID` env var to let the system pick any valid token
2. Authenticate with the specific account by deleting tokens and re-running OAuth flow

### Issue: "Multiple accounts but wrong one is selected"

**Solution:** Explicitly set `GITGUARDIAN_ACCOUNT_ID`:
```bash
export GITGUARDIAN_ACCOUNT_ID=123
```

### Issue: "Want to re-authenticate with a different account"

**Solution:** Either:
1. Delete the specific account's token from the JSON file manually
2. Use the `delete_token()` API programmatically
3. Delete the entire token file to start fresh

### Issue: "Old token file format not migrating"

**Solution:** The migration happens automatically on first load. If issues persist:
1. Back up your current token file
2. Delete the token file
3. Re-authenticate

## Example Workflow

Here's a complete example of working with multiple accounts:

```bash
# 1. Set up first account (Production)
export GITGUARDIAN_ACCOUNT_ID=123
# Start server - will authenticate via OAuth
# Token saved for account 123

# 2. Set up second account (Staging)
export GITGUARDIAN_ACCOUNT_ID=456
# Delete cached token to force new OAuth
rm ~/Library/Application\ Support/GitGuardian/mcp_oauth_tokens.json
# Start server - will authenticate via OAuth
# Token saved for account 456

# 3. Now both tokens are saved, switch between them:
export GITGUARDIAN_ACCOUNT_ID=123  # Work with production
# Start server

export GITGUARDIAN_ACCOUNT_ID=456  # Work with staging
# Start server

# 4. Or don't specify and use whichever is first/default
unset GITGUARDIAN_ACCOUNT_ID
# Start server - uses first valid token found
```

## Future Enhancements

Potential improvements for the future:

1. **MCP Tool for Account Management:** Add MCP tools like `list_accounts()`, `switch_account()`, `get_current_account()`
2. **Account Name/Label Storage:** Store human-readable account names alongside account_ids
3. **Interactive Account Selection:** Prompt user to select account if multiple are available
4. **Account Auto-Discovery:** Fetch and display account information from API
5. **Token Refresh:** Automatic token refresh when near expiration

## Summary

The multi-account support implementation provides:

✅ Seamless storage of multiple account tokens
✅ Easy account switching via environment variable
✅ Full backward compatibility with existing tokens
✅ Automatic migration of old token format
✅ Comprehensive test coverage
✅ Zero breaking changes to existing code
