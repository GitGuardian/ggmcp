# VCR Cassettes for API Testing

This directory contains VCR cassettes - recorded HTTP interactions with the GitGuardian API.

> **Important**: Cassettes are **recorded locally** and committed to the repository. CI replays from these committed cassettes without requiring API credentials. Developers should **periodically re-record cassettes** to keep them in sync with API changes.

## Recording Workflow

```
Local (with API key)                CI (no API key)
┌───────────────────────────┐       ┌─────────────────────┐
│ make test-vcr-with-env    │ ───▶  │ make test-vcr       │
│ (real API calls)          │ git   │ (replay only)       │
└───────────────────────────┘ push  └─────────────────────┘
```

## What are VCR Cassettes?

VCR cassettes record real HTTP requests and responses the first time a test runs, then replay those recorded responses on subsequent runs. This provides:

- **Realistic testing**: Tests use actual API responses
- **Fast execution**: No network calls after initial recording
- **Reproducible results**: Same responses every time
- **Offline testing**: Works without network access after recording

## Recording New Cassettes

### Prerequisites

1. A GitGuardian Personal Access Token (PAT) with appropriate scopes
2. Network access to the GitGuardian API

### Steps to Record

1. **Set your API key:**
   ```bash
   export GITGUARDIAN_API_KEY="your-personal-access-token"
   ```

2. **(Optional) Set custom GitGuardian URL:**
   ```bash
   # For self-hosted or EU instances
   export GITGUARDIAN_URL="https://dashboard.eu1.gitguardian.com"
   ```

3. **Delete existing cassette (if re-recording):**
   ```bash
   rm tests/cassettes/test_your_test_name.yaml
   ```

4. **Run the test:**
   ```bash
   ENABLE_LOCAL_OAUTH=false uv run pytest tests/test_vcr_example.py::test_your_test_name -v
   ```

5. **Verify the cassette was created:**
   ```bash
   ls -la tests/cassettes/
   ```

### Recording All Example Tests

```bash
export GITGUARDIAN_API_KEY="your-token"
ENABLE_LOCAL_OAUTH=false uv run pytest tests/test_vcr_example.py -v
```

## Writing Tests with Cassettes

### Basic Pattern (Context Manager)

```python
import pytest
from tests.conftest import my_vcr

@pytest.mark.vcr_test  # Disables auto-mocking
@pytest.mark.asyncio
async def test_something(real_client):
    with my_vcr.use_cassette("test_something"):
        result = await real_client.some_method()
        assert result is not None
```

### Decorator Pattern

```python
@pytest.mark.vcr_test
@pytest.mark.asyncio
@my_vcr.use_cassette("test_something")
async def test_something(real_client):
    result = await real_client.some_method()
    assert result is not None
```

### Key Points

- **`@pytest.mark.vcr_test`**: Required to disable automatic mocking
- **`real_client` fixture**: Provides a real GitGuardianClient instance
- **Cassette names**: Should match test names for clarity

## Cassette File Format

Cassettes are YAML files containing:

```yaml
interactions:
  - request:
      body: null
      headers:
        Authorization: FILTERED  # Sensitive data is filtered
      method: GET
      uri: https://api.gitguardian.com/v1/endpoint
    response:
      body:
        string: '{"data": [...]}'
      headers:
        content-type: application/json
      status:
        code: 200
        message: OK
version: 1
```

## Security

Cassettes are **automatically scrubbed** of sensitive data:

- Request headers are filtered (only safe headers like `content-type` are kept)
- Response body fields are redacted: `secret_key`, `access_token_id`, `token`, `api_key`, `password`, `secret`, `credential`, `share_url`
- Share URLs containing incident tokens are redacted
- POST data parameters are filtered: `api_key`, `secret`, `client_id`, `client_secret`, `token`, `password`

Redacted values appear as `[REDACTED]` in cassette files.

## Replay Mode

By default, VCR uses `record_mode="once"`:
- Records the first time a cassette is used
- Replays from that recording thereafter
- Fails if a cassette doesn't exist and recording fails

## Troubleshooting

### Test fails with 401 Unauthorized (when recording)
Your API key may be invalid or expired. Generate a new PAT from the GitGuardian dashboard.

### Cassette not being created
1. Ensure `GITGUARDIAN_API_KEY` is set in your `.env` file
2. Check that the cassettes directory exists
3. Verify network connectivity to the API

### Tests fail after API changes
Delete the cassette and re-record locally:
```bash
rm tests/cassettes/test_name.yaml
make test-vcr-with-env
```

### Re-record all cassettes
```bash
rm tests/cassettes/*.yaml
make test-vcr-with-env
```
