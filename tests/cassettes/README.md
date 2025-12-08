# VCR Cassettes for API Testing

This directory contains VCR cassettes - recorded HTTP interactions with the GitGuardian API.

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

- `Authorization` headers are filtered
- `X-Api-Key` headers are filtered
- Query parameters `api_key` and `token` are filtered

However, **always review cassettes before committing** to ensure no sensitive data remains in response bodies.

## Replay Mode

By default, VCR uses `record_mode="once"`:
- Records the first time a cassette is used
- Replays from that recording thereafter
- Fails if a cassette doesn't exist and recording fails

## Troubleshooting

### "GITGUARDIAN_API_KEY is not set" warning
Set the environment variable before running tests:
```bash
export GITGUARDIAN_API_KEY="your-token"
```

### Test fails with 401 Unauthorized
Your API key may be invalid or expired. Generate a new PAT from the GitGuardian dashboard.

### Cassette not being created
1. Ensure `record_mode` is set to `"once"` (default)
2. Check that the cassettes directory exists
3. Verify network connectivity to the API

### Tests fail after API changes
Delete the cassette and re-record:
```bash
rm tests/cassettes/test_name.yaml
ENABLE_LOCAL_OAUTH=false uv run pytest tests/path::test_name -v
```
