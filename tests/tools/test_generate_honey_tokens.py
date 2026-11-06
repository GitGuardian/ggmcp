from unittest.mock import AsyncMock

import pytest
from fastmcp.exceptions import ToolError


@pytest.mark.asyncio
async def test_generate_honeytoken_surfaces_api_detail_on_400(caplog):
    """A 400 from the API (e.g. duplicate name) is surfaced to the caller as a ToolError
    carrying the API's detail, and logged at warning — not error — so it does not become
    Sentry noise (GIM-MCP-SERVER-Z)."""
    import logging
    from unittest.mock import MagicMock, patch

    import httpx

    from gg_api_core.tools.generate_honey_token import GenerateHoneytokenParams, generate_honeytoken

    detail = "Another active honeytoken already exists with this name"
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.json.return_value = {"detail": detail}
    error = httpx.HTTPStatusError("400", request=MagicMock(), response=mock_response)

    mock_client = AsyncMock()
    mock_client.create_honeytoken = AsyncMock(side_effect=error)

    with patch("gg_api_core.tools.generate_honey_token.get_client", AsyncMock(return_value=mock_client)):
        with caplog.at_level(logging.WARNING, logger="gg_api_core.tools.generate_honey_token"):
            with pytest.raises(ToolError) as excinfo:
                # new_token=True skips the reuse lookup and goes straight to creation.
                await generate_honeytoken(GenerateHoneytokenParams(name="dup", new_token=True))

    assert detail in str(excinfo.value)
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert not errors, f"a handled 400 must not be logged at ERROR level: {errors}"
