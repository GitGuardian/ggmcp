"""Contract tests for canonical-to-wire incident filter adapters."""

from unittest.mock import AsyncMock

import pytest
from gg_api_core import incident_filter_adapters
from gg_api_core.client import GitGuardianClient


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method_name", "endpoint"),
    [
        ("list_incidents_for_mcp", "/incidents-for-mcp"),
        ("count_incidents_for_mcp", "/incidents-for-mcp/count"),
    ],
)
async def test_mcp_endpoints_translate_the_same_canonical_filters(method_name, endpoint):
    """
    GIVEN the same canonical filters for both MCP incident endpoints
    WHEN the client builds each endpoint's query
    THEN exact private wire values are sent for every translated vocabulary
    """
    client = GitGuardianClient(personal_access_token="test_token")
    client._request_get = AsyncMock(return_value={})

    await getattr(client, method_name)(
        status=["TRIGGERED", "ASSIGNED"],
        severity=["critical", "unknown"],
        validity=["valid", "unknown"],
        source_type=["github", "gitlab"],
        integration=["github", "github_enterprise_server", "gitlab"],
    )

    assert client._request_get.call_args.args[0] == endpoint
    query = client._request_get.call_args.kwargs["params"]
    assert query["status__in"] == "TRIGGERED,ASSIGNED"
    assert query["severity__in"] == "10,100"
    assert query["validity__in"] == "valid,not_checked"
    assert query["source_type__in"] == "gh_repository,gl_project"
    assert query["integration__in"] == "gh,ghe,gl"


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("status", ["TRIGGERED", "ASSIGNED", "RESOLVED", "IGNORED"], ["TRIGGERED", "ASSIGNED", "RESOLVED", "IGNORED"]),
        ("status", "TRIGGERED", ["TRIGGERED"]),
        ("severity", ["critical", "high", "medium", "low", "info", "unknown"], [10, 20, 30, 40, 50, 100]),
        ("severity", ["unknown", "low"], [100, 40]),
        ("validity", ["valid", "unknown"], ["valid", "not_checked"]),
        ("validity", "invalid", ["invalid"]),
        ("source_type", ["github", "gitlab", "azure_devops"], ["gh_repository", "gl_project", "ado_repository"]),
        ("source_type", "bitbucket", ["bb_repository"]),
        ("integration", ["github", "github_enterprise_server", "gitlab"], ["gh", "ghe", "gl"]),
        ("source_type", "custom_source", ["custom_source"]),
    ],
)
def test_to_mcp_translates_canonical_values_to_wire(field, value, expected):
    """
    GIVEN canonical filter values for a field (already normalized to a list or a single value)
    WHEN translating them for /incidents-for-mcp
    THEN the exact private wire values are produced
    """
    assert incident_filter_adapters.to_mcp(field, value) == expected


@pytest.mark.parametrize(
    ("field", "value", "allowed"),
    [
        ("status", "OPENED", "TRIGGERED"),
        ("severity", "10", "critical"),
        ("validity", "not_checked", "valid"),
        ("source_type", "unknown", "github"),
        ("integration", "ghe", "github"),
        ("status", ["TRIGGERED", "OPENED"], "TRIGGERED"),
    ],
)
def test_to_mcp_rejects_unsupported_values_with_allowed_list(field, value, allowed):
    """
    GIVEN an unsupported value for a translated field
    WHEN translating it
    THEN ValueError raises naming the field and an allowed value
    """
    with pytest.raises(ValueError) as exc_info:
        incident_filter_adapters.to_mcp(field, value)
    message = str(exc_info.value)
    assert f"Invalid {field} value" in message
    assert allowed in message


@pytest.mark.asyncio
async def test_low_level_client_rejects_opened_without_an_api_call():
    """
    GIVEN the noncanonical pseudo-status OPENED
    WHEN the low-level MCP endpoint adapter validates it
    THEN it raises with allowed values and makes no API request
    """
    client = GitGuardianClient(personal_access_token="test_token")
    client._request_get = AsyncMock()

    with pytest.raises(ValueError, match="Invalid status value 'OPENED'.*TRIGGERED"):
        await client.list_incidents_for_mcp(status="OPENED")  # type: ignore[arg-type]

    client._request_get.assert_not_called()


@pytest.mark.asyncio
async def test_public_occurrences_keep_canonical_values():
    """
    GIVEN canonical severity, status, and validity filters
    WHEN building a public occurrence query
    THEN public wire values remain unchanged and are comma-separated
    """
    client = GitGuardianClient(personal_access_token="test_token")
    client._request_list = AsyncMock(return_value={"data": [], "cursor": None, "has_more": False})

    await client.list_public_occurrences(
        incident_id=1,
        severity=["critical", "unknown"],
        status=["TRIGGERED", "ASSIGNED"],
        validity=["valid", "unknown"],
    )

    query = client._request_list.call_args.kwargs["params"]
    assert query["severity"] == "critical,unknown"
    assert query["status"] == "TRIGGERED,ASSIGNED"
    assert query["validity"] == "valid,unknown"
