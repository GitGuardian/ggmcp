"""The committed tool-contracts.json matches the tools the server registers."""

from pathlib import Path

from gg_mcp_server.register_tools import register_tools
from gg_mcp_server.tool_contracts import (
    REGENERATE_COMMAND,
    TOOL_CONTRACTS_FILENAME,
    build_tool_contracts,
    render_tool_contracts,
)

COMMITTED_CONTRACTS = Path(__file__).resolve().parents[1] / TOOL_CONTRACTS_FILENAME


async def test_committed_tool_contracts_are_up_to_date():
    """
    GIVEN the tools the server registers
    WHEN their contracts are generated in memory
    THEN they equal the committed tool-contracts.json, byte for byte
    """
    expected = render_tool_contracts(await build_tool_contracts())
    committed = COMMITTED_CONTRACTS.read_text(encoding="utf-8") if COMMITTED_CONTRACTS.exists() else ""

    assert committed == expected, (
        f"{TOOL_CONTRACTS_FILENAME} is out of date with the registered tools. "
        f"Run `{REGENERATE_COMMAND}` and commit the result."
    )


async def test_every_registered_tool_has_a_contract():
    """
    GIVEN the generated contracts
    WHEN they are compared with the tools register_tools declares
    THEN every tool is listed once, with input and output schemas and its scopes
    """
    contracts = (await build_tool_contracts())["tools"]

    registered: list[str] = []

    class _Recorder:
        def tool(self, fn, *args, **kwargs):
            registered.append(kwargs.get("name") or fn.__name__)

    register_tools(_Recorder())  # type: ignore[arg-type]

    assert [c["name"] for c in contracts] == sorted(registered)
    for contract in contracts:
        assert contract["inputSchema"]["type"] == "object", contract["name"]
        assert contract["outputSchema"]["type"] == "object", contract["name"]
        assert isinstance(contract["requiredScopes"], list), contract["name"]
    scopes = {c["name"]: c["requiredScopes"] for c in contracts}
    assert scopes["scan_secrets"] == ["scan"]
    assert scopes["list_internal_incident_members"] == ["incidents:read", "members:read"]
    assert scopes["get_my_identity"] == []
