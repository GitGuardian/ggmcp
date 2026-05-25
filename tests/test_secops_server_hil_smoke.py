"""Smoke test: load the SecOps server and assert all HIL tools + prompts are wired."""

import os

import pytest

# Pin a fake PAT so the secops module import doesn't try OAuth at startup.
os.environ.setdefault("GITGUARDIAN_PERSONAL_ACCESS_TOKEN", "fake-token-for-tests")
os.environ.setdefault("ENABLE_LOCAL_OAUTH", "false")


EXPECTED_HIL_TOOLS = {
    "dns_lookup",
    "reverse_dns_lookup",
    "rdap_domain_lookup",
    "rdap_ip_lookup",
    "check_host_reachability",
    "check_ssl_certificate",
    "search_github_issues",
    "search_github_code",
    "get_github_repo_metadata",
    "list_github_repo_contributors",
}

EXPECTED_HIL_PROMPTS = {
    "triage_public_secret_leak",
    "qualify_high_impact_leak",
    "investigate_secret_repository",
}


@pytest.mark.asyncio
async def test_secops_server_registers_all_hil_tools():
    from secops_mcp_server.server import mcp

    tools = await mcp._list_tools()
    tool_names = {t.name for t in tools}
    missing = EXPECTED_HIL_TOOLS - tool_names
    assert not missing, f"missing HIL tools on secops server: {missing}"


@pytest.mark.asyncio
async def test_secops_server_registers_all_hil_prompts():
    from secops_mcp_server.server import mcp

    prompts = await mcp._list_prompts()
    prompt_names = {p.name for p in prompts}
    missing = EXPECTED_HIL_PROMPTS - prompt_names
    assert not missing, f"missing HIL prompts on secops server: {missing}"


@pytest.mark.asyncio
async def test_developer_server_does_not_register_hil_tools():
    """The plan only registers HIL on secops. Sanity-check the dev server.

    The developer server registers its own tools via ``register_developer_tools``
    and inherits no HIL bindings. Re-importing here is cheap.
    """
    from developer_mcp_server.server import mcp as dev_mcp

    tools = await dev_mcp._list_tools()
    tool_names = {t.name for t in tools}
    assert not (EXPECTED_HIL_TOOLS & tool_names), (
        f"HIL tools leaked onto developer server: {EXPECTED_HIL_TOOLS & tool_names}"
    )
