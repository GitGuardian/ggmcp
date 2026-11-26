"""Outgoing headers stay safe and follow the active MCP request."""

import asyncio
from types import SimpleNamespace

import pytest
from mcp.types import ClientCapabilities, Implementation, InitializeRequestParams

from gg_api_core.client import GitGuardianClient
from gg_api_core.request_headers import DEFAULT_USER_AGENT, build_request_headers, track_tool_call


@pytest.fixture
def request_context(monkeypatch):
    monkeypatch.delenv("MCP_PORT", raising=False)
    monkeypatch.setattr("gg_api_core.request_headers.get_http_headers", lambda **_: {})
    context = SimpleNamespace(session=SimpleNamespace(client_params=None))
    monkeypatch.setattr("gg_api_core.request_headers.get_context", lambda: context)
    return context


def _params(name="cursor", version="1.0", protocol="2026-07-28"):
    return InitializeRequestParams(
        client_info=Implementation(name=name, version=version),
        protocol_version=protocol,
        capabilities=ClientCapabilities(),
    )


def test_reused_client_reads_live_identity_and_preserves_privacy(request_context):
    client = GitGuardianClient(personal_access_token="test-token")
    assert client._base_headers()["User-Agent"] == f"{DEFAULT_USER_AGENT} (transport=stdio)"
    for name in ("cursor", "claude-code"):
        request_context.session.client_params = _params(name)
        headers = client._base_headers(privacy_mode=False)
        assert headers["User-Agent"] == f"{DEFAULT_USER_AGENT} (transport=stdio; client={name}/1.0; mcp=2026-07-28)"
        assert headers["X-Privacy-Mode"] == "false"
        assert headers["Authorization"] == "Token test-token"
    assert client._base_headers()["X-Privacy-Mode"] == "true"


def test_http_fallback_handshake_preference_and_explicit_override(request_context, monkeypatch):
    monkeypatch.setenv("MCP_PORT", "8080")
    monkeypatch.setattr("gg_api_core.request_headers.get_http_headers", lambda **_: {"user-agent": "http-client/2"})
    assert build_request_headers()["User-Agent"] == f"{DEFAULT_USER_AGENT} (transport=http; client=http-client/2)"
    request_context.session.client_params = _params()
    assert "client=cursor/1.0" in build_request_headers()["User-Agent"]
    assert GitGuardianClient(user_agent="explicit-agent")._base_headers()["User-Agent"] == "explicit-agent"


@pytest.mark.parametrize("source", ["handshake", "http"])
def test_untrusted_identity_fields_are_sanitized_and_bounded(request_context, monkeypatch, source):
    value = "evil)\r\n; mcp=forged,é" + "a" * 100
    if source == "handshake":
        request_context.session.client_params = _params(value, protocol="2026-07-28\n")
    else:
        monkeypatch.setattr("gg_api_core.request_headers.get_http_headers", lambda **_: {"user-agent": value})
    ua = build_request_headers()["User-Agent"]
    client = ua.split("client=")[1].split(";")[0].rstrip(")")
    assert len(client) == 64
    assert ua.isascii() and "\r" not in ua and "\n" not in ua
    assert ua.count("mcp=") == (1 if source == "handshake" else 0)


def test_headers_work_outside_mcp_context(monkeypatch):
    def no_context():
        raise RuntimeError("No active context found.")

    monkeypatch.setattr("gg_api_core.request_headers.get_context", no_context)
    monkeypatch.setattr("gg_api_core.request_headers.get_http_headers", lambda **_: {})
    monkeypatch.delenv("MCP_PORT", raising=False)
    assert build_request_headers() == {"User-Agent": f"{DEFAULT_USER_AGENT} (transport=stdio)"}


@pytest.mark.parametrize("tool", ["scan_secrets", "bad name", "tool\r\nInjected: x", "a" * 65])
def test_tool_header_is_validated_and_reset_on_failure(request_context, tool):
    with pytest.raises(ValueError), track_tool_call(tool):
        headers = build_request_headers()
        assert headers.get("X-GG-MCP-Tool") == (tool if tool == "scan_secrets" else None)
        raise ValueError("tool failed")
    assert "X-GG-MCP-Tool" not in build_request_headers()


async def test_concurrent_and_nested_tools_have_isolated_headers(request_context):
    async def call(name):
        with track_tool_call(name):
            await asyncio.sleep(0)
            with track_tool_call("nested"):
                assert build_request_headers()["X-GG-MCP-Tool"] == "nested"
            return build_request_headers()["X-GG-MCP-Tool"]

    assert await asyncio.gather(call("first"), call("second")) == ["first", "second"]
    assert "X-GG-MCP-Tool" not in build_request_headers()
