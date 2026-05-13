"""Tests for the OAuth-proxy ASGI middleware that converts downstream 401s."""

import pytest
from gg_api_core.oauth_proxy_auth import (
    AdvertiseAuthorizationServerMetadataMiddleware,
    TranslateDownstreamUnauthorizedMiddleware,
    mark_downstream_unauthorized,
)


async def _drive(app):
    """Run an ASGI app once and return (status, headers)."""
    captured = {}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            captured["status"] = message["status"]
            captured["headers"] = message.get("headers", [])

    scope = {"type": "http", "path": "/mcp", "method": "POST", "headers": []}
    await app(scope, receive, send)
    return captured.get("status"), captured.get("headers", [])


@pytest.mark.asyncio
async def test_translate_rewrites_status_when_flag_set():
    async def inner_app(scope, receive, send):
        mark_downstream_unauthorized()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = TranslateDownstreamUnauthorizedMiddleware(inner_app)
    status, _ = await _drive(middleware)
    assert status == 401


@pytest.mark.asyncio
async def test_translate_passthrough_when_flag_unset():
    async def inner_app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = TranslateDownstreamUnauthorizedMiddleware(inner_app)
    status, _ = await _drive(middleware)
    assert status == 200


@pytest.mark.asyncio
async def test_advertise_synthesizes_header_with_both_params():
    """Bridged 401 (no existing WWW-Authenticate) gets resource_metadata + as_metadata."""

    async def inner_app(scope, receive, send):
        mark_downstream_unauthorized()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    # Stack as the proxy would: Translate (innermost) → Advertise (outermost).
    stacked = AdvertiseAuthorizationServerMetadataMiddleware(
        TranslateDownstreamUnauthorizedMiddleware(inner_app),
        as_metadata_url="https://mcp.example.com/.well-known/oauth-authorization-server",
        resource_metadata_url_provider=lambda: "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
    )
    status, headers = await _drive(stacked)
    assert status == 401
    header_map = {name.decode(): value.decode() for name, value in headers}
    www_auth = header_map["www-authenticate"]
    assert www_auth.startswith("Bearer ")
    assert 'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"' in www_auth
    assert 'as_metadata="https://mcp.example.com/.well-known/oauth-authorization-server"' in www_auth


@pytest.mark.asyncio
async def test_advertise_synthesizes_header_without_resource_metadata_when_unavailable():
    """If the resource URL isn't set yet, fall back to as_metadata-only."""

    async def inner_app(scope, receive, send):
        mark_downstream_unauthorized()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    stacked = AdvertiseAuthorizationServerMetadataMiddleware(
        TranslateDownstreamUnauthorizedMiddleware(inner_app),
        as_metadata_url="https://mcp.example.com/.well-known/oauth-authorization-server",
        resource_metadata_url_provider=lambda: None,
    )
    status, headers = await _drive(stacked)
    assert status == 401
    header_map = {name.decode(): value.decode() for name, value in headers}
    www_auth = header_map["www-authenticate"]
    assert "resource_metadata=" not in www_auth
    assert "as_metadata=" in www_auth


@pytest.mark.asyncio
async def test_advertise_appends_as_metadata_to_existing_header():
    """When FastMCP's auth already emitted WWW-Authenticate, just append as_metadata."""

    async def inner_app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (
                        b"www-authenticate",
                        b'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"',
                    )
                ],
            }
        )
        await send({"type": "http.response.body", "body": b""})

    stacked = AdvertiseAuthorizationServerMetadataMiddleware(
        inner_app,
        as_metadata_url="https://mcp.example.com/.well-known/oauth-authorization-server",
        resource_metadata_url_provider=lambda: "https://should-not-be-used.example.com",
    )
    status, headers = await _drive(stacked)
    assert status == 401
    header_map = {name.decode(): value.decode() for name, value in headers}
    www_auth = header_map["www-authenticate"]
    # The original resource_metadata is preserved; only as_metadata is appended.
    assert www_auth.count("resource_metadata=") == 1
    assert "should-not-be-used" not in www_auth
    assert ", as_metadata=" in www_auth
