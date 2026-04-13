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
async def test_advertise_adds_as_metadata_param_to_401():
    async def inner_app(scope, receive, send):
        mark_downstream_unauthorized()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    # Stack as the proxy would: Translate (innermost) → Advertise (outermost).
    stacked = AdvertiseAuthorizationServerMetadataMiddleware(
        TranslateDownstreamUnauthorizedMiddleware(inner_app),
        as_metadata_url="https://mcp.example.com/.well-known/oauth-authorization-server",
    )
    status, headers = await _drive(stacked)
    assert status == 401
    header_map = {name.decode(): value.decode() for name, value in headers}
    assert "www-authenticate" in header_map
    assert "as_metadata=" in header_map["www-authenticate"]
