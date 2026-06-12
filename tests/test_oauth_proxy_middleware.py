"""Tests for the OAuth-proxy ASGI middleware that converts downstream 401s."""

import json

import pytest
from gg_api_core.oauth_proxy_auth import (
    AdvertiseAuthorizationServerMetadataMiddleware,
    TranslateDownstreamUnauthorizedMiddleware,
    create_oauth_proxy,
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


@pytest.mark.asyncio
async def test_authorization_server_metadata_is_accurate():
    """AS metadata advertises only the auth methods the GG backend accepts and
    a spec-compliant issuer (no trailing slash)."""
    proxy = create_oauth_proxy(base_url="https://mcp.example.com")
    proxy.get_routes("/mcp")  # sets the resource URL via set_mcp_path

    resp = await proxy._handle_authorization_server_metadata(request=None)
    meta = json.loads(resp.body)

    # RFC 8414 §3.3: issuer == base used to build the well-known URL, no slash.
    assert meta["issuer"] == "https://mcp.example.com"
    # Mirrors ClientRegistrationRequestSerializer — no client_secret_basic.
    assert meta["token_endpoint_auth_methods_supported"] == [
        "none",
        "client_secret_post",
    ]
    assert meta["authorization_endpoint"] == "https://mcp.example.com/authorize"
    assert meta["code_challenge_methods_supported"] == ["S256"]


@pytest.mark.asyncio
async def test_resource_metadata_authorization_servers_match_issuer():
    """RFC 9728 authorization_servers must match the AS metadata issuer exactly."""
    proxy = create_oauth_proxy(base_url="https://mcp.example.com")
    proxy.get_routes("/mcp")

    as_meta = json.loads((await proxy._handle_authorization_server_metadata(request=None)).body)
    rm_meta = json.loads((await proxy._handle_resource_metadata(request=None)).body)

    assert rm_meta["authorization_servers"] == [as_meta["issuer"]]
    assert rm_meta["authorization_servers"] == ["https://mcp.example.com"]


def _route_paths(proxy) -> set[str]:
    return {route.path for route in proxy.get_routes("/mcp")}


def test_discovery_routes_dedicated_subdomain():
    """Path-less base (mcp.<domain>): metadata served at the bare well-known
    paths, exactly as before single-domain support."""
    proxy = create_oauth_proxy(base_url="https://mcp.example.com")
    paths = _route_paths(proxy)

    assert "/.well-known/oauth-protected-resource/mcp" in paths
    assert "/.well-known/oauth-authorization-server" in paths
    # No spurious path-inserted duplicate when the issuer has no path component.
    assert not any(p.startswith("/.well-known/oauth-authorization-server/") for p in paths)


def test_discovery_routes_single_domain_base_path():
    """Single-domain base (https://gg.example.com/mcp-server): metadata served
    at the RFC 9728 / RFC 8414 §3.1 host-root path-insertion locations, i.e.
    where a spec-compliant client actually looks — NOT under the /mcp-server
    prefix."""
    proxy = create_oauth_proxy(base_url="https://gg.example.com/mcp-server")
    paths = _route_paths(proxy)

    # RFC 9728: resource https://gg.example.com/mcp-server/mcp -> metadata at
    # host root with the full resource path inserted.
    assert "/.well-known/oauth-protected-resource/mcp-server/mcp" in paths
    # RFC 8414 §3.1: issuer https://gg.example.com/mcp-server -> insertion form.
    assert "/.well-known/oauth-authorization-server/mcp-server" in paths
    # Bare path kept too: reached after the reverse proxy strips /mcp-server,
    # and where Claude.ai's as_metadata shortcut points.
    assert "/.well-known/oauth-authorization-server" in paths


@pytest.mark.asyncio
async def test_resource_metadata_resource_matches_route_under_base_path():
    """The PRM route path must equal the path of the advertised `resource`
    metadata so the reverse proxy can pass through without rewriting."""
    proxy = create_oauth_proxy(base_url="https://gg.example.com/mcp-server")
    paths = _route_paths(proxy)

    rm_meta = json.loads((await proxy._handle_resource_metadata(request=None)).body)
    assert rm_meta["resource"] == "https://gg.example.com/mcp-server/mcp"
    assert rm_meta["authorization_servers"] == ["https://gg.example.com/mcp-server"]
    # Route is registered at exactly the RFC 9728 URL we advertise.
    assert "/.well-known/oauth-protected-resource/mcp-server/mcp" in paths
