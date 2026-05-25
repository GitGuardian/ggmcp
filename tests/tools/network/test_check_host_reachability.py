"""Tests for ``check_host_reachability``."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx
from gg_api_core.tools.network.check_host_reachability import (
    CheckHostReachabilityParams,
    check_host_reachability,
)


@pytest.mark.asyncio
async def test_reachability_happy_path():
    """DNS resolves, TCP connects, HTTP returns 200 with a Cloudflare hint."""
    fake_writer = MagicMock()
    fake_writer.close = MagicMock()
    fake_writer.wait_closed = AsyncMock()

    async def fake_open_connection(host, port):
        return MagicMock(), fake_writer

    with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("1.2.3.4", 0))]):
        with patch("asyncio.open_connection", side_effect=fake_open_connection):
            with respx.mock() as router:
                router.get("https://api.acme.com:443/").mock(
                    return_value=httpx.Response(200, headers={"cf-ray": "abc-123", "server": "cloudflare"})
                )
                result = await check_host_reachability(CheckHostReachabilityParams(host="api.acme.com", port=443))

    assert result.dns_ok is True
    assert result.tcp_ok is True
    assert result.http_status == 200
    assert result.waf_detected is True
    assert result.waf_vendor == "cloudflare"


@pytest.mark.asyncio
async def test_reachability_dns_fails():
    """``getaddrinfo`` raises — short-circuit at the DNS stage."""
    import socket as _socket

    with patch("socket.getaddrinfo", side_effect=_socket.gaierror(1, "no host")):
        result = await check_host_reachability(CheckHostReachabilityParams(host="nope.invalid"))

    assert result.dns_ok is False
    assert result.error == "dns_failed"


@pytest.mark.asyncio
async def test_reachability_tcp_fails():
    """DNS OK, TCP times out."""

    async def fake_open_connection(host, port):
        raise asyncio.TimeoutError

    with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("1.2.3.4", 0))]):
        with patch("asyncio.open_connection", side_effect=fake_open_connection):
            result = await check_host_reachability(
                CheckHostReachabilityParams(host="closed.acme.com", port=443, try_http=False)
            )

    assert result.dns_ok is True
    assert result.tcp_ok is False
    assert result.error == "tcp_failed"
