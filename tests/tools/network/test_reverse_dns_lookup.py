"""Tests for ``reverse_dns_lookup``."""

import socket
from unittest.mock import patch

import pytest
from gg_api_core.tools.network.reverse_dns_lookup import (
    ReverseDnsLookupParams,
    reverse_dns_lookup,
)


@pytest.mark.asyncio
async def test_reverse_dns_lookup_happy_path():
    with patch(
        "socket.gethostbyaddr",
        return_value=("ec2-1-2-3-4.compute-1.amazonaws.com", ["1.compute-1.amazonaws.com"], ["1.2.3.4"]),
    ):
        result = await reverse_dns_lookup(ReverseDnsLookupParams(ip_address="1.2.3.4"))

    assert result.hostname == "ec2-1-2-3-4.compute-1.amazonaws.com"
    assert result.aliases == ["1.compute-1.amazonaws.com"]
    assert result.error is None


@pytest.mark.asyncio
async def test_reverse_dns_lookup_herror():
    with patch("socket.gethostbyaddr", side_effect=socket.herror(1, "host not found")):
        result = await reverse_dns_lookup(ReverseDnsLookupParams(ip_address="1.2.3.4"))

    assert result.hostname is None
    assert result.error is not None
    assert "herror" in result.error
