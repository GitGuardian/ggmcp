"""Tests for the dns_lookup tool. Network is mocked via ``unittest.mock``."""

from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import pytest
from gg_api_core.tools.network.dns_lookup import DnsLookupParams, dns_lookup


class _FakeRdata:
    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


def _make_resolver(answers_by_type: dict[str, object]):
    """Return a mock resolver whose ``resolve(host, type)`` looks up in the dict."""
    resolver = MagicMock()

    def resolve(host: str, record_type: str):
        outcome = answers_by_type.get(record_type)
        if isinstance(outcome, Exception):
            raise outcome
        return list(outcome or [])

    resolver.resolve.side_effect = resolve
    return resolver


@pytest.mark.asyncio
async def test_dns_lookup_happy_path():
    """A + CNAME both resolve."""
    resolver = _make_resolver(
        {
            "A": [_FakeRdata("93.184.216.34")],
            "CNAME": [_FakeRdata("example.com.")],
        }
    )

    with patch("dns.resolver.Resolver", return_value=resolver):
        result = await dns_lookup(DnsLookupParams(hostname="example.com"))

    assert result.error is None
    assert result.records["A"] == ["93.184.216.34"]
    assert result.records["CNAME"] == ["example.com."]


@pytest.mark.asyncio
async def test_dns_lookup_nxdomain():
    """Every record type raises NXDOMAIN — surfaced at top level."""
    resolver = _make_resolver(
        {
            "A": dns.resolver.NXDOMAIN(),
            "CNAME": dns.resolver.NXDOMAIN(),
        }
    )

    with patch("dns.resolver.Resolver", return_value=resolver):
        result = await dns_lookup(DnsLookupParams(hostname="nonexistent.invalid"))

    assert result.error == "NXDOMAIN"
    assert result.records == {}


@pytest.mark.asyncio
async def test_dns_lookup_timeout():
    """All queries timeout — error surfaced."""
    resolver = _make_resolver(
        {
            "A": dns.exception.Timeout(),
        }
    )

    with patch("dns.resolver.Resolver", return_value=resolver):
        result = await dns_lookup(DnsLookupParams(hostname="slow.example.com", record_types=["A"]))

    assert result.error == "timeout"


@pytest.mark.asyncio
async def test_dns_lookup_no_answer():
    """``NoAnswer`` returns an empty list for that record but no error overall."""
    resolver = _make_resolver(
        {
            "A": [_FakeRdata("93.184.216.34")],
            "CNAME": dns.resolver.NoAnswer(),
        }
    )

    with patch("dns.resolver.Resolver", return_value=resolver):
        result = await dns_lookup(DnsLookupParams(hostname="example.com"))

    assert result.error is None
    assert result.records == {"A": ["93.184.216.34"], "CNAME": []}
