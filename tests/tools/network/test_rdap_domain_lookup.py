"""Tests for ``rdap_domain_lookup``. HTTPS mocked via ``respx``."""

import httpx
import pytest
import respx
from gg_api_core.tools.network.rdap_domain_lookup import (
    RDAP_BASE,
    RdapDomainLookupParams,
    rdap_domain_lookup,
)

_SAMPLE_RDAP_DOMAIN = {
    "objectClassName": "domain",
    "handle": "EXAMPLE.COM",
    "ldhName": "example.com",
    "status": ["active"],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2024-08-13T04:00:00Z"},
    ],
    "entities": [
        {
            "objectClassName": "entity",
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Acme Corp"],
                    ["org", {}, "text", ["Acme Corp"]],
                    ["adr", {"cc": "US"}, "text", ["", "", "1 Acme Way", "Springfield", "CA", "94000", "US"]],
                ],
            ],
        },
        {
            "objectClassName": "entity",
            "roles": ["registrar"],
            "vcardArray": [
                "vcard",
                [["version", {}, "text", "4.0"], ["fn", {}, "text", "RegistrarCo"]],
            ],
        },
    ],
    "nameservers": [
        {"objectClassName": "nameserver", "ldhName": "ns1.example.com"},
        {"objectClassName": "nameserver", "ldhName": "ns2.example.com"},
    ],
}


@pytest.mark.asyncio
async def test_rdap_domain_lookup_happy_path():
    with respx.mock(base_url=RDAP_BASE) as router:
        router.get("/domain/example.com").mock(return_value=httpx.Response(200, json=_SAMPLE_RDAP_DOMAIN))
        result = await rdap_domain_lookup(RdapDomainLookupParams(domain="example.com"))

    assert result.error is None
    assert result.registrant_organization == "Acme Corp"
    assert result.registrant_country == "US"
    assert result.registrar == "RegistrarCo"
    assert result.registration_date == "1995-08-14T04:00:00Z"
    assert result.name_servers == ["ns1.example.com", "ns2.example.com"]


@pytest.mark.asyncio
async def test_rdap_domain_lookup_not_found():
    with respx.mock(base_url=RDAP_BASE) as router:
        router.get("/domain/nope.invalid").mock(return_value=httpx.Response(404))
        result = await rdap_domain_lookup(RdapDomainLookupParams(domain="nope.invalid"))

    assert result.error == "not_found"
    assert result.registrant_organization is None


@pytest.mark.asyncio
async def test_rdap_domain_lookup_timeout():
    with respx.mock(base_url=RDAP_BASE) as router:
        router.get("/domain/slow.example.com").mock(side_effect=httpx.TimeoutException("timeout"))
        result = await rdap_domain_lookup(RdapDomainLookupParams(domain="slow.example.com"))

    assert result.error == "timeout"
