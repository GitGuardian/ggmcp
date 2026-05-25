"""Tests for ``rdap_ip_lookup``."""

import httpx
import pytest
import respx
from gg_api_core.tools.network.rdap_domain_lookup import RDAP_BASE
from gg_api_core.tools.network.rdap_ip_lookup import RdapIpLookupParams, rdap_ip_lookup

_SAMPLE_RDAP_IP = {
    "objectClassName": "ip network",
    "handle": "NET-1-2-3-0-1",
    "name": "ACME-NET",
    "country": "US",
    "startAddress": "1.2.3.0",
    "endAddress": "1.2.3.255",
    "type": "DIRECT ALLOCATION",
    "entities": [
        {
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [
                    ["fn", {}, "text", "Acme Networks"],
                    ["org", {}, "text", ["Acme Networks"]],
                ],
            ],
        }
    ],
}


@pytest.mark.asyncio
async def test_rdap_ip_lookup_happy_path():
    with respx.mock(base_url=RDAP_BASE) as router:
        router.get("/ip/1.2.3.4").mock(return_value=httpx.Response(200, json=_SAMPLE_RDAP_IP))
        result = await rdap_ip_lookup(RdapIpLookupParams(ip_address="1.2.3.4"))

    assert result.error is None
    assert result.network_name == "ACME-NET"
    assert result.organization == "Acme Networks"
    assert result.country == "US"


@pytest.mark.asyncio
async def test_rdap_ip_lookup_not_found():
    with respx.mock(base_url=RDAP_BASE) as router:
        router.get("/ip/0.0.0.0").mock(return_value=httpx.Response(404))
        result = await rdap_ip_lookup(RdapIpLookupParams(ip_address="0.0.0.0"))

    assert result.error == "not_found"
