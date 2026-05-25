"""RDAP IP lookup — modern WHOIS for an IP address."""

import logging
from typing import Any

import httpx
from pydantic import BaseModel, Field

from .rdap_domain_lookup import RDAP_BASE, RDAP_TIMEOUT, _parse_vcard

logger = logging.getLogger(__name__)


class RdapIpLookupParams(BaseModel):
    """Parameters for ``rdap_ip_lookup``."""

    ip_address: str = Field(description="IPv4 or IPv6 address to look up.")


class RdapIpLookupResult(BaseModel):
    """Result of an RDAP IP lookup."""

    ip_address: str
    network_name: str | None = None
    organization: str | None = None
    country: str | None = None
    asn: int | None = None
    raw_excerpt: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


def _extract_asn(data: dict[str, Any]) -> int | None:
    """RDAP responses for IPs sometimes carry an ASN in ``cidr0_cidrs`` or
    embedded handle. We look for it best-effort.
    """
    # Some registries expose 'arin_originas0_originautnums'.
    for key in ("arin_originas0_originautnums", "originautnums"):
        candidate = data.get(key)
        if isinstance(candidate, list) and candidate:
            value = candidate[0]
            if isinstance(value, int):
                return value
            try:
                return int(value)
            except (TypeError, ValueError):
                continue
    handle = data.get("handle")
    if isinstance(handle, str) and handle.upper().startswith("AS"):
        try:
            return int(handle[2:].split("-")[0])
        except ValueError:
            return None
    return None


def _extract_org_from_entities(entities: Any) -> dict[str, str]:
    if not isinstance(entities, list):
        return {}
    # Prefer 'registrant' / 'administrative' / 'technical' role.
    preferred_roles = ("registrant", "administrative", "technical", "abuse")
    for role in preferred_roles:
        for ent in entities:
            if not isinstance(ent, dict):
                continue
            if role in (ent.get("roles") or []):
                parsed = _parse_vcard(ent.get("vcardArray"))
                if parsed:
                    return parsed
    # Fallback: first entity with vCard.
    for ent in entities:
        if isinstance(ent, dict) and ent.get("vcardArray"):
            return _parse_vcard(ent.get("vcardArray"))
    return {}


async def rdap_ip_lookup(params: RdapIpLookupParams) -> RdapIpLookupResult:
    """Look up the organization owning an IP address via RDAP.

    Use after ``dns_lookup`` resolves a leaked hostname to an IP — the
    network owner is a direct signal for tying the leak back to infra
    (e.g. a self-hosted server) or a hosting provider (AWS / GCP).

    Args:
        params: ``RdapIpLookupParams`` with the IP to query.

    Returns:
        ``RdapIpLookupResult`` with network/org/country/ASN, or ``error``.
    """
    url = f"{RDAP_BASE}/ip/{params.ip_address}"
    logger.debug(f"rdap_ip_lookup url={url}")

    try:
        async with httpx.AsyncClient(timeout=RDAP_TIMEOUT, follow_redirects=True) as client:
            response = await client.get(url, headers={"Accept": "application/rdap+json"})
    except httpx.TimeoutException:
        return RdapIpLookupResult(ip_address=params.ip_address, error="timeout")
    except httpx.HTTPError as exc:
        return RdapIpLookupResult(ip_address=params.ip_address, error=f"http_error:{exc.__class__.__name__}")

    if response.status_code == 404:
        return RdapIpLookupResult(ip_address=params.ip_address, error="not_found")
    if response.status_code >= 400:
        return RdapIpLookupResult(ip_address=params.ip_address, error=f"http_{response.status_code}")

    try:
        data = response.json()
    except ValueError:
        return RdapIpLookupResult(ip_address=params.ip_address, error="invalid_json")

    parsed = _extract_org_from_entities(data.get("entities", []))
    raw_excerpt = {
        "handle": data.get("handle"),
        "name": data.get("name"),
        "startAddress": data.get("startAddress"),
        "endAddress": data.get("endAddress"),
        "type": data.get("type"),
        "country": data.get("country"),
    }

    return RdapIpLookupResult(
        ip_address=params.ip_address,
        network_name=data.get("name"),
        organization=parsed.get("org") or parsed.get("fn"),
        country=data.get("country") or parsed.get("country"),
        asn=_extract_asn(data),
        raw_excerpt=raw_excerpt,
    )
