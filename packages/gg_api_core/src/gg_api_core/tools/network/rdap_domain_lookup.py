"""RDAP domain lookup — modern WHOIS for a domain."""

import logging
from typing import Any

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

RDAP_TIMEOUT = 10.0
RDAP_BASE = "https://rdap.org"


class RdapDomainLookupParams(BaseModel):
    """Parameters for ``rdap_domain_lookup``."""

    domain: str = Field(description="Domain name to look up (e.g. 'acme.com').")


class RdapDomainLookupResult(BaseModel):
    """Result of an RDAP domain lookup."""

    domain: str
    registrant_organization: str | None = None
    registrant_country: str | None = None
    registrar: str | None = None
    registration_date: str | None = None
    name_servers: list[str] = Field(default_factory=list)
    raw_excerpt: dict[str, Any] = Field(
        default_factory=dict,
        description="Subset of the raw RDAP response (handle, status, events) for traceability.",
    )
    error: str | None = None


def _parse_vcard(vcard_array: Any) -> dict[str, str]:
    """Extract a flat ``{fn, org, country, email}`` map from a vCard jCard array.

    A jCard looks like ``["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "..."], ...]]``.
    """
    out: dict[str, str] = {}
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return out
    entries = vcard_array[1]
    if not isinstance(entries, list):
        return out
    for entry in entries:
        if not isinstance(entry, list) or len(entry) < 4:
            continue
        name = entry[0]
        params = entry[1] if isinstance(entry[1], dict) else {}
        value = entry[3]
        if name == "fn" and isinstance(value, str):
            out["fn"] = value
        elif name == "org":
            if isinstance(value, list) and value:
                out["org"] = value[0]
            elif isinstance(value, str):
                out["org"] = value
        elif name == "adr":
            # ADR is a list: [pobox, ext, street, locality, region, code, country]
            if isinstance(value, list) and len(value) >= 7 and value[6]:
                out["country"] = value[6]
            elif isinstance(params, dict) and "cc" in params:
                out["country"] = str(params["cc"])
        elif name == "email" and isinstance(value, str):
            out["email"] = value
    return out


def _extract_registrant(entities: Any) -> dict[str, str]:
    """Find the first entity with role 'registrant' and return its parsed vCard."""
    if not isinstance(entities, list):
        return {}
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        roles = ent.get("roles") or []
        if "registrant" in roles:
            return _parse_vcard(ent.get("vcardArray"))
    # Fallback: first entity with a vCard.
    for ent in entities:
        if isinstance(ent, dict) and ent.get("vcardArray"):
            return _parse_vcard(ent.get("vcardArray"))
    return {}


def _extract_registrar(entities: Any) -> str | None:
    if not isinstance(entities, list):
        return None
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        roles = ent.get("roles") or []
        if "registrar" in roles:
            parsed = _parse_vcard(ent.get("vcardArray"))
            return parsed.get("fn") or parsed.get("org")
    return None


def _extract_registration_date(events: Any) -> str | None:
    if not isinstance(events, list):
        return None
    for ev in events:
        if isinstance(ev, dict) and ev.get("eventAction") == "registration":
            return ev.get("eventDate")
    return None


def _extract_nameservers(nameservers: Any) -> list[str]:
    if not isinstance(nameservers, list):
        return []
    out: list[str] = []
    for ns in nameservers:
        if isinstance(ns, dict):
            name = ns.get("ldhName") or ns.get("unicodeName")
            if name:
                out.append(str(name))
    return out


async def rdap_domain_lookup(params: RdapDomainLookupParams) -> RdapDomainLookupResult:
    """Look up the registrant organization of a domain via RDAP (modern WHOIS).

    Primary signal for tying a leaked URL/host back to a company. The
    ``registrant_organization`` and ``registrant_country`` fields are the
    high-value ones; ``raw_excerpt`` retains a small slice of the response
    for traceability.

    Args:
        params: ``RdapDomainLookupParams`` with the target domain.

    Returns:
        ``RdapDomainLookupResult``. On failure, fields are None and
        ``error`` is set.
    """
    url = f"{RDAP_BASE}/domain/{params.domain}"
    logger.debug(f"rdap_domain_lookup url={url}")

    try:
        async with httpx.AsyncClient(timeout=RDAP_TIMEOUT, follow_redirects=True) as client:
            response = await client.get(url, headers={"Accept": "application/rdap+json"})
    except httpx.TimeoutException:
        return RdapDomainLookupResult(domain=params.domain, error="timeout")
    except httpx.HTTPError as exc:
        return RdapDomainLookupResult(domain=params.domain, error=f"http_error:{exc.__class__.__name__}")

    if response.status_code == 404:
        return RdapDomainLookupResult(domain=params.domain, error="not_found")
    if response.status_code >= 400:
        return RdapDomainLookupResult(domain=params.domain, error=f"http_{response.status_code}")

    try:
        data = response.json()
    except ValueError:
        return RdapDomainLookupResult(domain=params.domain, error="invalid_json")

    entities = data.get("entities", [])
    registrant = _extract_registrant(entities)
    registrar = _extract_registrar(entities)
    registration_date = _extract_registration_date(data.get("events"))
    name_servers = _extract_nameservers(data.get("nameservers"))

    raw_excerpt = {
        "handle": data.get("handle"),
        "ldhName": data.get("ldhName"),
        "status": data.get("status"),
    }

    return RdapDomainLookupResult(
        domain=params.domain,
        registrant_organization=registrant.get("org") or registrant.get("fn"),
        registrant_country=registrant.get("country"),
        registrar=registrar,
        registration_date=registration_date,
        name_servers=name_servers,
        raw_excerpt=raw_excerpt,
    )
