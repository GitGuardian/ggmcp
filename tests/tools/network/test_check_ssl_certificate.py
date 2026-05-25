"""Tests for ``check_ssl_certificate``."""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from gg_api_core.tools.network.check_ssl_certificate import (
    CheckSslCertificateParams,
    check_ssl_certificate,
)


def _make_self_signed_cert(cn: str = "api.acme.com", org: str = "Acme Corp") -> bytes:
    """Build a self-signed cert in-memory and return its DER bytes."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2024, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2034, 1, 1, tzinfo=timezone.utc))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn), x509.DNSName(f"www.{cn}")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.mark.asyncio
async def test_check_ssl_certificate_happy_path():
    der = _make_self_signed_cert(cn="api.acme.com", org="Acme Corp")

    with patch(
        "gg_api_core.tools.network.check_ssl_certificate._fetch_certificate",
        return_value=(der, None),
    ):
        result = await check_ssl_certificate(CheckSslCertificateParams(hostname="api.acme.com"))

    assert result.error is None
    assert result.subject_cn == "api.acme.com"
    assert result.subject_organization == "Acme Corp"
    assert result.self_signed is True
    assert "api.acme.com" in result.sans


@pytest.mark.asyncio
async def test_check_ssl_certificate_timeout():
    with patch(
        "gg_api_core.tools.network.check_ssl_certificate._fetch_certificate",
        return_value=(None, "timeout"),
    ):
        result = await check_ssl_certificate(CheckSslCertificateParams(hostname="slow.acme.com"))

    assert result.error == "timeout"
    assert result.subject_cn is None
