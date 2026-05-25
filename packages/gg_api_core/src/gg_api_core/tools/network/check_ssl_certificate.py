"""Fetch a host's TLS certificate and extract ownership signals."""

import asyncio
import logging
import socket
import ssl
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

SSL_TIMEOUT = 5.0


class CheckSslCertificateParams(BaseModel):
    """Parameters for ``check_ssl_certificate``."""

    hostname: str = Field(description="Hostname to connect to.")
    port: int = Field(default=443, ge=1, le=65535, description="TLS port.")


class CheckSslCertificateResult(BaseModel):
    """Result of a TLS certificate probe."""

    hostname: str
    port: int
    subject_cn: str | None = None
    subject_organization: str | None = None
    issuer_cn: str | None = None
    issuer_organization: str | None = None
    sans: list[str] = Field(default_factory=list)
    valid_from: str | None = None
    valid_to: str | None = None
    self_signed: bool = False
    error: str | None = None


def _parse_certificate(der_bytes: bytes, hostname: str) -> dict[str, Any]:
    """Parse a DER-encoded certificate using ``cryptography``."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.x509.oid import ExtensionOID, NameOID

    cert = x509.load_der_x509_certificate(der_bytes)

    def _get_attr(name, oid):
        attrs = name.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else None

    subject_cn = _get_attr(cert.subject, NameOID.COMMON_NAME)
    subject_org = _get_attr(cert.subject, NameOID.ORGANIZATION_NAME)
    issuer_cn = _get_attr(cert.issuer, NameOID.COMMON_NAME)
    issuer_org = _get_attr(cert.issuer, NameOID.ORGANIZATION_NAME)

    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = [str(name.value) for name in san_ext.value]
    except x509.ExtensionNotFound:
        sans = []

    self_signed = cert.issuer == cert.subject

    # Use timezone-aware UTC attributes when available (cryptography >=42).
    not_before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after

    _ = serialization  # silence unused warning if linter is picky
    _ = hostname
    return {
        "subject_cn": subject_cn,
        "subject_organization": subject_org,
        "issuer_cn": issuer_cn,
        "issuer_organization": issuer_org,
        "sans": sans,
        "valid_from": not_before.isoformat() if not_before else None,
        "valid_to": not_after.isoformat() if not_after else None,
        "self_signed": self_signed,
    }


def _fetch_certificate(hostname: str, port: int) -> tuple[bytes | None, str | None]:
    """Synchronously fetch the peer certificate DER bytes. Runs in a thread.

    We disable verification deliberately so we can inspect self-signed or
    expired certificates instead of failing the lookup.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=SSL_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
                return der, None
    except socket.timeout:
        return None, "timeout"
    except (socket.gaierror, OSError) as exc:
        return None, f"connect_error:{exc.__class__.__name__}"
    except ssl.SSLError as exc:
        return None, f"ssl_error:{exc.__class__.__name__}"
    except Exception as exc:  # pragma: no cover - defensive
        return None, f"error:{exc.__class__.__name__}"


async def check_ssl_certificate(params: CheckSslCertificateParams) -> CheckSslCertificateResult:
    """Fetch the TLS certificate for a hostname and extract ownership fields.

    The cert's Subject Organization is a strong ownership signal: if a leaked
    secret hits ``api.acme.com`` and the cert says ``O=Acme Corp``, that's
    near-conclusive evidence the host belongs to Acme.

    Args:
        params: ``CheckSslCertificateParams``.

    Returns:
        ``CheckSslCertificateResult`` with parsed cert fields or ``error``.
    """
    logger.debug(f"check_ssl_certificate hostname={params.hostname} port={params.port}")

    try:
        der_bytes, error = await asyncio.wait_for(
            asyncio.to_thread(_fetch_certificate, params.hostname, params.port),
            timeout=SSL_TIMEOUT + 1,
        )
    except asyncio.TimeoutError:
        return CheckSslCertificateResult(hostname=params.hostname, port=params.port, error="timeout")

    if error or der_bytes is None:
        return CheckSslCertificateResult(hostname=params.hostname, port=params.port, error=error or "no_certificate")

    try:
        parsed = _parse_certificate(der_bytes, params.hostname)
    except Exception as exc:
        logger.exception("Failed to parse certificate")
        return CheckSslCertificateResult(
            hostname=params.hostname,
            port=params.port,
            error=f"parse_error:{exc.__class__.__name__}",
        )

    return CheckSslCertificateResult(hostname=params.hostname, port=params.port, **parsed)
