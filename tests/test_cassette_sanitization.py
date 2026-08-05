"""Guards for the VCR fixture anonymization in conftest.

Cassettes are recorded against a real workspace, so the anonymization hooks are
what keep workspace-identifying data out of the repository. These tests fail if
a re-recording reintroduces it, or if a transform stops being idempotent.
"""

import re
from pathlib import Path

import pytest

from tests.conftest import (
    CASSETTES_DIR,
    PUBLIC_HOSTNAMES,
    _anonymize_text,
    _anonymize_uri,
    _redact_sensitive_fields,
)

CASSETTES = sorted(Path(CASSETTES_DIR).rglob("*.yaml"))

# Fake domains the anonymizers emit, plus opaque non-routable identifiers that
# carry no workspace information (Teams conversation ids, git-over-ssh remotes).
ALLOWED_EMAIL_DOMAINS = ("example.com", "thread.tacv", "users.noreply.github.com")

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_COMPANY_HOST = re.compile(r"[A-Za-z0-9.-]*gitguardian[A-Za-z0-9.-]*\.[A-Za-z]{2,}")


def test_cassettes_exist():
    assert CASSETTES, "no cassettes found; the hygiene scan below would vacuously pass"


@pytest.mark.parametrize("cassette", CASSETTES, ids=lambda p: p.name)
def test_cassette_has_no_real_email_addresses(cassette):
    """Only anonymized addresses may appear in a recorded fixture."""
    leaked = {
        email for email in _EMAIL.findall(cassette.read_text()) if not email.lower().endswith(ALLOWED_EMAIL_DOMAINS)
    }
    assert not leaked, f"{cassette.name} carries non-anonymized addresses: {sorted(leaked)}"


@pytest.mark.parametrize("cassette", CASSETTES, ids=lambda p: p.name)
def test_cassette_has_no_non_public_company_hostnames(cassette):
    """Product hostnames are fine; anything else on the company domain is not."""
    leaked = {host for host in _COMPANY_HOST.findall(cassette.read_text()) if host.lower() not in PUBLIC_HOSTNAMES}
    assert not leaked, f"{cassette.name} carries non-public hostnames: {sorted(leaked)}"


@pytest.mark.parametrize(
    "value",
    [
        "someone@corp.example.org",
        "user-f548df99@example.com",
        "internal-host.example.org",
        "/Users/someone/project/file.py",
        "/Users/user-eb6cfa60/project/file.py",
        "https://github.com/some-owner/some-repo",
        "https://github.com/ns-f0afee16/some-repo",
    ],
)
def test_text_anonymization_is_idempotent(value):
    """VCR filters outgoing requests at replay time as well as at record time,
    so an already-anonymized value must survive a second pass unchanged."""
    once = _anonymize_text(value)
    assert _anonymize_text(once) == once


@pytest.mark.parametrize(
    "uri",
    [
        "https://api.gitguardian.com/v1/sources?search=owner%2Frepo&per_page=50",
        "https://api.gitguardian.com/v1/sources?search=ns-1cb0f5a9%2Frepo&per_page=50",
    ],
)
def test_uri_anonymization_is_idempotent(uri):
    once = _anonymize_uri(uri)
    assert _anonymize_uri(once) == once


def test_structural_redaction_is_idempotent():
    """The name/endpoint/repository rules key off sibling fields, so they must
    also recognize their own output."""
    payload = {
        "members": [{"name": "Some Person", "email": "some.person@corp.example.org"}],
        "sources": [
            {"type": "endpoints", "name": "LAPTOP01 - some.person", "path": "LAPTOP01 - some.person"},
            {"type": "gh_repository", "name": "some-owner/some-repo", "path": "some-owner/some-repo"},
        ],
    }
    once = _redact_sensitive_fields(payload)
    assert _redact_sensitive_fields(once) == once
