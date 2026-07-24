import pytest
from gg_api_core.sanitization import (
    SENSITIVE_DATA_PLACEHOLDER,
    scrub_by_name,
    scrub_by_value,
    scrub_git_credentials,
    scrub_url_params,
)

PLACEHOLDER = SENSITIVE_DATA_PLACEHOLDER


class TestScrubByName:
    @pytest.mark.parametrize(
        ("name", "value", "expected"),
        [
            # sensitive key -> whole value redacted (case-insensitive)
            ("token", "raw secret material", PLACEHOLDER),
            ("client_secret", "raw secret material", PLACEHOLDER),
            ("Authorization", "raw secret material", PLACEHOLDER),
            ("document", "raw secret material", PLACEHOLDER),
            # benign key -> value kept
            ("account_id", 475789, 475789),
            ("endpoint", "/v1/incidents", "/v1/incidents"),
            # benign key whose value carries a secret shape -> value-scrubbed
            ("url", "https://gg.com/cb?token=abc&safe=1", f"https://gg.com/cb?token={PLACEHOLDER}&safe=1"),
            # dict under a benign key -> recurse, redact sensitive child keys
            ("payload", {"account_id": 1, "token": "x"}, {"account_id": 1, "token": PLACEHOLDER}),
            # list under a sensitive key -> whole value redacted
            ("documents", [{"document": "c"}], PLACEHOLDER),
            # list under a benign key -> recurse into items
            ("results", [{"token": "x"}], [{"token": PLACEHOLDER}]),
        ],
    )
    def test_scrub_by_name(self, name, value, expected):
        assert scrub_by_name(name, value) == expected


class TestScrubUrlParams:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://e.com/p?token=123&safe=456", f"https://e.com/p?token={PLACEHOLDER}&safe=456"),
            ("/p?token=123&token=234", f"/p?token={PLACEHOLDER}&token={PLACEHOLDER}"),
            ("/p?token=&key=123", f"/p?token=&key={PLACEHOLDER}"),
            ("/p?safe=123", "/p?safe=123"),
        ],
    )
    def test_redacts_sensitive_params(self, url, expected):
        assert scrub_url_params(url) == expected


class TestScrubGitCredentials:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("git clone https://u:p@host/r.git", f"git clone https://{PLACEHOLDER}:{PLACEHOLDER}@host/r.git"),
            ("https://a:b@gitlab.com/x", f"https://{PLACEHOLDER}:{PLACEHOLDER}@gitlab.com/x"),
            ("https://host/no-creds.git", "https://host/no-creds.git"),
        ],
    )
    def test_redacts_credentials(self, url, expected):
        assert scrub_git_credentials(url) == expected


class TestScrubByValue:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("clone https://u:p@host/r and ?token=abc", f"clone https://{PLACEHOLDER}:{PLACEHOLDER}@host/r and ?token={PLACEHOLDER}"),
            ("no secrets here", "no secrets here"),
            (42, 42),
        ],
    )
    def test_scrub_by_value(self, value, expected):
        assert scrub_by_value(value) == expected
