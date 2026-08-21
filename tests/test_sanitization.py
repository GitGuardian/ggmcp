import pytest
from gg_api_core.sanitization import (
    SENSITIVE_DATA_PLACEHOLDER,
    scrub_by_name,
    scrub_by_value,
    scrub_git_credentials,
    scrub_pydantic_input_value,
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
            ("token_id", "d0ca9877-641f-4c37-8857-c08e0ae148c4", "d0ca9877-641f-4c37-8857-c08e0ae148c4"),
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
            (
                "clone https://u:p@host/r and ?token=abc",
                f"clone https://{PLACEHOLDER}:{PLACEHOLDER}@host/r and ?token={PLACEHOLDER}",
            ),
            ("no secrets here", "no secrets here"),
            (42, 42),
        ],
    )
    def test_scrub_by_value(self, value, expected):
        assert scrub_by_value(value) == expected


class TestScrubPydanticInputValue:
    """Pydantic embeds the rejected input in every ValidationError message.

    FastMCP validates a tool call against a TypeAdapter built from the tool
    signature, not against the ``*Params`` model, so ``hide_input_in_errors``
    on the model never reaches this text. Scrubbing it here is what keeps
    submitted arguments out of the Sentry exception value.
    """

    @pytest.mark.parametrize(
        ("message", "expected"),
        [
            (
                "Input should be a valid list [type=list_type, input_value='doc', input_type=str]",
                f"Input should be a valid list [type=list_type, input_value={PLACEHOLDER}, input_type=str]",
            ),
            # The value runs to the LAST marker on the line, so a payload that
            # embeds ", input_type=" is still redacted in full.
            (
                "[type=list_type, input_value='a, input_type=x b', input_type=str]",
                f"[type=list_type, input_value={PLACEHOLDER}, input_type=str]",
            ),
            ("GET /v1/incidents?page=2 returned 200", "GET /v1/incidents?page=2 returned 200"),
        ],
    )
    def test_redacts_input_value(self, message, expected):
        assert scrub_pydantic_input_value(message) == expected

    def test_redacts_even_without_the_input_type_marker(self):
        """
        GIVEN a message carrying input_value with no trailing input_type marker
        WHEN it is scrubbed
        THEN the payload is still gone

        Pydantic always renders input_type after input_value, so this shape is
        defensive: redaction must not depend on the marker being present.
        """
        scrubbed = scrub_pydantic_input_value("[type=list_type, input_value='doc']")

        assert "doc" not in scrubbed
        assert PLACEHOLDER in scrubbed

    def test_redacts_every_error_in_a_multi_error_message(self):
        message = (
            "2 validation errors for call[scan_secrets]\n"
            "documents\n  msg [type=list_type, input_value='SECRET_ONE', input_type=str]\n"
            "filename\n  msg [type=int_type, input_value='SECRET_TWO', input_type=str]"
        )

        scrubbed = scrub_pydantic_input_value(message)

        assert "SECRET_ONE" not in scrubbed
        assert "SECRET_TWO" not in scrubbed
        assert scrubbed.count(f"input_value={PLACEHOLDER}") == 2

    def test_keeps_the_fields_that_explain_the_failure(self):
        message = "documents\n  Input should be a valid list [type=list_type, input_value='doc', input_type=str]"

        scrubbed = scrub_pydantic_input_value(message)

        assert "documents" in scrubbed
        assert "Input should be a valid list" in scrubbed
        assert "type=list_type" in scrubbed
        assert "input_type=str" in scrubbed

    def test_reached_through_scrub_by_value(self):
        assert scrub_by_value("[input_value='doc', input_type=str]") == (f"[input_value={PLACEHOLDER}, input_type=str]")
