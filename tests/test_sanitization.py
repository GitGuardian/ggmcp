import pytest
from gg_api_core.sanitization import SENSITIVE_DATA_PLACEHOLDER, scrub_by_name


class TestScrubByName:
    @pytest.mark.parametrize(
        "name",
        [
            # obvious secret-bearing names
            "token",
            "api_token",
            "password",
            "client_secret",
            "authorization",
            # scan-payload fields (raw content / matched secret)
            "document",
            "documents",
            "filename",
            "content",
            "patch",
            # matching is case-insensitive
            "Authorization",
            "API_KEY",
        ],
    )
    def test_sensitive_names_are_redacted(self, name):
        assert scrub_by_name(name, "raw secret material") == SENSITIVE_DATA_PLACEHOLDER

    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("account_id", 475789),
            ("endpoint", "/v1/incidents"),
            ("status_code", 200),
        ],
    )
    def test_non_sensitive_names_pass_through(self, name, value):
        assert scrub_by_name(name, value) == value

    def test_nested_dict_scrubbed_by_own_keys(self):
        out = scrub_by_name("payload", {"account_id": 1, "token": "gg_pat_x", "nested": {"secret": "s"}})
        assert out == {
            "account_id": 1,
            "token": SENSITIVE_DATA_PLACEHOLDER,
            "nested": {"secret": SENSITIVE_DATA_PLACEHOLDER},
        }

    def test_list_under_sensitive_name_is_fully_redacted(self):
        docs = [{"document": "content1", "filename": "a.py"}, {"document": "content2"}]
        assert scrub_by_name("documents", docs) == SENSITIVE_DATA_PLACEHOLDER

    def test_list_under_safe_name_recurses_into_items(self):
        items = [{"account_id": 1, "token": "x"}, {"account_id": 2, "token": "y"}]
        assert scrub_by_name("results", items) == [
            {"account_id": 1, "token": SENSITIVE_DATA_PLACEHOLDER},
            {"account_id": 2, "token": SENSITIVE_DATA_PLACEHOLDER},
        ]
