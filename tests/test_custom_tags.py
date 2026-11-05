import pytest
from gg_api_core.custom_tags import parse_tag


class TestParseTag:
    """
    Test the shared custom-tag "key" / "key:value" parser.
    """

    def test_key_only(self):
        """
        GIVEN a tag string with only a key
        WHEN parsing it
        THEN the key is returned with a None value
        """
        assert parse_tag("env") == ("env", None)

    def test_key_value(self):
        """
        GIVEN a tag string in key:value format
        WHEN parsing it
        THEN the key and value are returned
        """
        assert parse_tag("env:prod") == ("env", "prod")

    def test_value_containing_colons_keeps_rest(self):
        """
        GIVEN a tag with colons inside the value
        WHEN parsing it
        THEN only the first colon splits, the rest stays in the value
        """
        assert parse_tag("url:http://example.com") == ("url", "http://example.com")

    def test_values_are_whitespace_stripped(self):
        """
        GIVEN a tag with surrounding whitespace and an empty value
        WHEN parsing it
        THEN key and value are stripped, and an empty value becomes None
        """
        assert parse_tag(" env : prod ") == ("env", "prod")
        assert parse_tag("reviewed:") == ("reviewed", None)

    def test_empty_key_raises(self):
        """
        GIVEN a tag with a whitespace-only key
        WHEN parsing it
        THEN a ValueError is raised
        """
        with pytest.raises(ValueError, match="key cannot be empty"):
            parse_tag(" : x")
