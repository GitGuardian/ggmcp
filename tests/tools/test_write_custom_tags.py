from gg_api_core.tools.write_custom_tags import WriteCustomTagsParams


class TestWriteCustomTagsParams:
    """
    Test WriteCustomTagsParams validation and parsing.
    """

    def test_create_tag_with_key_only(self):
        """
        GIVEN a tag string with only a key
        WHEN creating WriteCustomTagsParams
        THEN the tag should be properly formatted
        """
        params = WriteCustomTagsParams(action="create_tag", tag="env")
        assert params.action == "create_tag"
        assert params.tag == "env"
        assert params.tag_id is None

    def test_create_tag_with_key_and_value(self):
        """
        GIVEN a tag string with key:value format
        WHEN creating WriteCustomTagsParams
        THEN the tag should be properly formatted
        """
        params = WriteCustomTagsParams(action="create_tag", tag="env:prod")
        assert params.action == "create_tag"
        assert params.tag == "env:prod"
        assert params.tag_id is None

    def test_create_tag_with_colon_in_value(self):
        """
        GIVEN a tag string with multiple colons
        WHEN creating WriteCustomTagsParams
        THEN the tag should be properly formatted
        """
        params = WriteCustomTagsParams(action="create_tag", tag="url:http://example.com")
        assert params.action == "create_tag"
        assert params.tag == "url:http://example.com"

    def test_delete_tag_with_id(self):
        """
        GIVEN a tag_id for deletion
        WHEN creating WriteCustomTagsParams
        THEN the params should be properly formatted
        """
        params = WriteCustomTagsParams(action="delete_tag", tag_id="12345")
        assert params.action == "delete_tag"
        assert params.tag_id == "12345"
        assert params.tag is None

    def test_create_tag_requires_tag(self):
        """
        GIVEN create_tag action without tag
        WHEN creating WriteCustomTagsParams
        THEN it should still validate (validation happens in the function)
        """
        params = WriteCustomTagsParams(action="create_tag")
        assert params.tag is None

    def test_delete_tag_requires_tag_id(self):
        """
        GIVEN delete_tag action without tag_id
        WHEN creating WriteCustomTagsParams
        THEN it should still validate (validation happens in the function)
        """
        params = WriteCustomTagsParams(action="delete_tag")
        assert params.tag_id is None
