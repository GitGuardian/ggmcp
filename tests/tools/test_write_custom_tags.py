from gg_api_core.tools.write_custom_tags import (
    UpdateOrCreateIncidentCustomTagsParams,
    WriteCustomTagsParams,
)


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


class TestUpdateOrCreateIncidentCustomTagsParams:
    """
    Test UpdateOrCreateIncidentCustomTagsParams validation.
    """

    def test_incident_with_single_tag_key_only(self):
        """
        GIVEN an incident_id and tag with key only
        WHEN creating UpdateOrCreateIncidentCustomTagsParams
        THEN the params should be properly formatted
        """
        params = UpdateOrCreateIncidentCustomTagsParams(incident_id="123", custom_tags=["env"])
        assert params.incident_id == "123"
        assert params.custom_tags == ["env"]

    def test_incident_with_single_tag_key_value(self):
        """
        GIVEN an incident_id and tag with key:value format
        WHEN creating UpdateOrCreateIncidentCustomTagsParams
        THEN the params should be properly formatted
        """
        params = UpdateOrCreateIncidentCustomTagsParams(incident_id="123", custom_tags=["env:prod"])
        assert params.incident_id == "123"
        assert params.custom_tags == ["env:prod"]

    def test_incident_with_multiple_tags(self):
        """
        GIVEN an incident_id and multiple tags
        WHEN creating UpdateOrCreateIncidentCustomTagsParams
        THEN the params should be properly formatted
        """
        params = UpdateOrCreateIncidentCustomTagsParams(
            incident_id="123", custom_tags=["env", "env:prod", "region:us-west-2"]
        )
        assert params.incident_id == "123"
        assert len(params.custom_tags) == 3
        assert "env" in params.custom_tags
        assert "env:prod" in params.custom_tags
        assert "region:us-west-2" in params.custom_tags

    def test_incident_id_as_int(self):
        """
        GIVEN an incident_id as integer
        WHEN creating UpdateOrCreateIncidentCustomTagsParams
        THEN it should be accepted
        """
        params = UpdateOrCreateIncidentCustomTagsParams(incident_id=123, custom_tags=["env:prod"])
        assert params.incident_id == 123

    def test_incident_id_as_string(self):
        """
        GIVEN an incident_id as string
        WHEN creating UpdateOrCreateIncidentCustomTagsParams
        THEN it should be accepted
        """
        params = UpdateOrCreateIncidentCustomTagsParams(incident_id="123", custom_tags=["env:prod"])
        assert params.incident_id == "123"
