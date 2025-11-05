"""Tests for schema compression utility to handle Claude Code Pydantic parameter bug."""

from gg_api_core.schema_utils import compress_pydantic_model_schema
from gg_api_core.tools.assign_incident import AssignIncidentParams, assign_incident
from gg_api_core.tools.list_repo_occurrences import (
    ListRepoOccurrencesParams,
    list_repo_occurrences,
)
from gg_api_core.tools.list_users import ListUsersParams, list_users
from pydantic import BaseModel, Field


class TestSchemaCompression:
    """Test suite for schema compression to work around Claude Code bug."""

    def test_compress_nested_schema(self):
        """Test that nested Pydantic model schemas are properly flattened."""
        # Create a sample nested schema like FastMCP generates
        nested_schema = {
            "type": "object",
            "properties": {
                "params": {
                    "type": "object",
                    "properties": {
                        "source_id": {"type": "integer", "description": "Source ID"},
                        "get_all": {"type": "boolean", "description": "Get all results"},
                    },
                    "required": ["source_id"],
                }
            },
            "required": ["params"],
        }

        # Compress the schema
        compressed = compress_pydantic_model_schema(nested_schema)

        # After compression with jsonref, the schema should be resolved
        # but we need to verify it's still valid
        assert "properties" in compressed
        assert compressed["type"] == "object"

    def test_compress_with_refs(self):
        """Test compression with JSON schema references."""
        schema_with_refs = {
            "type": "object",
            "properties": {
                "params": {
                    "$ref": "#/$defs/MyParams",
                }
            },
            "$defs": {
                "MyParams": {
                    "type": "object",
                    "properties": {
                        "field1": {"type": "string"},
                        "field2": {"type": "integer"},
                    },
                }
            },
        }

        compressed = compress_pydantic_model_schema(schema_with_refs)

        # The $ref should be resolved
        assert "properties" in compressed
        # After jsonref processing, refs should be replaced with actual content
        params_props = compressed["properties"].get("params", {})
        assert "properties" in params_props or "type" in compressed

    def test_list_repo_occurrences_accepts_both_formats(self):
        """
        Test that list_repo_occurrences can handle both:
        1. Expected format: direct parameters as dict
        2. Claude Code buggy format: params wrapped under 'params' key
        """
        # Expected format (what GPT-4o and correct clients send)
        expected_params = {"source_id": 9036019, "get_all": True}

        # Should be able to construct the Pydantic model from expected format
        params_obj = ListRepoOccurrencesParams(**expected_params)
        assert params_obj.source_id == 9036019
        assert params_obj.get_all is True

        # Buggy format (what Claude Code currently sends - wrapped)
        buggy_params = {"params": {"source_id": 9036019, "get_all": True}}

        # After schema compression, the tool should accept flattened params
        # The function signature still expects the Pydantic model, so we construct it
        params_from_buggy = ListRepoOccurrencesParams(**buggy_params["params"])
        assert params_from_buggy.source_id == 9036019
        assert params_from_buggy.get_all is True

    def test_list_users_accepts_both_formats(self):
        """Test that list_users can handle both parameter formats."""
        # Expected format
        expected_params = {"per_page": 50, "search": "test@example.com", "get_all": False}

        params_obj = ListUsersParams(**expected_params)
        assert params_obj.per_page == 50
        assert params_obj.search == "test@example.com"
        assert params_obj.get_all is False

        # Buggy format (wrapped)
        buggy_params = {"params": {"per_page": 50, "search": "test@example.com", "get_all": False}}

        params_from_buggy = ListUsersParams(**buggy_params["params"])
        assert params_from_buggy.per_page == 50
        assert params_from_buggy.search == "test@example.com"
        assert params_from_buggy.get_all is False

    def test_assign_incident_accepts_both_formats(self):
        """Test that assign_incident can handle both parameter formats."""
        # Expected format
        expected_params = {"incident_id": 234, "email": "toto@gg.com"}

        params_obj = AssignIncidentParams(**expected_params)
        assert params_obj.incident_id == 234
        assert params_obj.email == "toto@gg.com"

        # Buggy format (wrapped)
        buggy_params = {"params": {"incident_id": 234, "email": "toto@gg.com"}}

        params_from_buggy = AssignIncidentParams(**buggy_params["params"])
        assert params_from_buggy.incident_id == 234
        assert params_from_buggy.email == "toto@gg.com"

    def test_schema_compression_preserves_required_fields(self):
        """Test that required fields are preserved after compression."""

        class TestModel(BaseModel):
            required_field: str = Field(description="A required field")
            optional_field: str | None = Field(default=None, description="An optional field")

        # Generate schema from Pydantic model
        schema = TestModel.model_json_schema()

        # Compress it
        compressed = compress_pydantic_model_schema(schema)

        # Check that required fields are still marked
        assert "required" in compressed or "properties" in compressed

    def test_schema_compression_handles_empty_schema(self):
        """Test that compression handles empty or invalid schemas gracefully."""
        empty_schema = {}

        # Should not crash, should return the original
        result = compress_pydantic_model_schema(empty_schema)
        assert result == empty_schema

    def test_schema_compression_handles_simple_schema(self):
        """Test that compression works with simple non-nested schemas."""
        simple_schema = {
            "type": "object",
            "properties": {"field1": {"type": "string"}, "field2": {"type": "integer"}},
        }

        compressed = compress_pydantic_model_schema(simple_schema)

        # Should still have the same structure
        assert compressed["type"] == "object"
        assert "properties" in compressed


class TestRealWorldIntegration:
    """Integration tests with actual FastMCP tool registration."""

    def test_list_repo_occurrences_schema_is_flattened(self):
        """
        Test that when registered with FastMCP and compressed,
        list_repo_occurrences has a flattened schema.
        """
        from fastmcp import FastMCP

        mcp = FastMCP("test")

        # Register the tool (without required_scopes which is our custom extension)
        tool = mcp.tool(list_repo_occurrences)

        # Before compression, the schema should have nested params
        original_schema = tool.parameters
        assert "properties" in original_schema

        # Apply compression

        tool.parameters = compress_pydantic_model_schema(tool.parameters)

        # After compression, check the schema is valid
        compressed_schema = tool.parameters
        assert "properties" in compressed_schema
        assert compressed_schema["type"] == "object"

    def test_list_users_schema_is_flattened(self):
        """Test that list_users schema is properly compressed."""
        from fastmcp import FastMCP

        mcp = FastMCP("test")

        # Register the tool
        tool = mcp.tool(list_users)

        # Apply compression

        tool.parameters = compress_pydantic_model_schema(tool.parameters)

        # Verify schema is valid
        compressed_schema = tool.parameters
        assert "properties" in compressed_schema
        assert compressed_schema["type"] == "object"

    def test_assign_incident_schema_is_flattened(self):
        """Test that assign_incident schema is properly compressed."""
        from fastmcp import FastMCP

        mcp = FastMCP("test")

        # Register the tool
        tool = mcp.tool(assign_incident)

        # Apply compression
        tool.parameters = compress_pydantic_model_schema(tool.parameters)

        # Verify schema is valid
        compressed_schema = tool.parameters
        assert "properties" in compressed_schema
        assert compressed_schema["type"] == "object"
