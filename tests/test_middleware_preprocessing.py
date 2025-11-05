"""Tests for middleware parameter preprocessing to handle Claude Code bug.

Claude Code has a bug where it serializes Pydantic model parameters as JSON strings
instead of proper dictionaries. The middleware in mcp_server.py converts these strings
back to dicts before FastMCP's validation layer.

See: https://github.com/anthropics/claude-code/issues/3084
"""

from gg_api_core.tools.assign_incident import AssignIncidentParams
from gg_api_core.tools.list_repo_occurrences import ListRepoOccurrencesParams
from gg_api_core.tools.list_users import ListUsersParams


class TestPydanticModelParsing:
    """Test suite to verify Pydantic models can parse both expected and buggy formats."""

    def test_list_repo_occurrences_parses_direct_params(self):
        """Test that Pydantic model can parse direct parameters."""
        params = {"source_id": 9036019, "get_all": True}

        params_obj = ListRepoOccurrencesParams(**params)
        assert params_obj.source_id == 9036019
        assert params_obj.get_all is True

    def test_list_users_parses_direct_params(self):
        """Test that list_users Pydantic model parses parameters."""
        params = {"per_page": 50, "search": "test@example.com", "get_all": False}

        params_obj = ListUsersParams(**params)
        assert params_obj.per_page == 50
        assert params_obj.search == "test@example.com"
        assert params_obj.get_all is False

    def test_assign_incident_parses_direct_params(self):
        """Test that assign_incident Pydantic model parses parameters."""
        params = {"incident_id": 234, "email": "toto@gg.com"}

        params_obj = AssignIncidentParams(**params)
        assert params_obj.incident_id == 234
        assert params_obj.email == "toto@gg.com"


class TestMiddlewareParameterPreprocessing:
    """Test suite for middleware parameter preprocessing."""

    def test_middleware_converts_stringified_json_params(self):
        """Test that middleware converts JSON strings to dicts."""
        import asyncio

        from gg_api_core.mcp_server import GitGuardianPATEnvMCP

        mcp = GitGuardianPATEnvMCP("test", personal_access_token="test_token")

        # Create a mock context with stringified JSON parameters
        class MockContext:
            method = "tools/call"
            params = {"arguments": {"params": '{"source_id": 9036019, "get_all": true}'}}

        async def mock_call_next(ctx):
            # Verify the params were preprocessed
            assert isinstance(ctx.params["arguments"]["params"], dict)
            assert ctx.params["arguments"]["params"]["source_id"] == 9036019
            assert ctx.params["arguments"]["params"]["get_all"] is True
            return "success"

        context = MockContext()

        # Run the middleware
        result = asyncio.run(mcp._parameter_preprocessing_middleware(context, mock_call_next))
        assert result == "success"

    def test_middleware_preserves_dict_params(self):
        """Test that middleware doesn't modify already-valid dict params."""
        import asyncio

        from gg_api_core.mcp_server import GitGuardianPATEnvMCP

        mcp = GitGuardianPATEnvMCP("test", personal_access_token="test_token")

        # Create a mock context with already-valid dict parameters
        class MockContext:
            method = "tools/call"
            params = {"arguments": {"params": {"source_id": 9036019, "get_all": True}}}

        async def mock_call_next(ctx):
            # Verify the params are still a dict
            assert isinstance(ctx.params["arguments"]["params"], dict)
            assert ctx.params["arguments"]["params"]["source_id"] == 9036019
            assert ctx.params["arguments"]["params"]["get_all"] is True
            return "success"

        context = MockContext()

        # Run the middleware
        result = asyncio.run(mcp._parameter_preprocessing_middleware(context, mock_call_next))
        assert result == "success"

    def test_middleware_ignores_non_tool_call_requests(self):
        """Test that middleware only processes tools/call requests."""
        import asyncio

        from gg_api_core.mcp_server import GitGuardianPATEnvMCP

        mcp = GitGuardianPATEnvMCP("test", personal_access_token="test_token")

        # Create a mock context for tools/list
        class MockContext:
            method = "tools/list"
            params = {}

        async def mock_call_next(ctx):
            return "success"

        context = MockContext()

        # Run the middleware - should pass through without modification
        result = asyncio.run(mcp._parameter_preprocessing_middleware(context, mock_call_next))
        assert result == "success"

    def test_middleware_handles_invalid_json_gracefully(self):
        """Test that middleware doesn't crash on invalid JSON strings."""
        import asyncio

        from gg_api_core.mcp_server import GitGuardianPATEnvMCP

        mcp = GitGuardianPATEnvMCP("test", personal_access_token="test_token")

        # Create a mock context with invalid JSON
        class MockContext:
            method = "tools/call"
            params = {"arguments": {"params": "{invalid json"}}

        async def mock_call_next(ctx):
            # Invalid JSON should be left as-is
            assert ctx.params["arguments"]["params"] == "{invalid json"
            return "success"

        context = MockContext()

        # Run the middleware
        result = asyncio.run(mcp._parameter_preprocessing_middleware(context, mock_call_next))
        assert result == "success"
