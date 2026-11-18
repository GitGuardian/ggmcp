from unittest.mock import AsyncMock, patch

import pytest
from fastmcp.exceptions import ToolError

from gg_api_core.tools.get_gitguardian_resource import GetGitGuardianResourceParams, get_gitguardian_resource


async def test_outside_a_server_the_workspace_comes_from_the_client():
    """
    GIVEN the tool called directly, with no running server to hold the cached token info
    WHEN a link names a workspace other than the token's
    THEN the client's own token lookup supplies the workspace, and the link is refused before any incident read
    """
    client = AsyncMock()
    client.get_current_token_info = AsyncMock(return_value={"workspace_id": 1})

    with patch("gg_api_core.tools.get_gitguardian_resource.get_client", AsyncMock(return_value=client)):
        with pytest.raises(ToolError, match="workspace 2"):
            await get_gitguardian_resource(
                GetGitGuardianResourceParams(url="https://dashboard.gitguardian.com/workspace/2/incidents/77")
            )

    client.get_incident.assert_not_called()
