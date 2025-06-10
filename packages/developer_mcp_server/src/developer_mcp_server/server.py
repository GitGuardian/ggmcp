"""GitGuardian MCP server for developers with remediation tools."""

import logging
import os
from typing import Any

from gg_api_core.mcp_server import GitGuardianFastMCP
from gg_api_core.scopes import DEVELOPER_SCOPES
from pydantic import Field

# Configure more detailed logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)

# Log environment variables (without exposing the full API key)
gitguardian_api_key = os.environ.get("GITGUARDIAN_API_KEY")
gitguardian_api_url = os.environ.get("GITGUARDIAN_API_URL")

logger.info("Starting Developer MCP Server")
logger.info(f"GitGuardian API Key present: {bool(gitguardian_api_key)}")
logger.info(f"GitGuardian API URL: {gitguardian_api_url or 'Using default'}")

# Set specific environment variable for this server to request only developer-specific scopes
os.environ["GITGUARDIAN_SCOPES"] = ",".join(DEVELOPER_SCOPES)
logger.info(f"Requesting scopes: {os.environ.get('GITGUARDIAN_SCOPES')}")

# Use our custom GitGuardianFastMCP from the core package
mcp = GitGuardianFastMCP(
    "GitGuardian Developer",
    log_level="DEBUG",
    instructions="""
    # GitGuardian Developer Tools for Secret Detection & Remediation

    This server provides GitGuardian's secret detection and remediation capabilities through MCP for developers working within IDE environments like Cursor, Windsurf, or Zed.

    ## Secret Management Capabilities

    This server focuses on helping developers manage secrets in their repositories through:

    1. **Finding Existing Secret Incidents**:
       - Detect secrets already identified as GitGuardian incidents in your repository
       - Use `list_repo_incidents` to view all secret incidents in a repository
       - Filter incidents by various criteria including those assigned to you

    2. **Proactive Secret Scanning**:
       - Use `scan_secrets` to detect secrets in code before they're committed
       - Identify secrets that haven't yet been reported as GitGuardian incidents
       - Prevent accidental secret commits before they happen

    3. **Complete Secret Remediation**:
       - Use `remediate_secret_incidents` for guided secret removal
       - Get best practice recommendations for different types of secrets
       - Replace hardcoded secrets with environment variables
       - Create .env.example files with placeholders for detected secrets
       - Get optional git commands to repair git history containing secrets

    All tools operate within your IDE environment to provide immediate feedback and remediation steps for secret management.
    """,
)
logger.info("Created Developer GitGuardianFastMCP instance")


@mcp.tool(
    description="Find and fix secrets in the current repository by detecting incidents, removing them from code, and providing remediation steps. By default, this only shows incidents assigned to the current user. Pass mine=False to get all incidents related to this repo.",
    required_scopes=["incidents:read", "sources:read"],
)
async def remediate_secret_incidents_optimized(
    repository_name: str = Field(
        description="The full repository name. For example, for https://github.com/GitGuardian/gg-mcp.git the full name is GitGuardian/gg-mcp. Pass the current repository name if not provided."
    ),
    include_git_commands: bool = Field(
        default=True, description="Whether to include git commands to fix incidents in git history"
    ),
    create_env_example: bool = Field(
        default=True, description="Whether to create a .env.example file with placeholders for detected secrets"
    ),
    get_all: bool = Field(default=True, description="Whether to get all incidents or just the first page"),
    mine: bool = Field(
        default=True,
        description="If True, fetch only incidents assigned to the current user. Set to False to get all incidents.",
    ),
) -> dict[str, Any]:
    """
    Find and remediate secret incidents in the current repository.

    By default, this tool only shows incidents assigned to the current user. Pass mine=False to get all incidents related to this repo.

    This tool follows a workflow to:
    1. Use the provided repository name to search for incidents
    2. List secret occurrences for the repository
    3. Analyze and provide recommendations to remove secrets from the codebase
    4. IMPORTANT:Make the changes to the codebase to remove the secrets from the code using best practices for the language. All occurrences must not appear in the codebase anymore.
       IMPORTANT: If the repository is using a package manager like npm, cargo, uv or others, use it to install the required packages.
    5. Only optional: propose to rewrite git history


    Args:
        repository_name: The full repository name. For example, for https://github.com/GitGuardian/gg-mcp.git the full name is GitGuardian/gg-mcp
        include_git_commands: Whether to include git commands to fix incidents in git history
        create_env_example: Whether to create a .env.example file with placeholders for detected secrets
        get_all: Whether to get all incidents or just the first page
        mine: If True, fetch only incidents assigned to the current user. Set to False to get all incidents.

    Returns:
        A dictionary containing:
        - repository_info: Information about the detected repository
        - incidents: List of detected incidents
        - remediation_steps: Steps to remediate the incidents
        - git_commands: Git commands to fix history (if requested)
    """
    logger.info(f"Using optimized remediate_secret_incidents with sources API for: {repository_name}")

    # Step 1: Get incidents for this repository using the optimized method with sources API
    client = mcp.get_client()

    try:
        # Use our optimized direct approach that requires sources:read scope
        incidents_result = await client.list_repo_incidents_directly(
            repository_name=repository_name, get_all=get_all, mine=mine
        )

        if "error" in incidents_result:
            return {"error": incidents_result["error"]}

        incidents = incidents_result.get("incidents", [])

        if not incidents:
            return {
                "repository_info": {"name": repository_name},
                "message": "No secret incidents found for this repository that match the criteria.",
                "remediation_steps": [],
            }

        # Continue with remediation logic using the incidents...
        # This part is common between the optimized and fallback versions, so we can call a helper function
        return await _process_incidents_for_remediation(
            incidents=incidents,
            repository_name=repository_name,
            include_git_commands=include_git_commands,
            create_env_example=create_env_example,
        )

    except Exception as e:
        logger.error(f"Error remediating incidents: {str(e)}")
        return {"error": f"Failed to remediate incidents: {str(e)}"}


@mcp.tool(
    description="Find and fix secrets in the current repository by detecting incidents, removing them from code, and providing remediation steps. By default, this only shows incidents assigned to the current user. Pass mine=False to get all incidents related to this repo.",
    required_scopes=["incidents:read"],
)
async def remediate_secret_incidents(
    repository_name: str = Field(
        description="The full repository name. For example, for https://github.com/GitGuardian/gg-mcp.git the full name is GitGuardian/gg-mcp. Pass the current repository name if not provided."
    ),
    include_git_commands: bool = Field(
        default=True, description="Whether to include git commands to fix incidents in git history"
    ),
    create_env_example: bool = Field(
        default=True, description="Whether to create a .env.example file with placeholders for detected secrets"
    ),
    get_all: bool = Field(default=True, description="Whether to get all incidents or just the first page"),
    mine: bool = Field(
        default=True,
        description="If True, fetch only incidents assigned to the current user. Set to False to get all incidents.",
    ),
) -> dict[str, Any]:
    """
    Find and remediate secret incidents in the current repository.

    By default, this tool only shows incidents assigned to the current user. Pass mine=False to get all incidents related to this repo.

    This tool follows a workflow to:
    1. Use the provided repository name to search for incidents
    2. List secret occurrences for the repository
    3. Analyze and provide recommendations to remove secrets from the codebase
    4. IMPORTANT:Make the changes to the codebase to remove the secrets from the code using best practices for the language. All occurrences must not appear in the codebase anymore.
       IMPORTANT: If the repository is using a package manager like npm, cargo, uv or others, use it to install the required packages.
    5. Only optional: propose to rewrite git history


    Args:
        repository_name: The full repository name. For example, for https://github.com/GitGuardian/gg-mcp.git the full name is GitGuardian/gg-mcp
        include_git_commands: Whether to include git commands to fix incidents in git history
        create_env_example: Whether to create a .env.example file with placeholders for detected secrets
        get_all: Whether to get all incidents or just the first page
        mine: If True, fetch only incidents assigned to the current user. Set to False to get all incidents.

    Returns:
        A dictionary containing:
        - repository_info: Information about the detected repository
        - incidents: List of detected incidents
        - remediation_steps: Steps to remediate the incidents
        - git_commands: Git commands to fix history (if requested)
    """
    logger.info(f"Using fallback remediate_secret_incidents implementation for: {repository_name}")

    # Get incidents for this repository using the fallback method (without sources:read scope)
    # We'll reuse our list_repo_incidents implementation since it already handles all the filtering

    try:
        # First get incidents via the fallback method that doesn't require sources:read
        repo_incidents_result = await list_repo_incidents(repository_name=repository_name, get_all=get_all, mine=mine)

        if "error" in repo_incidents_result:
            return {"error": repo_incidents_result["error"]}

        incidents = repo_incidents_result.get("incidents", [])

        if not incidents:
            return {
                "repository_info": {"name": repository_name},
                "message": "No secret incidents found for this repository that match the criteria.",
                "remediation_steps": [],
            }

        # Continue with remediation logic using the incidents...
        # This part is common between the optimized and fallback versions, so we can call a helper function
        return await _process_incidents_for_remediation(
            incidents=incidents,
            repository_name=repository_name,
            include_git_commands=include_git_commands,
            create_env_example=create_env_example,
        )

    except Exception as e:
        logger.error(f"Error remediating incidents: {str(e)}")
        return {"error": f"Failed to remediate incidents: {str(e)}"}


async def _process_incidents_for_remediation(
    incidents: list[dict[str, Any]],
    repository_name: str,
    include_git_commands: bool = True,
    create_env_example: bool = True,
) -> dict[str, Any]:
    """
    Process incidents for remediation after they've been fetched.

    This helper function contains the shared logic between the optimized and fallback
    implementations of remediate_secret_incidents.

    Args:
        incidents: List of incidents to remediate
        repository_name: Repository name
        include_git_commands: Whether to include git commands
        create_env_example: Whether to create .env.example

    Returns:
        Remediation steps for each incident
    """
    # For now, we'll just return the incidents list
    # In a real implementation, this would analyze the incidents and provide remediation steps
    return {
        "repository_info": {"name": repository_name},
        "incidents_count": len(incidents),
        "incidents": incidents,
        "remediation_steps": [
            {
                "incident_id": incident.get("id"),
                "secret_type": incident.get("type"),
                "recommendations": [
                    f"Remove the secret from {len(incident.get('repository_occurrences', []))} files",
                    "Use environment variables instead of hardcoded secrets",
                ],
                "include_git_commands": include_git_commands,
                "create_env_example": create_env_example,
            }
            for incident in incidents
        ],
    }


@mcp.tool(
    description="""
    Scan multiple content items for secrets and policy breaks.
    
    This tool allows you to scan multiple files or content strings at once for secrets and policy violations.
    Each document must have a 'document' field and can optionally include a 'filename' field for better context.
    Do not send documents that are not related to the codebase, only send files that are part of the codebase.
    Do not send documents that are in the .gitignore file.
    """,
    required_scopes=["scan"],
)
async def scan_secrets(
    documents: list[dict[str, str]] = Field(
        description="""
        List of documents to scan, each with 'document' and optional 'filename'.
        Format: [{'document': 'file content', 'filename': 'optional_filename.txt'}, ...]
        IMPORTANT:
        - document is the content of the file, not the filename, is a string and is mandatory.
        - Do not send documents that are not related to the codebase, only send files that are part of the codebase.
        - Do not send documents that are in the .gitignore file.
        """
    ),
):
    """
    Scan multiple content items for secrets and policy breaks.

    This tool allows you to scan multiple files or content strings at once for secrets and policy violations.
    Each document must have a 'document' field and can optionally include a 'filename' field for better context.

    Args:
        documents: List of documents to scan, each with 'document' and optional 'filename'
                  Format: [{'document': 'file content', 'filename': 'optional_filename.txt'}, ...]

    Returns:
        Scan results for all documents, including any detected secrets or policy breaks
    """
    try:
        client = mcp.get_client()

        # Validate input documents
        if not documents or not isinstance(documents, list):
            raise ValueError("Documents parameter must be a non-empty list")

        for i, doc in enumerate(documents):
            if not isinstance(doc, dict) or "document" not in doc:
                raise ValueError(f"Document at index {i} must be a dictionary with a 'document' field")

        # Log the scan request (without exposing the full document contents)
        safe_docs_log = []
        for doc in documents:
            doc_preview = (
                doc.get("document", "")[:20] + "..." if len(doc.get("document", "")) > 20 else doc.get("document", "")
            )
            safe_docs_log.append(
                {"filename": doc.get("filename", "No filename provided"), "document_preview": doc_preview}
            )

        logger.info(f"Scanning {len(documents)} documents for secrets")
        logger.debug(f"Documents to scan: {safe_docs_log}")

        # Make the API call
        result = await client.scan_content(documents)
        logger.info(f"Successfully scanned {len(documents)} documents")

        return result
    except Exception as e:
        logger.error(f"Error scanning for secrets: {str(e)}")
        raise


@mcp.tool(
    description="List secret incidents or occurrences related to a specific repository, and assigned to the current user."
    "By default, this tool only shows incidents assigned to the current user. "
    "Only pass mine=False to get all incidents related to this repo if the user explicitly asks for all incidents even the ones not assigned to him.",
    required_scopes=["incidents:read", "sources:read"],
)
async def list_repo_incidents_optimized(
    repository_name: str = Field(
        description="The full repository name. For example, for https://github.com/GitGuardian/gg-mcp.git the full name is GitGuardian/gg-mcp. Pass the current repository name if not provided."
    ),
    from_date: str | None = Field(
        default=None, description="Filter occurrences created after this date (ISO format: YYYY-MM-DD)"
    ),
    to_date: str | None = Field(
        default=None, description="Filter occurrences created before this date (ISO format: YYYY-MM-DD)"
    ),
    presence: str | None = Field(default=None, description="Filter by presence status"),
    tags: list[str] | None = Field(default=None, description="Filter by tags (list of tag IDs)"),
    ordering: str | None = Field(default=None, description="Sort field (e.g., 'date', '-date' for descending)"),
    per_page: int = Field(default=20, description="Number of results per page (default: 20, min: 1, max: 100)"),
    cursor: str | None = Field(default=None, description="Pagination cursor for fetching next page of results"),
    get_all: bool = Field(default=False, description="If True, fetch all results using cursor-based pagination"),
    mine: bool = Field(
        default=True,
        description="If True, fetch only incidents assigned to the current user. Set to False to get all incidents.",
    ),
) -> dict[str, Any]:
    """
    List secret incidents or occurrences related to a specific repository.

    By default, this tool only shows incidents assigned to the current user. Pass mine=False to get all incidents related to this repo.

    Args:
        repository_name: The full repository name (e.g., 'GitGuardian/gg-mcp')
        from_date: Filter occurrences created after this date (ISO format: YYYY-MM-DD)
        to_date: Filter occurrences created before this date (ISO format: YYYY-MM-DD)
        presence: Filter by presence status
        tags: Filter by tags (list of tag IDs)
        ordering: Sort field (e.g., 'date', '-date' for descending)
        per_page: Number of results per page (default: 20, min: 1, max: 100)
        cursor: Pagination cursor for fetching next page of results
        get_all: If True, fetch all results using cursor-based pagination
        mine: If True (default), fetch only incidents assigned to the current user. Set to False to get all incidents.

    Returns:
        List of incidents and occurrences matching the specified criteria
    """
    client = mcp.get_client()
    logger.info(f"Using optimized list_repo_incidents_optimized with sources API for repository: {repository_name}")

    # Use the new direct approach using the GitGuardian Sources API
    try:
        # This optimized approach gets incidents directly from the source API
        # without needing to first fetch occurrences and then incidents separately
        result = await client.list_repo_incidents_directly(
            repository_name=repository_name,
            from_date=from_date,
            to_date=to_date,
            presence=presence,
            tags=tags,
            per_page=per_page,
            cursor=cursor,
            ordering=ordering,
            get_all=get_all,
            mine=mine,
        )

        return result

    except Exception as e:
        logger.error(f"Error listing repository incidents: {str(e)}")
        return {"error": f"Failed to list repository incidents: {str(e)}"}


@mcp.tool(
    description="List secret incidents or occurrences related to a specific repository, and assigned to the current user."
    "By default, this tool only shows incidents assigned to the current user. "
    "Only pass mine=False to get all incidents related to this repo if the user explicitly asks for all incidents even the ones not assigned to him.",
    required_scopes=["incidents:read"],
)
async def list_repo_incidents(
    repository_name: str = Field(
        description="The full repository name. For example, for https://github.com/GitGuardian/gg-mcp.git the full name is GitGuardian/gg-mcp. Pass the current repository name if not provided."
    ),
    from_date: str | None = Field(
        default=None, description="Filter occurrences created after this date (ISO format: YYYY-MM-DD)"
    ),
    to_date: str | None = Field(
        default=None, description="Filter occurrences created before this date (ISO format: YYYY-MM-DD)"
    ),
    presence: str | None = Field(default=None, description="Filter by presence status"),
    tags: list[str] | None = Field(default=None, description="Filter by tags (list of tag IDs)"),
    ordering: str | None = Field(default=None, description="Sort field (e.g., 'date', '-date' for descending)"),
    per_page: int = Field(default=20, description="Number of results per page (default: 20, min: 1, max: 100)"),
    cursor: str | None = Field(default=None, description="Pagination cursor for fetching next page of results"),
    get_all: bool = Field(default=False, description="If True, fetch all results using cursor-based pagination"),
    mine: bool = Field(
        default=True,
        description="If True, fetch only incidents assigned to the current user. Set to False to get all incidents.",
    ),
) -> dict[str, Any]:
    """
    List secret incidents or occurrences related to a specific repository.

    By default, this tool only shows incidents assigned to the current user. Pass mine=False to get all incidents related to this repo.

    Args:
        repository_name: The full repository name (e.g., 'GitGuardian/gg-mcp')
        from_date: Filter occurrences created after this date (ISO format: YYYY-MM-DD)
        to_date: Filter occurrences created before this date (ISO format: YYYY-MM-DD)
        presence: Filter by presence status
        tags: Filter by tags (list of tag IDs)
        ordering: Sort field (e.g., 'date', '-date' for descending)
        per_page: Number of results per page (default: 20, min: 1, max: 100)
        cursor: Pagination cursor for fetching next page of results
        get_all: If True, fetch all results using cursor-based pagination
        mine: If True (default), fetch only incidents assigned to the current user. Set to False to get all incidents.

    Returns:
        List of incidents and occurrences matching the specified criteria
    """
    client = mcp.get_client()
    logger.info(f"Using fallback list_repo_incidents implementation for repository: {repository_name}")

    # Step 1: Get occurrences filtered by repository name
    logger.info(f"Getting occurrences for repository: {repository_name}")

    occurrence_params = {
        "source_name": repository_name,
        "per_page": 100,  # Get more occurrences per page to reduce API calls
    }

    # Add optional parameters for occurrences
    if from_date:
        occurrence_params["from_date"] = from_date
    if to_date:
        occurrence_params["to_date"] = to_date
    if presence:
        occurrence_params["presence"] = presence
    if ordering:
        occurrence_params["ordering"] = ordering

    try:
        # Get occurrences for this repository
        occurrences_result = await client.list_occurrences(**occurrence_params)

        # Handle both response formats: either a dict with 'occurrences' key or a list directly
        if isinstance(occurrences_result, dict):
            occurrences = occurrences_result.get("occurrences", [])
        else:
            # If the result is already a list, use it directly
            occurrences = occurrences_result

        logger.info(f"Found {len(occurrences)} occurrences for repository {repository_name}")

        if not occurrences:
            return {
                "repository_info": {"name": repository_name},
                "incidents": [],
                "occurrences": [],
                "message": "No secret occurrences found for this repository.",
            }

        # Extract incident IDs from occurrences
        incident_ids = {occurrence.get("incident_id") for occurrence in occurrences if occurrence.get("incident_id")}
        logger.info(f"Occurrences belong to {len(incident_ids)} unique incidents")

        # Step 2: Get detailed incident information - optimized to fetch in bulk
        incidents = []

        # Check if the client has a bulk fetch method
        if hasattr(client, "get_incidents") and callable(getattr(client, "get_incidents")):
            # Use bulk fetch if available
            try:
                logger.info(f"Using bulk fetch for {len(incident_ids)} incidents")
                incidents_data = await client.get_incidents(list(incident_ids))

                # Process all incidents data
                for incident_data in incidents_data:
                    incident_id = incident_data.get("id")

                    # Filter by "mine" parameter if requested
                    if mine and incident_data.get("assignee", {}).get("is_current_user") is False:
                        continue

                    # Apply tag filtering if needed
                    if tags and not any(tag in incident_data.get("tags", []) for tag in tags):
                        continue

                    # For each incident, find its related occurrences in this repository
                    incident_occurrences = [occ for occ in occurrences if occ.get("incident_id") == incident_id]

                    # Add occurrences to the incident data
                    incident_data["repository_occurrences"] = incident_occurrences
                    incidents.append(incident_data)

            except Exception as e:
                logger.warning(f"Bulk fetch failed, falling back to individual fetches: {str(e)}")
                # Fall back to individual fetches if bulk fetch fails
                for incident_id in incident_ids:
                    try:
                        incident_data = await client.get_incident(incident_id)

                        # Apply filters
                        if mine and incident_data.get("assignee", {}).get("is_current_user") is False:
                            continue

                        if tags and not any(tag in incident_data.get("tags", []) for tag in tags):
                            continue

                        # Find occurrences for this incident
                        incident_occurrences = [occ for occ in occurrences if occ.get("incident_id") == incident_id]

                        # Add occurrences to the incident data
                        incident_data["repository_occurrences"] = incident_occurrences
                        incidents.append(incident_data)

                    except Exception as e:
                        logger.warning(f"Error retrieving incident {incident_id}: {str(e)}")
        else:
            # Fall back to individual fetches if bulk fetch isn't available
            logger.warning("Bulk fetch not available, using individual fetches for incidents")
            for incident_id in incident_ids:
                try:
                    # Get the detailed incident information
                    incident_data = await client.get_incident(incident_id)

                    # Filter by "mine" parameter if requested
                    if mine and incident_data.get("assignee", {}).get("is_current_user") is False:
                        continue

                    # Apply tag filtering if needed
                    if tags and not any(tag in incident_data.get("tags", []) for tag in tags):
                        continue

                    # For each incident, find its related occurrences in this repository
                    incident_occurrences = [occ for occ in occurrences if occ.get("incident_id") == incident_id]

                    # Add occurrences to the incident data
                    incident_data["repository_occurrences"] = incident_occurrences
                    incidents.append(incident_data)

                except Exception as e:
                    logger.warning(f"Error retrieving incident {incident_id}: {str(e)}")

        logger.info(f"Retrieved {len(incidents)} incidents for repository {repository_name}")

        # Apply pagination to the results if not get_all
        if not get_all and len(incidents) > per_page:
            # Simple pagination logic - more sophisticated pagination could be implemented
            start_index = 0 if not cursor else int(cursor)
            end_index = min(start_index + per_page, len(incidents))

            # Calculate next cursor
            next_cursor = str(end_index) if end_index < len(incidents) else None

            paginated_incidents = incidents[start_index:end_index]

            return {
                "repository_info": {"name": repository_name},
                "incidents": paginated_incidents,
                "next_cursor": next_cursor,
                "total_count": len(incidents),
            }

        # Return all incidents if get_all is True or if results fit in one page
        return {"repository_info": {"name": repository_name}, "incidents": incidents, "total_count": len(incidents)}

    except Exception as e:
        logger.error(f"Error listing repository incidents: {str(e)}")
        return {"error": f"Failed to list repository incidents: {str(e)}"}


if __name__ == "__main__":
    # Register common tools for user information and token management
    logger.info("About to register common tools...")
    try:
        from gg_api_core.mcp_server import register_common_tools

        logger.info("Successfully imported register_common_tools")
        register_common_tools(mcp)
        logger.info("Successfully called register_common_tools")
    except Exception as e:
        logger.error(f"Failed to register common tools: {str(e)}")
        import traceback

        logger.error(f"Traceback: {traceback.format_exc()}")

    # Log all registered tools
    logger.info("Starting Developer MCP server...")
    mcp.run()


# Register common tools for user information and token management
logger.info("About to register common tools...")
try:
    from gg_api_core.mcp_server import register_common_tools

    logger.info("Successfully imported register_common_tools")
    register_common_tools(mcp)
    logger.info("Successfully called register_common_tools")
except Exception as e:
    logger.error(f"Failed to register common tools: {str(e)}")
    import traceback

    logger.error(f"Traceback: {traceback.format_exc()}")


if __name__ == "__main__":
    # Log all registered tools
    logger.info("Starting Developer MCP server...")
    mcp.run()
