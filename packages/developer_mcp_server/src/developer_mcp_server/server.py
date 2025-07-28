"""GitGuardian MCP server for developers with remediation tools."""

import json
import logging
import os
from typing import Any

from gg_api_core.mcp_server import GitGuardianFastMCP
from gg_api_core.scopes import get_developer_scopes, is_self_hosted_instance, validate_scopes
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import Field

# Configure more detailed logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)

# Log environment variables
gitguardian_url = os.environ.get("GITGUARDIAN_URL")

logger.info("Starting Developer MCP Server")
logger.debug(f"GitGuardian URL: {gitguardian_url or 'Using default'}")

# Set specific environment variable for this server to request only developer-specific scopes
# Use dynamic scope detection based on instance type (self-hosted vs SaaS)
# But respect user-specified scopes if they exist
is_self_hosted = is_self_hosted_instance(gitguardian_url)

# Only override scopes if user hasn't specified them
if not os.environ.get("GITGUARDIAN_SCOPES"):
    developer_scopes = get_developer_scopes(gitguardian_url)
    os.environ["GITGUARDIAN_SCOPES"] = ",".join(developer_scopes)
    logger.debug(f"Auto-detected scopes for instance type: {'Self-hosted' if is_self_hosted else 'SaaS'}")
    if is_self_hosted:
        logger.info("Self-hosted instance detected - honeytokens:write scope omitted to avoid permission issues")
else:
    # Validate user-specified scopes
    try:
        user_scopes_str = os.environ.get("GITGUARDIAN_SCOPES")
        validated_scopes = validate_scopes(user_scopes_str)
        os.environ["GITGUARDIAN_SCOPES"] = ",".join(validated_scopes)
        logger.info(f"Using validated user-specified scopes: {os.environ.get('GITGUARDIAN_SCOPES')}")
    except ValueError as e:
        logger.error(f"Invalid scopes configuration: {e}")
        logger.error("Please check your GITGUARDIAN_SCOPES environment variable")
        raise

logger.debug(f"Final scopes: {os.environ.get('GITGUARDIAN_SCOPES')}")

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
    
    4. **Generate and hide honey tokens**:
       - Use `generate_honey_tokens` to generate and hide honey tokens
       - If you want to create a new token, you must pass new_token=True to generate_honey_tokens
       - hide the generated token in the codebase


    All tools operate within your IDE environment to provide immediate feedback and remediation steps for secret management.
    """,
)
logger.info("Created Developer GitGuardianFastMCP instance")


@mcp.tool(
    description="Find and fix secrets in the current repository by detecting incidents, removing them from code, and providing remediation steps. By default, this only shows incidents assigned to the current user. Pass mine=False to get all incidents related to this repo.",
    required_scopes=["incidents:read", "sources:read"],
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
    logger.debug(f"Using remediate_secret_incidents with sources API for: {repository_name}")

    try:
        incidents_result = await list_repo_incidents(
            repository_name=repository_name,
            get_all=get_all,
            mine=mine,
            # Explicitly pass None for optional parameters to avoid FieldInfo objects
            from_date=None,
            to_date=None,
            presence=None,
            tags=None,
            ordering=None,
            per_page=20,
            cursor=None,
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
        logger.debug(f"Processing {len(incidents)} incidents for remediation")
        result = await _process_incidents_for_remediation(
            incidents=incidents,
            repository_name=repository_name,
            include_git_commands=include_git_commands,
            create_env_example=create_env_example,
        )
        logger.debug(
            f"Remediation processing complete, returning result with {len(result.get('remediation_steps', []))} steps"
        )
        return result

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
    remediation_steps = []
    for incident in incidents:
        step = {
            "incident_id": incident.get("id"),
            "secret_type": incident.get("type"),
            "recommendations": [
                f"Remove the secret from {len(incident.get('repository_occurrences', []))} files",
                "Use environment variables instead of hardcoded secrets",
            ],
            "include_git_commands": include_git_commands,
            "create_env_example": create_env_example,
        }
        remediation_steps.append(step)

    return {
        "repository_info": {"name": repository_name},
        "incidents_count": len(incidents),
        "incidents": incidents,
        "remediation_steps": remediation_steps,
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

        logger.debug(f"Scanning {len(documents)} documents for secrets")
        logger.debug(f"Documents to scan: {safe_docs_log}")

        # Make the API call
        result = await client.multiple_scan(documents)
        logger.debug(f"Scanned {len(documents)} documents")

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
        mine: If True, fetch only incidents assigned to the current user. Set to False to get all incidents.

    Returns:
        List of incidents and occurrences matching the specified criteria
    """
    client = mcp.get_client()
    logger.debug(f"Using optimized list_repo_incidents with sources API for repository: {repository_name}")

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
    description="Generate an AWS GitGuardian honeytoken and get injection recommendations",
    required_scopes=["honeytokens:write"],
)
async def generate_honeytoken(
    name: str = Field(description="Name for the honeytoken"),
    description: str = Field(default="", description="Description of what the honeytoken is used for"),
    new_token: bool = Field(
        default=False,
        description="If False, retrieves an existing active honeytoken created by you instead of generating a new one. "
        "If no existing token is found, a new one will be created. "
        "To generate a new token, set this to True.",
    ),
) -> dict[str, Any]:
    """
    Generate an AWS GitGuardian honeytoken and get injection recommendations.

    Args:
        name: Name for the honeytoken
        description: Description of what the honeytoken is used for
        new_token: If False, retrieves an existing active honeytoken created by you instead of generating a new one.
                  If no existing token is found, a new one will be created.
                  IMPORTANT: If you want to generate a new token, set this to True.

    Returns:
        Honeytoken data and injection recommendations
    """
    client = mcp.get_client()
    logger.debug(f"Processing honeytoken request with name: {name}, new_token: {new_token}")

    # If new_token is False, try to find an existing honeytoken created by the current user
    if not new_token:
        try:
            # Get current user's info
            token_info = await client.get_current_token_info()
            if token_info and "user_id" in token_info:
                current_user_id = token_info["user_id"]

                # List honeytokens created by the current user
                filters = {
                    "status": "ACTIVE",  # Only get active tokens
                    "creator_id": current_user_id,
                    "per_page": 10,  # Fetch just a few recent ones
                    "ordering": "-created_at",  # Get newest first
                }

                logger.debug(f"Looking for existing honeytokens for user {current_user_id}")
                result = await client.list_honeytokens(**filters)

                # Process the result to get the list of tokens
                if isinstance(result, dict):
                    honeytokens = result.get("honeytokens", [])
                else:
                    honeytokens = result

                # Find the most recent active token
                if honeytokens:
                    logger.debug(f"Found {len(honeytokens)} existing honeytokens, using the most recent one")
                    # Get the full honeytoken with token details
                    honeytoken_id = honeytokens[0].get("id")
                    if honeytoken_id:
                        detailed_token = await client.get_honeytoken(honeytoken_id, show_token=True)
                        logger.debug(f"Retrieved existing honeytoken with ID: {honeytoken_id}")
                        return detailed_token

                logger.debug("No suitable existing honeytokens found, creating a new one")
            else:
                logger.warning("Could not determine current user ID, creating a new honeytoken instead")
        except Exception as e:
            logger.warning(f"Error while looking for existing honeytokens: {str(e)}. Creating a new one instead.")

    # Create a new honeytoken if requested or if we couldn't find an existing one
    try:
        # Generate the honeytoken with default tags
        custom_tags = [
            {"key": "source", "value": "auto-generated"},
            {"key": "type", "value": "aws"},
        ]
        result = await client.create_honeytoken(name=name, description=description, custom_tags=custom_tags)

        # Validate that we got an ID in the response
        if not result.get("id"):
            raise ToolError("Failed to get honeytoken ID from GitGuardian API")

        logger.debug(f"Generated new honeytoken with ID: {result.get('id')}")

        # Add injection recommendations to the response
        result["injection_recommendations"] = {
            "instructions": "Add the honeytoken to your codebase in configuration files, environment variables, or code comments to detect unauthorized access."
        }

        return result
    except Exception as e:
        logger.error(f"Error generating honeytoken: {str(e)}")
        raise ToolError(f"Failed to generate honeytoken: {str(e)}")


@mcp.tool(
    description="List honeytokens from the GitGuardian dashboard with filtering options",
    required_scopes=["honeytokens:read"],
)
async def list_honeytokens(
    status: str | None = Field(default=None, description="Filter by status (ACTIVE or REVOKED)"),
    search: str | None = Field(default=None, description="Search string to filter results by name or description"),
    ordering: str | None = Field(
        default=None, description="Sort field (e.g., 'name', '-name', 'created_at', '-created_at')"
    ),
    show_token: bool = Field(default=False, description="Whether to include token details in the response"),
    creator_id: str | None = Field(default=None, description="Filter by creator ID"),
    creator_api_token_id: str | None = Field(default=None, description="Filter by creator API token ID"),
    per_page: int = Field(default=20, description="Number of results per page (default: 20, min: 1, max: 100)"),
    get_all: bool = Field(default=False, description="If True, fetch all results using cursor-based pagination"),
    mine: bool = Field(default=False, description="If True, fetch honeytokens created by the current user"),
) -> list[dict[str, Any]]:
    """
    List honeytokens from the GitGuardian dashboard with filtering options.

    Args:
        status: Filter by status (ACTIVE or REVOKED)
        search: Search string to filter results by name or description
        ordering: Sort field (e.g., 'name', '-name', 'created_at', '-created_at')
        show_token: Whether to include token details in the response
        creator_id: Filter by creator ID
        creator_api_token_id: Filter by creator API token ID
        per_page: Number of results per page (default: 20, min: 1, max: 100)
        get_all: If True, fetch all results using cursor-based pagination
        mine: If True, fetch honeytokens created by the current user

    Returns:
        List of honeytokens matching the specified criteria
    """
    client = mcp.get_client()
    logger.debug("Listing honeytokens with filters")

    # Handle mine parameter separately - if mine=True, we'll need to get
    # the current user's info first and set creator_id accordingly
    if mine:
        try:
            # Get current token info to identify the user
            token_info = await client.get_current_token_info()
            if token_info and "user_id" in token_info:
                # If we have user_id, use it as creator_id
                creator_id = token_info["user_id"]
                logger.debug(f"Setting creator_id to current user: {creator_id}")
            else:
                logger.warning("Could not determine current user ID for 'mine' filter")
        except Exception as e:
            logger.warning(f"Failed to get current user info for 'mine' filter: {str(e)}")

    # Build filters dictionary with parameters supported by the client API
    filters = {
        "status": status,
        "search": search,
        "ordering": ordering,
        "show_token": show_token,
        "creator_id": creator_id,
        "creator_api_token_id": creator_api_token_id,
        "per_page": per_page,
        "get_all": get_all,
    }

    logger.debug(f"Filters: {json.dumps({k: v for k, v in filters.items() if v is not None})}")

    try:
        result = await client.list_honeytokens(**filters)

        # Handle both response formats: either a dict with 'honeytokens' key or a list directly
        if isinstance(result, dict):
            honeytokens = result.get("honeytokens", [])
        else:
            # If the result is already a list, use it directly
            honeytokens = result

        logger.debug(f"Found {len(honeytokens)} honeytokens")
        return honeytokens
    except Exception as e:
        logger.error(f"Error listing honeytokens: {str(e)}")
        raise ToolError(str(e))


# Register common tools for user information and token management
try:
    from gg_api_core.mcp_server import register_common_tools

    register_common_tools(mcp)
except Exception as e:
    logger.error(f"Failed to register common tools: {str(e)}")
    import traceback

    logger.error(f"Traceback: {traceback.format_exc()}")


if __name__ == "__main__":
    logger.info("Starting Developer MCP server...")
    mcp.run()
