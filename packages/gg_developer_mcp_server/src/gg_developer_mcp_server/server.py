"""GitGuardian MCP server for developers with remediation tools."""

import json
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
        mine: If True (default), fetch only incidents assigned to the current user. Set to False to get all incidents.

    Returns:
        A dictionary containing:
        - repository_info: Information about the detected repository
        - incidents: List of detected incidents
        - remediation_steps: Steps to remediate the incidents
        - git_commands: Git commands to fix history (if requested)
    """
    client = mcp.get_client()
    logger.info(f"Remediating secret incidents for repository: {repository_name}")

    # Validate repository name
    if not repository_name or "/" not in repository_name:
        logger.warning(f"Invalid repository name format: {repository_name}")
        return {
            "error": "Invalid repository name format. Please provide the full repository name (e.g., 'GitGuardian/gg-mcp')."
        }

    # List repository incidents
    try:
        logger.info(f"Listing incidents for repository: {repository_name}")
        result = await client.list_repo_incidents(
            repository_name=repository_name,
            get_all=get_all,
            mine=mine,
        )

        incidents = result.get("incidents", [])
        logger.info(f"Found {len(incidents)} incidents")

        if not incidents:
            return {
                "repository_info": {"name": repository_name},
                "incidents": [],
                "message": "No secret incidents found for this repository.",
            }

        # Analyze incidents and generate remediation steps
        logger.info("Generating remediation steps")

        # Process the incidents to generate remediation steps
        remediation_steps = []
        for incident in incidents:
            incident_type = incident.get("incident_type", "")
            detail = incident.get("detail", {})
            validity = incident.get("validity", "unknown")

            # Only process valid incidents
            if validity.lower() != "valid":
                continue

            # Get occurrences
            occurrences = incident.get("occurrences", [])

            for occurrence in occurrences:
                file_path = occurrence.get("file_path", "")
                line_start = occurrence.get("line_start")
                line_end = occurrence.get("line_end")

                if file_path and line_start is not None and line_end is not None:
                    remediation_steps.append(
                        {
                            "file_path": file_path,
                            "line_start": line_start,
                            "line_end": line_end,
                            "incident_type": incident_type,
                            "secret_type": detail.get("type", "unknown"),
                            "recommendation": "Replace this secret with an environment variable reference",
                        }
                    )

        # Generate git commands if requested
        git_commands = []
        if include_git_commands:
            git_commands = [
                "# Commands to fix git history (use with caution):",
                "# 1. Stage all your current changes first:",
                "git add .",
                "git commit -m 'Remove secrets from codebase'",
                "",
                "# 2. Use git filter-repo to remove secrets from history (requires git-filter-repo):",
                "# Install git-filter-repo if needed: pip install git-filter-repo",
                "# Create a backup first:",
                "git clone --mirror . ../backup-repo",
                "",
                "# 3. Run for each secret file:",
            ]

            for step in remediation_steps:
                file_path = step.get("file_path")
                if file_path:
                    git_commands.append(f"git filter-repo --path {file_path} --force")

        # Create .env.example content if requested
        env_example_content = ""
        if create_env_example:
            env_vars = []
            for step in remediation_steps:
                secret_type = step.get("secret_type", "").upper()
                if secret_type:
                    placeholder = f"{secret_type.replace(' ', '_')}_SECRET"
                    env_vars.append(f"{placeholder}=your_secret_value_here")

            env_example_content = "\n".join(env_vars)

        # Prepare the final response
        response = {
            "repository_info": {"name": repository_name},
            "incidents": incidents,
            "remediation_steps": remediation_steps,
        }

        if git_commands:
            response["git_commands"] = git_commands

        if env_example_content:
            response["env_example"] = env_example_content

        return response

    except Exception as e:
        logger.error(f"Error remediating secret incidents: {str(e)}")
        return {"error": f"Error: {str(e)}"}


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
    description="""
    List secret incidents or occurrences related to a specific repository. This tool allows you
    to list secret incidents by filtering them based on a repository name.
    
    By default, this tool only shows incidents assigned to the current user. Pass mine=False to get all incidents related to this repo.
    """,
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
):
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
    try:
        client = mcp.get_client()

        # Handle repository name validation
        if not repository_name or "/" not in repository_name:
            logger.error("Repository name is invalid - must be in format 'owner/repo'")
            raise ValueError(
                "Repository name must be in the format 'owner/repo'. "
                "For example, for https://github.com/GitGuardian/gg-mcp.git the full name is GitGuardian/gg-mcp"
            )

        # Log the filter values
        filters = {
            "repository_name": repository_name,
            "from_date": from_date,
            "to_date": to_date,
            "presence": presence,
            "tags": tags,
            "ordering": ordering,
            "per_page": per_page,
            "cursor": cursor,
            "get_all": get_all,
            "mine": mine,
        }

        logger.info(f"Filters: {json.dumps({k: v for k, v in filters.items() if v is not None and k != 'tags'})}")

        if tags:
            logger.info(f"Tags filter: {tags}")

        # Make the API call
        result = await client.list_repo_incidents(
            repository_name=repository_name,
            from_date=from_date,
            to_date=to_date,
            presence=presence,
            tags=tags,
            ordering=ordering,
            per_page=per_page,
            cursor=cursor,
            get_all=get_all,
            mine=mine,
        )

        logger.info(f"Successfully listed incidents for repository {repository_name}")
        return result
    except Exception as e:
        logger.error(f"Error listing repository incidents: {str(e)}")
        raise


if __name__ == "__main__":
    # Log all registered tools
    logger.info("Starting Developer MCP server...")
    mcp.run()
