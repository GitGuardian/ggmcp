import logging
import os
import subprocess
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from gg_api_core.utils import get_client, parse_repo_url

logger = logging.getLogger(__name__)


class SourceCandidate(BaseModel):
    """A candidate source that might match the repository."""

    id: str | int = Field(description="Source ID")
    url: str | None = Field(default=None, description="Repository URL")
    name: str | None = Field(default=None, description="Repository name")
    monitored: bool | None = Field(default=None, description="Whether source is monitored")
    deleted_at: str | None = Field(default=None, description="Deletion timestamp if deleted")


class FindCurrentSourceIdResult(BaseModel):
    """Successful result from finding source ID."""

    repository_name: str = Field(description="Detected repository name")
    source_id: str | int | None = Field(default=None, description="GitGuardian source ID (if exact match)")
    source: dict[str, Any] | None = Field(default=None, description="Full source information (if exact match)")
    message: str | None = Field(default=None, description="Status or informational message")
    suggestion: str | None = Field(default=None, description="Suggestions for next steps")
    candidates: list[SourceCandidate] | None = Field(
        default=None, description="List of candidate sources (if no exact match)"
    )


class FindCurrentSourceIdError(BaseModel):
    """Error result from finding source ID."""

    error: str = Field(description="Error message")
    repository_name: str | None = Field(default=None, description="Repository name if detected")
    details: str | None = Field(default=None, description="Additional error details")
    message: str | None = Field(default=None, description="User-friendly message")
    suggestion: str | None = Field(default=None, description="Suggestions for resolving the error")


async def find_current_source_id(repository_path: str = ".") -> FindCurrentSourceIdResult | FindCurrentSourceIdError:
    """
    Find the GitGuardian source_id for a repository.

    This tool:
    1. Attempts to get the repository name from git remote URL
    2. If git fails, falls back to using the directory name
    3. Searches GitGuardian for matching sources
    4. Returns the source_id if an exact match is found
    5. If no exact match, returns all search results for the model to choose from

    Args:
        repository_path: Path to the repository directory. Defaults to "." (current directory).
                        If you're working in a specific repository, provide the full path to ensure
                        the correct repository is analyzed (e.g., "/home/user/my-project").
                        Note: If the directory is not a git repository, the tool will use the
                        directory name as the repository name.

    Returns:
        FindCurrentSourceIdResult: Pydantic model containing:
            - repository_name: The detected repository name
            - source_id: The GitGuardian source ID (if exact match found)
            - source: Full source information from GitGuardian (if exact match found)
            - message: Status or informational message
            - suggestion: Suggestions for next steps
            - candidates: List of SourceCandidate objects (if no exact match but potential matches found)

        FindCurrentSourceIdError: Pydantic model containing:
            - error: Error message
            - repository_name: Repository name if detected
            - details: Additional error details
            - message: User-friendly message
            - suggestion: Suggestions for resolving the error
    """
    client = await get_client()
    logger.debug(f"Finding source_id for repository at path: {repository_path}")

    repository_name = None
    remote_url = None
    detection_method = None

    try:
        # Try Method 1: Get repository name from git remote URL
        try:
            result = subprocess.run(
                ["git", "config", "--get", "remote.origin.url"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
                cwd=repository_path,
            )
            remote_url = result.stdout.strip()
            parsed_url = parse_repo_url(remote_url)
            if parsed_url:
                repository_name = parsed_url.split("/")[-1]
            else:
                repository_name = None
            detection_method = "git remote URL"
            logger.debug(f"Found remote URL: {remote_url}, parsed repository name: {repository_name}")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            logger.debug(f"Git remote detection failed: {e}, falling back to directory name")

            # Fallback Method 2: Use the directory name as repository name
            abs_path = os.path.abspath(repository_path)
            repository_name = Path(abs_path).name
            detection_method = "directory name"
            logger.info(f"Using directory name as repository name: {repository_name}")

        if not repository_name:
            return FindCurrentSourceIdError(
                error="Could not determine repository name",
                message="Failed to determine repository name from both git remote and directory name.",
                suggestion="Please ensure you're in a valid directory or provide a valid repository_path parameter.",
            )

        logger.info(f"Detected repository name: {repository_name} (method: {detection_method})")

        # Search for the source in GitGuardian with robust non-exact matching
        source_result: dict[str, Any] | list[dict[str, Any]] | None = await client.get_source_by_name(
            repository_name, return_all_on_no_match=True
        )

        # Handle exact match (single dict result)
        if isinstance(source_result, dict):
            source_id: str | int | None = source_result.get("id")
            logger.info(f"Found exact match with source_id: {source_id}")

            message = f"Successfully found exact match for GitGuardian source: {repository_name}"
            if detection_method == "directory name":
                message += f" (repository name inferred from {detection_method})"

            return FindCurrentSourceIdResult(
                repository_name=repository_name,
                source_id=source_id if source_id is not None else "",
                source=source_result,
                message=message,
            )

        # Handle multiple candidates (list result)
        elif isinstance(source_result, list) and len(source_result) > 0:
            logger.info(f"Found {len(source_result)} candidate sources for repository: {repository_name}")

            message = f"No exact match found for '{repository_name}', but found {len(source_result)} potential matches."
            if detection_method == "directory name":
                message += f" (repository name inferred from {detection_method})"

            return FindCurrentSourceIdResult(
                repository_name=repository_name,
                message=message,
                suggestion="Review the candidates below and determine which source best matches the current repository based on the name and URL.",
                candidates=[
                    SourceCandidate(
                        id=source.get("id", -1),
                        url=source.get("url"),
                        name=source.get("full_name") or source.get("name"),
                        monitored=source.get("monitored"),
                        deleted_at=source.get("deleted_at"),
                    )
                    for source in source_result
                ],
            )

        # No matches found at all
        else:
            # Try searching with just the repo name (without org) as fallback
            if "/" in repository_name:
                repo_only = repository_name.split("/")[-1]
                logger.debug(f"Trying fallback search with repo name only: {repo_only}")
                fallback_result = await client.get_source_by_name(repo_only, return_all_on_no_match=True)

                # Handle fallback results
                if isinstance(fallback_result, dict):
                    fallback_source_id: str | int | None = fallback_result.get("id")
                    logger.info(f"Found match using repo name only, source_id: {fallback_source_id}")

                    message = f"Found match using repository name '{repo_only}' (without organization prefix)"
                    if detection_method == "directory name":
                        message += f" (repository name inferred from {detection_method})"

                    return FindCurrentSourceIdResult(
                        repository_name=repository_name,
                        source_id=fallback_source_id if fallback_source_id is not None else "",
                        source=fallback_result,
                        message=message,
                    )
                elif isinstance(fallback_result, list) and len(fallback_result) > 0:
                    logger.info(f"Found {len(fallback_result)} candidates using repo name only")

                    message = f"No exact match for '{repository_name}', but found {len(fallback_result)} potential matches using repo name '{repo_only}'."
                    if detection_method == "directory name":
                        message += f" (repository name inferred from {detection_method})"

                    return FindCurrentSourceIdResult(
                        repository_name=repository_name,
                        message=message,
                        suggestion="Review the candidates below and determine which source best matches the current repository.",
                        candidates=[
                            SourceCandidate(
                                id=source.get("id", -1),
                                url=source.get("url"),
                                name=source.get("full_name") or source.get("name"),
                                monitored=source.get("monitored"),
                                deleted_at=source.get("deleted_at"),
                            )
                            for source in fallback_result
                            if source.get("id") is not None
                        ],
                    )

            # Absolutely no matches found
            logger.warning(f"No sources found for repository: {repository_name}")

            message = "The repository may not be connected to GitGuardian, or you may not have access to it."
            if detection_method == "directory name":
                message += f" Note: repository name was inferred from {detection_method}, which may not match the actual GitGuardian source name."

            return FindCurrentSourceIdError(
                repository_name=repository_name,
                error=f"Repository '{repository_name}' not found in GitGuardian",
                message=message,
                suggestion="Check that the repository is properly connected to GitGuardian and that your account has access to it.",
            )

    except Exception as e:
        logger.exception(f"Error finding source_id: {str(e)}")
        return FindCurrentSourceIdError(error=f"Failed to find source_id: {str(e)}")
