import json
import logging
import os
import re
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

import httpx

# Setup logger
logger = logging.getLogger(__name__)


class IncidentSeverity(str, Enum):
    """Enum for incident severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class IncidentStatus(str, Enum):
    """Enum for incident statuses."""

    VALID = "valid"
    INVALID = "invalid"
    IGNORED = "IGNORED"
    FIXED = "fixed"
    TRIGGERED = "TRIGGERED"
    ASSIGNED = "ASSIGNED"
    RESOLVED = "RESOLVED"


class IncidentValidity(str, Enum):
    """Enum for incident validity values."""

    VALID = "valid"
    INVALID = "invalid"
    FAILED_TO_CHECK = "failed_to_check"
    NO_CHECKER = "no_checker"
    UNKNOWN = "unknown"


class GitGuardianClient:
    """Client for interacting with the GitGuardian API."""

    def __init__(self, api_key: str | None = None, api_url: str | None = None):
        """Initialize the GitGuardian client.

        Args:
            api_key: GitGuardian API key, defaults to GITGUARDIAN_API_KEY env var
            api_url: GitGuardian API URL, defaults to GITGUARDIAN_API_URL env var or https://api.gitguardian.com/v1
        """
        logger.info("Initializing GitGuardian client")

        # Use provided API key or get from environment
        self.api_key = api_key or os.environ.get("GITGUARDIAN_API_KEY")

        # Log API key status (without exposing the actual key)
        if self.api_key:
            logger.info("API key found")
            # Only show first 4 chars for logging
            key_preview = self.api_key[:4] + "..." if len(self.api_key) > 4 else "***"
            logger.debug(f"Using API key starting with: {key_preview}")
        else:
            logger.error("GitGuardian API key is missing - not found in parameters or environment variables")
            raise ValueError("GitGuardian API key is required")

        # Use provided API URL or get from environment with default fallback
        self.api_url = api_url or os.environ.get("GITGUARDIAN_API_URL", "https://api.gitguardian.com/v1")
        logger.info(f"Using API URL: {self.api_url}")

        logger.info("GitGuardian client initialized successfully")

    async def _request(
        self, method: str, endpoint: str, return_headers: bool = False, **kwargs
    ) -> Union[Dict[str, Any], Tuple[Dict[str, Any], Dict[str, Any]]]:
        """Make a request to the GitGuardian API.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            return_headers: Whether to return headers along with data
            **kwargs: Additional arguments to pass to requests

        Returns:
            Response data as dictionary, or tuple of (data, headers) if return_headers=True

        Raises:
            requests.HTTPError: If the API returns an error
        """
        url = f"{self.api_url}/{endpoint.lstrip('/')}"
        logger.debug(f"Making {method} request to {url}")

        headers = {
            "Authorization": f"Token {self.api_key}",
            "Content-Type": "application/json",
        }
        headers.update(kwargs.pop("headers", {}))

        try:
            async with httpx.AsyncClient() as client:
                logger.debug(f"Sending request with payload: {kwargs.get('json', {})}")
                response = await client.request(method, url, headers=headers, **kwargs)

            # Log detailed response information
            logger.debug(f"Response status code: {response.status_code}")
            logger.debug(f"Response headers: {dict(response.headers)}")

            # Log response content if present
            if response.content:
                try:
                    logger.debug(f"Response content: {response.content.decode()}")
                except UnicodeDecodeError:
                    logger.debug("Response content could not be decoded as UTF-8")

            response.raise_for_status()

            if response.status_code == 204:  # No content
                logger.debug("Received 204 No Content response")
                return ({}, response.headers) if return_headers else {}

            try:
                if not response.content or response.content.strip() == b"":
                    logger.debug("Received empty response content")
                    return ({}, response.headers) if return_headers else {}

                data = response.json()

                # Handle empty array responses properly
                if data == [] and return_headers:
                    logger.debug("Received empty array response")
                    return ([], response.headers)

                logger.debug(f"Parsed JSON response: {json.dumps(data, indent=2)}")
                return (data, response.headers) if return_headers else data
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON response: {str(e)}")
                logger.error(f"Raw response content: {response.content}")
                raise

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error occurred: {e.response.status_code} - {e.response.text}")
            raise
        except httpx.RequestError as e:
            logger.error(f"Request error occurred: {str(e)}")
            raise
        except Exception as e:
            logger.exception(f"Unexpected error during API request: {str(e)}")
            raise

    def _extract_next_cursor(self, headers: Dict[str, str]) -> Optional[str]:
        """Extract the next cursor from the Link header.

        Args:
            headers: Response headers containing Link header

        Returns:
            Next cursor if available, None otherwise
        """
        link_header = headers.get("link")
        if not link_header:
            return None

        # Extract the URL from the link header
        next_url_match = re.search(r'<([^>]+)>;\s*rel="next"', link_header)
        if not next_url_match:
            return None

        next_url = next_url_match.group(1)

        # Extract cursor from the URL
        cursor_match = re.search(r"cursor=([^&]+)", next_url)
        if not cursor_match:
            return None

        return cursor_match.group(1)

    async def paginate_all(self, endpoint: str, params: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Fetch all pages of results using cursor-based pagination.

        Args:
            endpoint: API endpoint path
            params: Query parameters to include in the request

        Returns:
            List of all items from all pages
        """
        params = params or {}
        all_items = []
        cursor = None

        while True:
            # If we have a cursor, add it to params
            if cursor:
                params["cursor"] = cursor

            # Build query string
            query_string = "&".join([f"{k}={v}" for k, v in params.items()]) if params else ""
            full_endpoint = f"{endpoint}?{query_string}" if query_string else endpoint

            # Make request with headers
            data, headers = await self._request("GET", full_endpoint, return_headers=True)

            # Handle empty responses or empty arrays
            if not data:
                logger.debug("Received empty response data, stopping pagination")
                break

            # Add items to our collection
            if isinstance(data, dict) and "results" in data:
                items = data.get("results", [])
            elif isinstance(data, list):
                items = data
            else:
                items = []

            all_items.extend(items)

            # Check for next cursor
            cursor = self._extract_next_cursor(headers)
            if not cursor:
                break

        return all_items

    async def create_honeytoken(
        self, name: str, description: str = "", custom_tags: list | None = None
    ) -> dict[str, Any]:
        """Create a new honeytoken in GitGuardian.

        Args:
            name: Name of the honeytoken
            description: Description of the honeytoken
            custom_tags: List of custom tags to apply to the honeytoken

        Returns:
            Honeytoken data
        """
        logger.info(f"Creating honeytoken: {name}")
        data = {"name": name, "description": description, "type": "AWS", "custom_tags": custom_tags or []}

        return await self._request("POST", "/honeytokens", json=data)

    async def create_honeytoken_with_context(
        self,
        name: str,
        description: str = "",
        custom_tags: list | None = None,
        language: str | None = None,
        filename: str | None = None,
        project_extensions: str | None = None,
    ) -> dict[str, Any]:
        """Create a honeytoken with context for smart injection into code.

        Args:
            name: Name of the honeytoken
            description: Description of the honeytoken
            custom_tags: List of custom tags to apply to the honeytoken
            language: Programming language for context
            filename: Suggested filename
            project_extensions: Comma-separated string of file extensions in the project (e.g. 'py,yml,json')

        Returns:
            Honeytoken context data including content, filepath, and honeytoken_id
        """
        logger.info(f"Creating honeytoken with context: {name}")
        logger.debug(f"Context: language={language}, filename={filename}, extensions={project_extensions}")

        data = {"name": name, "description": description, "type": "AWS", "custom_tags": custom_tags or []}

        if language:
            data["language"] = language
        if filename:
            data["filename"] = filename
        if project_extensions:
            data["project_extensions"] = project_extensions

        return await self._request("POST", "/honeytokens/with-context", json=data)

    async def get_honeytoken(self, honeytoken_id: str, show_token: bool = True) -> dict[str, Any]:
        """Get details for a specific honeytoken.

        Args:
            honeytoken_id: ID of the honeytoken
            show_token: Whether to include token details

        Returns:
            Honeytoken data
        """
        logger.info(f"Getting honeytoken details for ID: {honeytoken_id}")
        return await self._request("GET", f"/honeytokens/{honeytoken_id}?show_token={str(show_token).lower()}")

    async def list_incidents(
        self,
        severity: IncidentSeverity | str | None = None,
        status: IncidentStatus | str | None = None,
        from_date: str | None = None,
        to_date: str | None = None,
        assignee_email: str | None = None,
        assignee_id: str | None = None,
        validity: IncidentValidity | str | None = None,
        per_page: int = 20,
        cursor: str | None = None,
        ordering: str | None = None,
        get_all: bool = False,
    ) -> dict[str, Any]:
        """List secrets incidents with optional filtering and cursor-based pagination.

        Args:
            severity: Filter by severity level (IncidentSeverity enum or string: critical, high, medium, low)
            status: Filter by status (IncidentStatus enum or string: IGNORED, TRIGGERED, ASSIGNED, RESOLVED)
            from_date: Filter incidents created after this date (ISO format: YYYY-MM-DD)
            to_date: Filter incidents created before this date (ISO format: YYYY-MM-DD)
            assignee_email: Filter incidents assigned to a specific email address
            assignee_id: Filter incidents assigned to a specific member ID
            validity: Filter by validity status (IncidentValidity enum or string: valid, invalid, failed_to_check, no_checker, unknown)
            per_page: Number of results per page (default: 20)
            cursor: Pagination cursor (for cursor-based pagination)
            ordering: Sort field (Enum: date, -date, resolved_at, -resolved_at, ignored_at, -ignored_at)
                     Default is ASC, DESC if preceded by '-'
            get_all: If True, fetch all results using cursor-based pagination

        Returns:
            List of incidents matching the criteria or an empty dict/list if no results
        """
        logger.info(
            f"Listing incidents with filters: severity={severity}, status={status}, assignee_email={assignee_email}, assignee_id={assignee_id}, validity={validity}, ordering={ordering}"
        )

        # Build query parameters
        params = {}

        # Process severity parameter
        if severity:
            # If it's already an enum, use its value
            if isinstance(severity, IncidentSeverity):
                params["severity"] = severity.value
            # If it's a string, validate and convert
            elif isinstance(severity, str):
                try:
                    # Convert to enum to validate, then get the value
                    params["severity"] = IncidentSeverity(severity.lower()).value
                except ValueError:
                    valid_values = [e.value for e in IncidentSeverity]
                    logger.warning(f"Invalid severity value: {severity}. Must be one of {valid_values}")
                    raise ValueError(f"Invalid severity value: {severity}. Must be one of {valid_values}")
            else:
                raise TypeError("severity must be a string or IncidentSeverity enum")

        # Process status parameter
        if status:
            # If it's already an enum, use its value
            if isinstance(status, IncidentStatus):
                params["status"] = status.value
            # If it's a string, validate and convert
            elif isinstance(status, str):
                try:
                    # For status, we need to check if it's uppercase already
                    if status in [e.value for e in IncidentStatus]:
                        params["status"] = status
                    else:
                        # Try with uppercase for compatibility
                        params["status"] = IncidentStatus(status.upper()).value
                except ValueError:
                    valid_values = [e.value for e in IncidentStatus]
                    logger.warning(f"Invalid status value: {status}. Must be one of {valid_values}")
                    raise ValueError(f"Invalid status value: {status}. Must be one of {valid_values}")
            else:
                raise TypeError("status must be a string or IncidentStatus enum")

        # Process validity parameter
        if validity:
            # If it's already an enum, use its value
            if isinstance(validity, IncidentValidity):
                params["validity"] = validity.value
            # If it's a string, validate and convert
            elif isinstance(validity, str):
                try:
                    # Convert to enum to validate, then get the value
                    params["validity"] = IncidentValidity(validity.lower()).value
                except ValueError:
                    valid_values = [e.value for e in IncidentValidity]
                    logger.warning(f"Invalid validity value: {validity}. Must be one of {valid_values}")
                    raise ValueError(f"Invalid validity value: {validity}. Must be one of {valid_values}")
            else:
                raise TypeError("validity must be a string or IncidentValidity enum")

        # Add other parameters
        if from_date:
            params["from_date"] = from_date
        if to_date:
            params["to_date"] = to_date
        if assignee_email:
            params["assignee_email"] = assignee_email
        if assignee_id:
            params["assignee_id"] = assignee_id
        if per_page:
            params["per_page"] = str(per_page)
        if cursor:
            params["cursor"] = cursor
        if ordering:
            params["ordering"] = ordering

        endpoint = "/incidents/secrets"

        if get_all:
            return await self.paginate_all(endpoint, params)

        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        if query_string:
            endpoint = f"{endpoint}?{query_string}"

        return await self._request("GET", endpoint)

    async def get_incident(self, incident_id: str) -> dict[str, Any]:
        """Get detailed information about a specific incident.

        Args:
            incident_id: ID of the incident to retrieve

        Returns:
            Detailed incident data
        """
        logger.info(f"Getting details for incident ID: {incident_id}")
        return await self._request("GET", f"/incidents/secrets/{incident_id}")

    async def update_incident(self, incident_id: str, status: str = None, custom_tags: list = None) -> dict[str, Any]:
        """Update a secret incident.

        Args:
            incident_id: ID of the incident
            status: New status (e.g., "IGNORED", "TRIGGERED", "ASSIGNED", "RESOLVED")
            custom_tags: List of custom tags to apply to the incident
                         Format: [{"key": "key1", "value": "value1"}, {"key": "key2", "value": "value2"}]

        Returns:
            Updated incident data
        """
        logger.info(f"Updating incident {incident_id} with status={status}, custom_tags={custom_tags}")

        payload = {}
        if status:
            payload["status"] = status
        if custom_tags:
            payload["custom_tags"] = custom_tags

        if not payload:
            raise ValueError("At least one of status or custom_tags must be provided")

        return await self._request("PATCH", f"/incidents/secrets/{incident_id}", json=payload)

    async def list_honeytokens(
        self,
        status: str | None = None,
        search: str | None = None,
        ordering: str | None = None,
        show_token: bool = False,
        creator_id: str | None = None,
        creator_api_token_id: str | None = None,
        per_page: int = 20,
        cursor: str | None = None,
        get_all: bool = False,
    ) -> dict[str, Any]:
        """List all honeytokens with optional filtering and cursor-based pagination.

        Args:
            status: Filter by status (ACTIVE or REVOKED)
            search: Search string to filter results
            ordering: Sort field (e.g., 'name', '-name', 'created_at', '-created_at')
            show_token: Whether to include token details in the response
            creator_id: Filter by creator ID
            creator_api_token_id: Filter by creator API token ID
            per_page: Number of results per page (default: 20)
            cursor: Pagination cursor (for cursor-based pagination)
            get_all: If True, fetch all results using cursor-based pagination

        Returns:
            List of honeytokens matching the criteria or an empty dict/list if no results
        """
        logger.info(
            f"Listing honeytokens with filters: status={status}, search={search}, ordering={ordering}, creator_id={creator_id}, creator_api_token_id={creator_api_token_id}"
        )

        # Build query parameters
        params = {}
        if status:
            params["status"] = status
        if search:
            params["search"] = search
        if ordering:
            params["ordering"] = ordering
        if show_token is not None:
            params["show_token"] = str(show_token).lower()
        if creator_id:
            params["creator_id"] = creator_id
        if creator_api_token_id:
            params["creator_api_token_id"] = creator_api_token_id
        if per_page:
            params["per_page"] = str(per_page)
        if cursor:
            params["cursor"] = cursor

        endpoint = "/honeytokens"

        if get_all:
            return await self.paginate_all(endpoint, params)

        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        if query_string:
            endpoint = f"{endpoint}?{query_string}"

        return await self._request("GET", endpoint)

    async def revoke_honeytoken(self, honeytoken_id: str) -> dict[str, Any]:
        """Revoke a honeytoken.

        Args:
            honeytoken_id: ID of the honeytoken

        Returns:
            Result of the operation
        """
        logger.info(f"Revoking honeytoken: {honeytoken_id}")
        return await self._request("POST", f"/honeytokens/{honeytoken_id}/revoke")

    async def get_current_token_info(self) -> dict[str, Any]:
        """Get information about the current API token.

        This endpoint retrieves details about the API token being used,
        including its name, creation date, expiration, and scopes.

        Returns:
            Dictionary containing token information including scopes
        """
        logger.info("Getting current API token information")
        return await self._request("GET", "/api_tokens/self")

    async def list_api_tokens(self) -> dict[str, Any]:
        """List all API tokens for the account.

        Returns:
            List of API tokens
        """
        logger.info("Listing API tokens")
        return await self._request("GET", "/api_tokens")

    async def multiple_scan(self, documents: list[dict[str, str]]) -> dict[str, Any]:
        """Scan multiple documents for secrets and policy breaks.

        Args:
            documents: List of documents to scan, each with 'content' and optional 'filename'
                      Format: [{'document': 'file content', 'filename': 'optional_filename.txt'}, ...]

        Returns:
            Scan results for all documents
        """
        logger.info(f"Scanning {len(documents)} documents for secrets")

        # Validate input format
        for i, doc in enumerate(documents):
            if "document" not in doc:
                raise ValueError(f"Document at index {i} is missing required 'document' field")

        return await self._request("POST", "/multiscan", json=documents)

    async def get_audit_logs(self, limit: int = 100) -> dict[str, Any]:
        """Get audit logs for the organization.

        Args:
            limit: Maximum number of logs to return

        Returns:
            List of audit log entries
        """
        logger.info(f"Getting audit logs (limit: {limit})")
        return await self._request("GET", f"/audit_logs?per_page={limit}")

    async def list_custom_tags(self) -> dict[str, Any]:
        """List all custom tags.

        Returns:
            List of custom tags
        """
        logger.info("Listing custom tags")
        return await self._request("GET", "/custom-tags")

    async def create_custom_tag(self, key: str, value: str) -> dict[str, Any]:
        """Create a custom tag.

        Args:
            key: Tag key
            value: Tag value

        Returns:
            Created custom tag data
        """
        logger.info(f"Creating custom tag with key={key}, value={value}")
        return await self._request("POST", "/custom-tags", json={"key": key, "value": value})

    async def update_custom_tag(self, tag_id: str, key: str = None, value: str = None) -> dict[str, Any]:
        """Update a custom tag.

        Args:
            tag_id: ID of the custom tag to update
            key: New tag key (optional)
            value: New tag value (optional)

        Returns:
            Updated custom tag data
        """
        logger.info(f"Updating custom tag {tag_id} with key={key}, value={value}")

        payload = {}
        if key is not None:
            payload["key"] = key
        if value is not None:
            payload["value"] = value

        if not payload:
            raise ValueError("At least one of key or value must be provided")

        return await self._request("PATCH", f"/custom-tags/{tag_id}", json=payload)

    async def delete_custom_tag(self, tag_id: str) -> dict[str, Any]:
        """Delete a custom tag.

        Args:
            tag_id: ID of the custom tag to delete

        Returns:
            Empty dict on success
        """
        logger.info(f"Deleting custom tag {tag_id}")
        return await self._request("DELETE", f"/custom-tags/{tag_id}")

    async def get_custom_tag(self, tag_id: str) -> dict[str, Any]:
        """Get a specific custom tag by ID.

        Args:
            tag_id: ID of the custom tag to retrieve

        Returns:
            Custom tag data
        """
        logger.info(f"Getting custom tag {tag_id}")
        return await self._request("GET", f"/custom-tags/{tag_id}")

    async def list_teams(self, search: str | None = None) -> dict[str, Any]:
        """List teams with optional search filtering.

        Args:
            search: Optional search term to filter teams by name

        Returns:
            List of teams matching the search criteria
        """
        logger.info(f"Listing teams with search filter: {search}")

        endpoint = "/teams"
        if search:
            endpoint = f"{endpoint}?search={search}"

        return await self._request("GET", endpoint)

    async def list_members(self, search: str | None = None) -> dict[str, Any]:
        """List all members with optional search filtering.

        Args:
            search: Optional search term to filter members by name or email

        Returns:
            List of members matching the search criteria
        """
        logger.info(f"Listing members with search filter: {search}")

        endpoint = "/members"
        if search:
            endpoint = f"{endpoint}?search={search}"

        return await self._request("GET", endpoint)

    async def add_member_to_team(self, team_id: str, member_id: str) -> dict[str, Any]:
        """Add a member to a team.

        Args:
            team_id: ID of the team to add the member to
            member_id: ID of the member to add to the team

        Returns:
            Status of the operation
        """
        logger.info(f"Adding member {member_id} to team {team_id}")

        endpoint = f"/teams/{team_id}/team_memberships"
        payload = {"member_id": member_id}
        return await self._request("POST", endpoint, json=payload)

    # Secret Incident management endpoints
    async def assign_incident(self, incident_id: str, assignee_id: str) -> dict[str, Any]:
        """Assign a secret incident to a member.

        Args:
            incident_id: ID of the secret incident
            assignee_id: ID of the member to assign the incident to

        Returns:
            Status of the operation
        """
        logger.info(f"Assigning incident {incident_id} to member {assignee_id}")
        return await self._request("POST", f"/incidents/secrets/{incident_id}/assign", json={"member_id": assignee_id})

    async def unassign_incident(self, incident_id: str) -> dict[str, Any]:
        """Unassign a secret incident.

        Args:
            incident_id: ID of the secret incident

        Returns:
            Status of the operation
        """
        logger.info(f"Unassigning incident {incident_id}")
        return await self._request("POST", f"/incidents/secrets/{incident_id}/unassign")

    async def resolve_incident(self, incident_id: str) -> dict[str, Any]:
        """Resolve a secret incident.

        Args:
            incident_id: ID of the secret incident

        Returns:
            Status of the operation
        """
        logger.info(f"Resolving incident {incident_id}")
        return await self._request("POST", f"/incidents/secrets/{incident_id}/resolve")

    async def ignore_incident(self, incident_id: str, ignore_reason: str = None) -> dict[str, Any]:
        """Ignore a secret incident.

        Args:
            incident_id: ID of the secret incident
            ignore_reason: Reason for ignoring (test_credential, false_positive, etc.)

        Returns:
            Status of the operation
        """
        logger.info(f"Ignoring incident {incident_id} with reason: {ignore_reason}")
        payload = {}
        if ignore_reason:
            payload["ignore_reason"] = ignore_reason
        return await self._request("POST", f"/incidents/secrets/{incident_id}/ignore", json=payload)

    async def reopen_incident(self, incident_id: str) -> dict[str, Any]:
        """Reopen a secret incident.

        Args:
            incident_id: ID of the secret incident

        Returns:
            Status of the operation
        """
        logger.info(f"Reopening incident {incident_id}")
        return await self._request("POST", f"/incidents/secrets/{incident_id}/reopen")

    async def share_incident(self, incident_id: str) -> dict[str, Any]:
        """Share a secret incident (create a share link).

        Args:
            incident_id: ID of the secret incident

        Returns:
            Share information including share URL
        """
        logger.info(f"Creating share link for incident {incident_id}")
        return await self._request("POST", f"/incidents/secrets/{incident_id}/share")

    async def unshare_incident(self, incident_id: str) -> dict[str, Any]:
        """Unshare a secret incident (remove share link).

        Args:
            incident_id: ID of the secret incident

        Returns:
            Status of the operation
        """
        logger.info(f"Removing share link for incident {incident_id}")
        return await self._request("POST", f"/incidents/secrets/{incident_id}/unshare")

    async def grant_incident_access(
        self, incident_id: str, member_id: str = None, team_id: str = None
    ) -> dict[str, Any]:
        """Grant access to a secret incident to a member or team.

        Args:
            incident_id: ID of the secret incident
            member_id: ID of the member to grant access to (either member_id or team_id must be provided)
            team_id: ID of the team to grant access to (either member_id or team_id must be provided)

        Returns:
            Status of the operation
        """
        if not member_id and not team_id:
            raise ValueError("Either member_id or team_id must be provided")

        if member_id and team_id:
            raise ValueError("Only one of member_id or team_id should be provided")

        payload = {}
        if member_id:
            logger.info(f"Granting access to incident {incident_id} for member {member_id}")
            payload["member_id"] = member_id
        else:
            logger.info(f"Granting access to incident {incident_id} for team {team_id}")
            payload["team_id"] = team_id

        return await self._request("POST", f"/incidents/secrets/{incident_id}/grant_access", json=payload)

    async def revoke_incident_access(
        self, incident_id: str, member_id: str = None, team_id: str = None
    ) -> dict[str, Any]:
        """Revoke access to a secret incident from a member or team.

        Args:
            incident_id: ID of the secret incident
            member_id: ID of the member to revoke access from (either member_id or team_id must be provided)
            team_id: ID of the team to revoke access from (either member_id or team_id must be provided)

        Returns:
            Status of the operation
        """
        if not member_id and not team_id:
            raise ValueError("Either member_id or team_id must be provided")

        if member_id and team_id:
            raise ValueError("Only one of member_id or team_id should be provided")

        payload = {}
        if member_id:
            logger.info(f"Revoking access to incident {incident_id} from member {member_id}")
            payload["member_id"] = member_id
        else:
            logger.info(f"Revoking access to incident {incident_id} from team {team_id}")
            payload["team_id"] = team_id

        return await self._request("POST", f"/incidents/secrets/{incident_id}/revoke_access", json=payload)

    async def list_incident_members(self, incident_id: str) -> dict[str, Any]:
        """List members having access to a secret incident.

        Args:
            incident_id: ID of the secret incident

        Returns:
            List of members with access to the incident
        """
        logger.info(f"Listing members with access to incident {incident_id}")
        return await self._request("GET", f"/incidents/secrets/{incident_id}/members")

    async def list_incident_teams(self, incident_id: str) -> dict[str, Any]:
        """List teams having access to a secret incident.

        Args:
            incident_id: ID of the secret incident

        Returns:
            List of teams with access to the incident
        """
        logger.info(f"Listing teams with access to incident {incident_id}")
        return await self._request("GET", f"/incidents/secrets/{incident_id}/teams")

    async def get_incident_impacted_perimeter(self, incident_id: str) -> dict[str, Any]:
        """Retrieve the impacted perimeter of a secret incident.

        Args:
            incident_id: ID of the secret incident

        Returns:
            Information about the impacted perimeter
        """
        logger.info(f"Getting impacted perimeter for incident {incident_id}")
        return await self._request("GET", f"/incidents/secrets/{incident_id}/perimeter")

    # Secret Incident Notes management
    async def list_incident_notes(self, incident_id: str) -> dict[str, Any]:
        """List notes on a secret incident.

        Args:
            incident_id: ID of the secret incident

        Returns:
            List of notes attached to the incident
        """
        logger.info(f"Listing notes for incident {incident_id}")
        return await self._request("GET", f"/incidents/secrets/{incident_id}/notes")

    async def create_incident_note(self, incident_id: str, content: str) -> dict[str, Any]:
        """Create a note on a secret incident.

        Args:
            incident_id: ID of the secret incident
            content: Content of the note

        Returns:
            Created note details
        """
        logger.info(f"Creating note for incident {incident_id}")
        return await self._request("POST", f"/incidents/secrets/{incident_id}/notes", json={"content": content})

    async def update_incident_note(self, incident_id: str, note_id: str, content: str) -> dict[str, Any]:
        """Update a note on a secret incident.

        Args:
            incident_id: ID of the secret incident
            note_id: ID of the note to update
            content: New content for the note

        Returns:
            Updated note details
        """
        logger.info(f"Updating note {note_id} for incident {incident_id}")
        return await self._request(
            "PATCH", f"/incidents/secrets/{incident_id}/notes/{note_id}", json={"content": content}
        )

    async def delete_incident_note(self, incident_id: str, note_id: str) -> dict[str, Any]:
        """Delete a note from a secret incident.

        Args:
            incident_id: ID of the secret incident
            note_id: ID of the note to delete

        Returns:
            Status of the operation
        """
        logger.info(f"Deleting note {note_id} from incident {incident_id}")
        return await self._request("DELETE", f"/incidents/secrets/{incident_id}/notes/{note_id}")

    # Secret Occurrences management
    async def list_secret_occurrences(self, incident_id: str) -> dict[str, Any]:
        """List secret occurrences for an incident.

        Args:
            incident_id: ID of the secret incident

        Returns:
            List of secret occurrences
        """
        logger.info(f"Listing occurrences for incident {incident_id}")
        return await self._request("GET", f"/incidents/secrets/{incident_id}/occurrences")

    # Additional incident list methods
    async def list_source_incidents(self, source_id: str, **kwargs) -> dict[str, Any]:
        """List secret incidents of a source.

        Args:
            source_id: ID of the source
            **kwargs: Additional filtering parameters

        Returns:
            List of incidents for the source
        """
        logger.info(f"Listing incidents for source {source_id}")

        # Convert kwargs to query parameters
        query_params = "&".join([f"{k}={v}" for k, v in kwargs.items()])
        endpoint = f"/sources/{source_id}/secret-incidents"
        if query_params:
            endpoint = f"{endpoint}?{query_params}"

        return await self._request("GET", endpoint)

    async def list_team_incidents(self, team_id: str, **kwargs) -> dict[str, Any]:
        """List secret incidents of a team.

        Args:
            team_id: ID of the team
            **kwargs: Additional filtering parameters

        Returns:
            List of incidents for the team
        """
        logger.info(f"Listing incidents for team {team_id}")

        # Convert kwargs to query parameters
        query_params = "&".join([f"{k}={v}" for k, v in kwargs.items()])
        endpoint = f"/teams/{team_id}/secret-incidents"
        if query_params:
            endpoint = f"{endpoint}?{query_params}"

        return await self._request("GET", endpoint)

    async def list_member_incidents(self, member_id: str, **kwargs) -> dict[str, Any]:
        """List secret incidents a member has access to.

        Args:
            member_id: ID of the member
            **kwargs: Additional filtering parameters

        Returns:
            List of incidents the member has access to
        """
        logger.info(f"Listing incidents for member {member_id}")

        # Convert kwargs to query parameters
        query_params = "&".join([f"{k}={v}" for k, v in kwargs.items()])
        endpoint = f"/members/{member_id}/secret-incidents"
        if query_params:
            endpoint = f"{endpoint}?{query_params}"

        return await self._request("GET", endpoint)
