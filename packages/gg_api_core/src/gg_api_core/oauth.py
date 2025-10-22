"""OAuth authentication implementation for GitGuardian API using MCP SDK."""

import datetime
import json
import logging
import os
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel, ConfigDict, Field

from mcp.client.auth import TokenStorage
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

# Configure logger
logger = logging.getLogger(__name__)

# Port range for callback server
CALLBACK_PORT_RANGE = (8000, 8999)

# Default token expiry in days (if not specified in token info)
DEFAULT_TOKEN_EXPIRY_DAYS = 30

# Global counter for OAuth client instances (debugging)
_oauth_client_counter = 0


class StoredOAuthToken(BaseModel):
    """Pydantic model representing a single stored OAuth token.

    This model describes the format of token data stored in FileTokenStorage
    for a specific account.

    Attributes:
        access_token: The OAuth access token string used for API authentication.
        expires_at: ISO format datetime string indicating when the token expires.
                   Examples: "2025-10-28T11:15:58.656719+00:00"
                   Can be None if token never expires.
        token_name: Human-readable name for the token (e.g., "SecOps MCP Token").
        scopes: List of OAuth scopes granted to this token
               (e.g., ["scan", "incidents:read", "honeytokens:read"]).
        account_id: The GitGuardian account ID this token belongs to.
                   Can be an integer or "unknown" for legacy tokens.
    """

    access_token: str = Field(..., description="OAuth access token for API authentication")
    expires_at: Optional[str] = Field(None, description="ISO format expiration datetime or None if never expires")
    token_name: str = Field(..., description="Human-readable name for the token")
    scopes: list[str] = Field(default_factory=list, description="List of OAuth scopes for this token")
    account_id: Optional[str | int] = Field(None, description="GitGuardian account ID (int) or 'unknown'")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "ghp_1234567890abcdef",
                "expires_at": "2025-10-28T11:15:58.656719+00:00",
                "token_name": "SecOps MCP Token",
                "scopes": ["scan", "incidents:read", "honeytokens:read"],
                "account_id": 123,
            }
        }
    )


class FileTokenStorage:
    """File-based storage for OAuth tokens to enable token reuse with multi-account support.

    Token Storage Structure:
        The token file stores tokens nested by instance URL and account ID:
        {
            "instance_url": {
                "account_id": StoredOAuthToken
            }
        }

        Example:
        {
            "https://dashboard.gitguardian.com": {
                "123": {
                    "access_token": "...",
                    "expires_at": "2025-10-28T11:15:58.656719+00:00",
                    "token_name": "Production Account",
                    "scopes": ["scan", "incidents:read"],
                    "account_id": 123
                },
                "456": {
                    "access_token": "...",
                    "expires_at": "2025-10-28T11:15:58.656719+00:00",
                    "token_name": "Staging Account",
                    "scopes": ["scan"],
                    "account_id": 456
                }
            },
            "https://self-hosted.example.com": {
                "789": {
                    "access_token": "...",
                    "expires_at": "2025-10-28T11:15:58.656719+00:00",
                    "token_name": "Self-Hosted",
                    "scopes": ["scan", "incidents:read"],
                    "account_id": 789
                }
            }
        }
    """

    def __init__(self, token_file=None):
        """Initialize the token storage.

        Args:
            token_file: Path to the token file. If None, uses system-appropriate directory
                following XDG spec on Linux and Application Support on macOS
        """
        if token_file is None:
            # Determine platform-appropriate config directory
            import os
            import platform

            system = platform.system()
            home_dir = Path.home()

            if system == "Darwin":  # macOS
                # Use macOS standard directory conventions
                app_support_dir = home_dir / "Library" / "Application Support"
                gitguardian_dir = app_support_dir / "GitGuardian"
            else:  # Linux and other Unix-like systems - follow XDG spec
                # Use XDG_CONFIG_HOME if defined, otherwise ~/.config
                xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
                if xdg_config_home:
                    config_dir = Path(xdg_config_home)
                else:
                    config_dir = home_dir / ".config"
                gitguardian_dir = config_dir / "gitguardian"

            gitguardian_dir.mkdir(exist_ok=True, parents=True)
            self.token_file = gitguardian_dir / "mcp_oauth_tokens.json"
        else:
            self.token_file = Path(token_file)
            # Ensure parent directory exists
            self.token_file.parent.mkdir(exist_ok=True, parents=True)

    def load_tokens(self):
        """Load tokens from the token file."""
        try:
            if self.token_file.exists():
                with open(self.token_file, "r") as f:
                    tokens = json.load(f)
                    # Migrate old format to new format if needed
                    return self._migrate_token_format(tokens)
        except Exception as e:
            logger.warning(f"Failed to load tokens from {self.token_file}: {e}")
        return {}

    def _migrate_token_format(self, tokens):
        """Migrate old token format to new multi-account format.

        Old format:
        {
          "https://dashboard.gitguardian.com": {
            "access_token": "...",
            "expires_at": "...",
            ...
          }
        }

        New format:
        {
          "https://dashboard.gitguardian.com": {
            "account_123": {
              "access_token": "...",
              "expires_at": "...",
              "account_id": 123,
              ...
            }
          }
        }
        """
        migrated = {}
        needs_migration = False

        for instance_url, data in tokens.items():
            # Check if this is old format (has access_token directly)
            if isinstance(data, dict) and "access_token" in data:
                # Old format - migrate to new format
                needs_migration = True
                account_id = data.get("account_id", "unknown")
                migrated[instance_url] = {
                    str(account_id): data
                }
                logger.info(f"Migrated token for {instance_url} to new multi-account format")
            elif isinstance(data, dict):
                # New format or nested structure - check if it's already properly nested
                # If all values are dicts with access_token, it's already new format
                is_new_format = all(
                    isinstance(v, dict) and "access_token" in v
                    for v in data.values()
                    if isinstance(v, dict)
                )
                if is_new_format:
                    migrated[instance_url] = data
                else:
                    # Ambiguous format, treat as old format for safety
                    needs_migration = True
                    account_id = data.get("account_id", "unknown")
                    migrated[instance_url] = {
                        str(account_id): data
                    }
            else:
                # Unknown format, keep as is
                migrated[instance_url] = data

        # Save migrated format back to file if migration occurred
        if needs_migration:
            try:
                with open(self.token_file, "w") as f:
                    json.dump(migrated, f, indent=2)
                self.token_file.chmod(0o600)
                logger.info(f"Saved migrated token format to {self.token_file}")
            except Exception as e:
                logger.warning(f"Failed to save migrated tokens: {e}")

        return migrated

    def save_token(self, instance_url, account_id, token_data):
        """Save a token for a specific instance URL and account.

        The token_data will be validated against the StoredOAuthToken model.

        Args:
            instance_url: The dashboard URL (e.g., https://dashboard.gitguardian.com)
            account_id: The account ID from the OAuth token response
            token_data: Token data dict including access_token, expires_at, token_name, scopes, account_id.
                       Will be validated against StoredOAuthToken model.

        Raises:
            ValueError: If token_data doesn't match StoredOAuthToken model schema
        """
        # Validate token data against Pydantic model
        try:
            StoredOAuthToken.model_validate(token_data)
        except Exception as e:
            logger.warning(f"Token data validation warning (non-blocking): {e}")
            # Log warning but don't fail - this maintains backward compatibility

        tokens = self.load_tokens()

        # Ensure instance_url exists in tokens
        if instance_url not in tokens:
            tokens[instance_url] = {}

        # Ensure the instance_url entry is a dict (for migrated formats)
        if not isinstance(tokens[instance_url], dict):
            tokens[instance_url] = {}

        # Store token nested by account_id
        tokens[instance_url][str(account_id)] = token_data

        try:
            with open(self.token_file, "w") as f:
                json.dump(tokens, f, indent=2)
            # Set file permissions to user-only read/write
            self.token_file.chmod(0o600)
            logger.info(f"Saved token for {instance_url} (account {account_id}) to {self.token_file}")
        except Exception as e:
            logger.warning(f"Failed to save token to {self.token_file}: {e}")

    def validate_token_data(self, token_data: dict) -> tuple[bool, str]:
        """Validate token data against StoredOAuthToken model.

        Args:
            token_data: Token data dictionary to validate

        Returns:
            Tuple of (is_valid, error_message). error_message is empty string if valid.
        """
        try:
            StoredOAuthToken.model_validate(token_data)
            return True, ""
        except Exception as e:
            return False, str(e)

    def get_schema(self) -> dict:
        """Get the JSON schema for StoredOAuthToken.

        Returns:
            Dict containing the Pydantic JSON schema for token validation
        """
        return StoredOAuthToken.model_json_schema()

    def get_token(self, instance_url, account_id=None):
        """Get a token for a specific instance URL and account if it exists and is not expired.

        Args:
            instance_url: The dashboard URL
            account_id: Optional account ID. If None, uses GITGUARDIAN_ACCOUNT_ID env var,
                       or returns the first available valid token

        Returns:
            Tuple of (access_token, full_token_data) or (None, None) if not found
        """
        tokens = self.load_tokens()
        instance_tokens = tokens.get(instance_url)

        if not instance_tokens:
            return None, None

        # Determine which account to use
        if account_id is None:
            # Check environment variable
            account_id = os.environ.get("GITGUARDIAN_ACCOUNT_ID")

        if account_id:
            # Try to get token for specific account
            token_data = instance_tokens.get(str(account_id))
            if token_data:
                # Check if token is expired
                if self._is_token_valid(token_data, instance_url, account_id):
                    return token_data.get("access_token"), token_data
                else:
                    return None, None
            else:
                logger.warning(f"No token found for account {account_id} at {instance_url}")
                return None, None
        else:
            # No specific account requested, return first valid token
            for acc_id, token_data in instance_tokens.items():
                if self._is_token_valid(token_data, instance_url, acc_id):
                    logger.info(f"Using token for account {acc_id} at {instance_url}")
                    return token_data.get("access_token"), token_data

            logger.info(f"No valid tokens found for {instance_url}")
            return None, None

    def _is_token_valid(self, token_data, instance_url, account_id):
        """Check if a token is valid (not expired)."""
        expires_at = token_data.get("expires_at")
        if expires_at:
            # Parse ISO format date
            try:
                expiry_date = datetime.datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                now = datetime.datetime.now(datetime.timezone.utc)
                if now >= expiry_date:
                    logger.debug(f"Token for {instance_url} (account {account_id}) has expired")
                    return False
            except Exception as e:
                logger.warning(f"Failed to parse expiry date: {e}")
                # If we can't parse the date, assume it's still valid

        return True

    def list_accounts(self, instance_url):
        """List all accounts with tokens for a specific instance URL.

        Args:
            instance_url: The dashboard URL

        Returns:
            List of dicts with account information
        """
        tokens = self.load_tokens()
        instance_tokens = tokens.get(instance_url, {})

        accounts = []
        for account_id, token_data in instance_tokens.items():
            is_valid = self._is_token_valid(token_data, instance_url, account_id)
            accounts.append({
                "account_id": account_id,
                "token_name": token_data.get("token_name"),
                "expires_at": token_data.get("expires_at"),
                "scopes": token_data.get("scopes", []),
                "is_valid": is_valid,
            })

        return accounts

    def delete_token(self, instance_url, account_id):
        """Delete a token for a specific instance URL and account.

        Args:
            instance_url: The dashboard URL
            account_id: The account ID
        """
        tokens = self.load_tokens()

        if instance_url in tokens and str(account_id) in tokens[instance_url]:
            del tokens[instance_url][str(account_id)]

            # Clean up empty instance entries
            if not tokens[instance_url]:
                del tokens[instance_url]

            try:
                with open(self.token_file, "w") as f:
                    json.dump(tokens, f, indent=2)
                self.token_file.chmod(0o600)
                logger.info(f"Deleted token for {instance_url} (account {account_id})")
            except Exception as e:
                logger.warning(f"Failed to delete token: {e}")


class InMemoryTokenStorage(TokenStorage):
    """Simple in-memory token storage implementation."""

    def __init__(self):
        self._tokens: Optional[OAuthToken] = None
        self._client_info: Optional[OAuthClientInformationFull] = None

    async def get_tokens(self) -> Optional[OAuthToken]:
        return self._tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self._tokens = tokens

    async def get_client_info(self) -> Optional[OAuthClientInformationFull]:
        return self._client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self._client_info = client_info


class CallbackHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler to capture OAuth callback."""

    def __init__(self, request, client_address, server, callback_data):
        """Initialize with callback data storage."""
        self.callback_data = callback_data
        super().__init__(request, client_address, server)

    def do_GET(self):
        """Handle GET request from OAuth redirect."""
        parsed = urlparse(self.path)
        query_params = parse_qs(parsed.query)

        if "code" in query_params:
            self.callback_data["authorization_code"] = query_params["code"][0]
            self.callback_data["state"] = query_params.get("state", [None])[0]
            # Get the dashboard URL from the callback data
            dashboard_url = self.callback_data.get("dashboard_url")
            use_dashboard_page = self.callback_data.get("use_dashboard_page", False)
            redirect_url = None
            if dashboard_url and use_dashboard_page:
                redirect_url = f"{dashboard_url}/authenticated"

            if redirect_url:
                self.send_response(302)
                self.send_header("Location", redirect_url)
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>MCP Server Authentication</title>
                    <style>
                        body {
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
                            background-color: #0d1b32;
                            color: white;
                            margin: 0;
                            padding: 0;
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            height: 100vh;
                            background-image: radial-gradient(circle, rgba(26, 54, 93, 0.3) 1px, transparent 1px);
                            background-size: 20px 20px;
                        }
                        .container {
                            background-color: #1e293b;
                            border-radius: 8px;
                            width: 90%;
                            max-width: 500px;
                            padding: 30px;
                            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                            text-align: center;
                        }
                        .logo {
                            margin-bottom: 20px;
                            width: 60px;
                            height: 60px;
                        }
                        h1 {
                            font-size: 28px;
                            margin-bottom: 20px;
                        }
                        p {
                            margin-bottom: 25px;
                            line-height: 1.5;
                        }
                        .success-box {
                            background-color: rgba(16, 185, 129, 0.1);
                            border-radius: 6px;
                            padding: 15px;
                            margin: 20px 0;
                            color: #10b981;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                        }
                        .success-box svg {
                            margin-right: 10px;
                        }
                        .success-message {
                            text-align: left;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>MCP Server Authentication</h1>
                        <p>You have successfully authenticated with your GitGuardian workspace.</p>
                        
                        <div class="success-box">
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                                <polyline points="22 4 12 14.01 9 11.01"></polyline>
                            </svg>
                            <div class="success-message">
                                Success, you can now close this tab and start using MCP Server!
                            </div>
                        </div>
                    </div>
                </body>
                </html>
                """)
        elif "error" in query_params:
            self.callback_data["error"] = query_params["error"][0]
            self.send_response(400)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                f"""
            <html>
            <body>
                <h1>Authorization Failed</h1>
                <p>Error: {query_params["error"][0]}</p>
                <p>You can close this window and return to the application.</p>
            </body>
            </html>
            """.encode()
            )
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


class CallbackServer:
    """Simple server to handle OAuth callbacks."""

    def __init__(self, port_range=CALLBACK_PORT_RANGE, dashboard_url=None, use_dashboard_page=False):
        """Initialize the callback server with a range of ports to try.

        Args:
            port_range: Tuple of (min_port, max_port) to try
            dashboard_url: URL of the GitGuardian dashboard for redirect
            use_dashboard_page: If True, redirect to dashboard authenticated page instead of showing local page
        """
        self.port_range = port_range
        self.port = None
        self.server = None
        self.thread = None
        self.callback_data = {
            "dashboard_url": dashboard_url,
            "authorization_code": None,
            "state": None,
            "error": None,
            "use_dashboard_page": use_dashboard_page,
        }

    def _create_handler_with_data(self):
        """Create a handler class with access to callback data."""
        callback_data = self.callback_data

        class DataCallbackHandler(CallbackHandler):
            def __init__(self, request, client_address, server):
                super().__init__(request, client_address, server, callback_data)

        return DataCallbackHandler

    def is_port_available(self, port):
        """Check if a port is available by attempting to bind to it.

        Args:
            port: Port number to check

        Returns:
            bool: True if the port is available, False otherwise
        """
        import errno
        import socket

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", port))
        except socket.error as e:
            if e.errno == errno.EADDRINUSE:
                return False

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("0.0.0.0", port))
        except socket.error as e:
            if e.errno == errno.EADDRINUSE:
                return False

        return True

    def start(self):
        """Start the callback server in a background thread."""
        handler_class = self._create_handler_with_data()

        # Try ports in the specified range until we find an available one
        for port in range(self.port_range[0], self.port_range[1] + 1):
            if not self.is_port_available(port):
                continue

            try:
                self.server = HTTPServer(("localhost", port), handler_class)
                self.port = port  # Save the successful port
                break
            except OSError as e:
                # Port became unavailable between check and server creation
                logger.debug(f"Failed to bind to port {port}: {e}")
                continue

        if not self.server:
            raise RuntimeError(f"Could not find an available port in range {self.port_range}")

        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        logger.info(f"Started callback server on http://localhost:{self.port}")

    def stop(self):
        """Stop the callback server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=1)

    def wait_for_callback(self, timeout=300):
        """Wait for OAuth callback with timeout."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.callback_data["authorization_code"]:
                return self.callback_data["authorization_code"]
            elif self.callback_data["error"]:
                raise Exception(f"OAuth error: {self.callback_data['error']}")
            time.sleep(0.1)
        raise Exception("Timeout waiting for OAuth callback")

    def get_state(self):
        """Get the received state parameter."""
        return self.callback_data["state"]


class GitGuardianOAuthClient:
    """OAuth client for GitGuardian using MCP SDK's OAuth support."""

    def __init__(
        self,
        api_url: str,
        dashboard_url: str,
        scopes: list[str] | None = None,
        token_name: str | None = None,
        token_lifetime: int | None = None,
    ):
        """
        Args:
            api_url: GitGuardian API URL (e.g., https://api.gitguardian.com/v1)
            dashboard_url: GitGuardian dashboard URL (e.g., https://dashboard.gitguardian.com)
            scopes: List of OAuth scopes to request (default: ["scan"])
            token_name: Custom name for the OAuth token (default: "mcp-server-token-YYYY-MM-DD")
        """
        # Debug OAuth client creation
        global _oauth_client_counter
        _oauth_client_counter += 1
        logger.debug(f"Creating OAuth client #{_oauth_client_counter} for {dashboard_url}")
        
        self.api_url = api_url
        self.dashboard_url = dashboard_url
        self.scopes = scopes or ["scan"]
        self.token_storage = InMemoryTokenStorage()
        self.file_token_storage = FileTokenStorage()
        self.oauth_provider = None
        self.access_token = None
        self.token_info = None
        self._account_id = None  # Will be populated from OAuth response

        # Use provided token name or use the default "MCP server token"
        self.token_name = token_name
        if not self.token_name:
            # Use a consistent default name
            self.token_name = "MCP server token"

        # Configure token lifetime from environment variable or use default (30 days)
        # Special value 'never' or -1 means token never expires
        self.token_lifetime = token_lifetime
        if self.token_lifetime is None:
            lifetime_env = os.environ.get("GITGUARDIAN_TOKEN_LIFETIME", "30")
            if lifetime_env.lower() == "never":
                self.token_lifetime = -1  # -1 indicates no expiration
            else:
                try:
                    self.token_lifetime = int(lifetime_env)
                except ValueError:
                    logger.warning(
                        f"Invalid GITGUARDIAN_TOKEN_LIFETIME value: {lifetime_env}. Using default of 30 days."
                    )
                    self.token_lifetime = 30



        # Try to load a saved token first
        self._load_saved_token()

    def _load_saved_token(self):
        """Try to load a saved token from file storage."""
        logger.debug(f"Attempting to load saved token for {self.dashboard_url}")
        try:
            # Use the new get_token method which handles account selection
            access_token, token_data = self.file_token_storage.get_token(self.dashboard_url)

            if not access_token or not token_data:
                logger.debug(f"No saved token found for {self.dashboard_url}")
                return

            # Set the access token and related info
            self.access_token = access_token
            self._account_id = token_data.get("account_id", "unknown")
            self.token_info = {
                "expires_at": token_data.get("expires_at"),
                "scopes": token_data.get("scopes"),
                "token_name": token_data.get("token_name"),
                "account_id": self._account_id,
            }
            self.token_name = token_data.get("token_name", self.token_name)

            logger.info(f"Loaded saved token '{self.token_name}' for {self.dashboard_url} (account {self._account_id})")
        except Exception as e:
            logger.warning(f"Failed to load saved token: {e}")
            # Continue without a saved token

    async def oauth_process(self, login_path: str | None = None) -> str:
        """Execute the OAuth authentication flow.

        Args:
            login_path: Optional custom login path (default: "auth/login")

        Returns:
            The access token if successful

        Raises:
            Exception: If authentication fails
        """
        logger.debug(f"oauth_process() called for token '{self.token_name}'")
            
        # Check if we already have a valid token loaded
        if self.access_token and self.token_info:
            logger.info(f"Using existing token '{self.token_name}' - skipping OAuth flow")
            return self.access_token
        
        logger.info(f"No valid token found for '{self.token_name}', starting OAuth authentication flow")
        
        # Handle the base URL correctly
        base_url = self.dashboard_url
        server_url = base_url.rstrip("/")

        logger.info(f"Starting OAuth authentication with GitGuardian at {server_url}")

        # Check if we should use the dashboard authenticated page from environment variable
        use_dashboard_page = os.environ.get("GITGUARDIAN_USE_DASHBOARD_AUTHENTICATED_PAGE", "").lower() in (
            "true",
            "1",
            "yes",
        )

        # Set up callback server with the use_dashboard_page option
        callback_server = CallbackServer(dashboard_url=self.dashboard_url, use_dashboard_page=use_dashboard_page)
        callback_server.start()

        # Define the redirect handler function to open browser
        async def redirect_handler(authorization_url: str) -> None:
            """Opens the browser for authorization."""
            logger.info(f"Opening browser for authorization: {authorization_url}")
            
            # Try to open the browser, but provide fallback instructions
            try:
                browser_opened = webbrowser.open(authorization_url)
                if not browser_opened:
                    logger.warning("Could not open browser automatically.")
                    print("\n\n-------------------------------------------------------------")
                    print("Please open the following URL in your browser to authenticate:")
                    print(f"\n{authorization_url}\n")
                    print("-------------------------------------------------------------\n\n")
                else:
                    logger.debug(f"Browser window opened successfully for '{self.token_name}'")
            except Exception as e:
                logger.error(f"Error opening browser: {e}")
                print("\n\n-------------------------------------------------------------")
                print("Please open the following URL in your browser to authenticate:")
                print(f"\n{authorization_url}\n")
                print("-------------------------------------------------------------\n\n")

        # Store relevant information for manual OAuth flow
        print("\n\n===========================================================")
        print("                 GITGUARDIAN OAUTH LOGIN                ")
        print("===========================================================\n")
        print(f"The server will open a browser window to {server_url} for authentication.")
        print("You'll need to log in and authorize the application.")
        print(f"After authorization, you'll be redirected to http://localhost:{callback_server.port}\n")

        # Create a simple server directly instead of trying to use OAuthClientProvider
        try:
            # 1. Generate a random state and PKCE verifier
            import base64
            import hashlib
            import random
            import string
            import urllib.parse

            # Create a state that includes the token name
            state_data = {
                "token_name": self.token_name,
                "random": "".join(random.choices(string.ascii_letters + string.digits, k=8)),
            }
            # Encode as JSON string
            state = json.dumps(state_data)

            # Generate PKCE code verifier and challenge
            code_verifier = "".join(random.choices(string.ascii_letters + string.digits + "-._~", k=128))
            code_challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip("=")
            )

            # Get OAuth client ID from environment variable or use default
            client_id = os.environ.get("GITGUARDIAN_CLIENT_ID", "ggshield_oauth")

            # 2. Create the authorization URL with the appropriate parameters
            auth_url = f"{server_url}/auth/login?"
            params = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": f"http://localhost:{callback_server.port}",
                "scope": " ".join(self.scopes),
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "auth_mode": "ggshield_login",
                "name": self.token_name,  # Try with 'name' instead of 'token_name'
                "token_name": self.token_name,  # Keep original in case it's needed
                "utm_source": "cli",  # Match the working URL parameters
                "utm_medium": "login",
                "utm_campaign": "ggshield",
            }
            auth_url += urllib.parse.urlencode(params)

            # 3. Open the browser with the authorization URL
            await redirect_handler(auth_url)

            # 4. Wait for the callback with the authorization code
            auth_code = callback_server.wait_for_callback(timeout=300)
            received_state = callback_server.get_state()

            # 5. Verify the state to prevent CSRF attacks
            try:
                # Try to parse as JSON
                if received_state and received_state.startswith("{") and received_state.endswith("}"):
                    received_state_data = json.loads(received_state)
                    state_data = json.loads(state) if isinstance(state, str) else state
                    # Check if the random values match
                    if received_state_data.get("random") != state_data.get("random"):
                        raise Exception("State mismatch: random value doesn't match")
                    # Store token name if present in the state
                    if "token_name" in received_state_data:
                        self.token_name = received_state_data["token_name"]
                elif received_state != state:
                    raise Exception(f"State mismatch: expected {state}, got {received_state}")
            except json.JSONDecodeError:
                # If either isn't valid JSON, fall back to direct comparison
                if received_state != state:
                    raise Exception(f"State mismatch: expected {state}, got {received_state}")

            logger.info("Received authorization code")

            # 6. Exchange the authorization code for an access token
            # Use the API URL for token endpoint, not the dashboard URL
            token_url = f"{self.api_url}/oauth/token"
            token_params = {
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": f"http://localhost:{callback_server.port}",
                "client_id": client_id,
                "code_verifier": code_verifier,  # Include the PKCE code verifier
                "name": self.token_name,  # Include token name in token request
            }

            # Add lifetime parameter if configured
            if self.token_lifetime is not None:
                if self.token_lifetime == -1:
                    # -1 means no expiration (don't set lifetime)
                    logger.info("Configuring token to never expire")
                else:
                    logger.info(f"Setting token lifetime to {self.token_lifetime} days")
                    token_params["lifetime"] = str(self.token_lifetime)

            # Make the token request
            import httpx

            # Prepare headers with token name information
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Token-Name": self.token_name,  # Custom header with token name
                "User-Agent": f"MCP-Server/{self.token_name}",  # Include in user agent
            }

            async with httpx.AsyncClient() as client:
                response = await client.post(token_url, data=token_params, headers=headers)

                if response.status_code == 200:
                    oauth_token_response = response.json()
                    self.access_token = oauth_token_response.get("access_token") or oauth_token_response.get("key")
                    if not self.access_token:
                        logger.error(f"No access token in response: {oauth_token_response}")
                        raise Exception("No access token in response")

                    # Extract account_id from OAuth token response
                    # According to GGShieldPublicAPITokenCreateOutputSerializer schema
                    account_id = oauth_token_response.get("account_id")
                    if account_id:
                        logger.info(f"Received token for account {account_id}")
                    else:
                        logger.warning("No account_id in OAuth token response, using 'unknown'")
                        account_id = "unknown"

                    # Store account_id for later use
                    self._account_id = account_id
                else:
                    logger.error(f"Failed to get token: {response.status_code} {response.text}")
                    raise Exception(f"Failed to get token: {response.status_code}")

            # Get token info by calling the GitGuardian API
            # Fetch token information for verification
            await self._fetch_token_info()
            logger.info("OAuth authentication successful")

            # Save the token for future reuse
            if self.access_token and self.token_info:
                # Get expiry date from token info or set based on configured lifetime
                expires_at = self.token_info.get("expires_at")

                # If no expiry date was returned from the API but we have a token lifetime
                if not expires_at and self.token_lifetime is not None:
                    if self.token_lifetime == -1:
                        # -1 means token never expires
                        logger.info("Token configured to never expire")
                        expires_at = None
                    else:
                        # Set expiry based on configured lifetime
                        logger.info(f"Setting token expiry to {self.token_lifetime} days from now")
                        expiry_date = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
                            days=self.token_lifetime
                        )
                        expires_at = expiry_date.isoformat()
                elif not expires_at:
                    # Default token expiration (30 days)
                    logger.info("Using default token expiry of 30 days")
                    expiry_date = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
                    expires_at = expiry_date.isoformat()

                # Prepare token data for storage
                token_storage_data = {
                    "access_token": self.access_token,
                    "expires_at": expires_at,
                    "token_name": self.token_name,
                    "scopes": self.token_info.get("scopes", self.scopes),
                    "account_id": self._account_id,
                }

                # Save to file storage with account_id
                self.file_token_storage.save_token(self.dashboard_url, self._account_id, token_storage_data)
                logger.info(f"Saved token '{self.token_name}' for account {self._account_id}")
                return self.access_token
            else:
                raise Exception("Failed to obtain access token during OAuth flow")

        except Exception as e:
            logger.error(f"OAuth authentication failed: {e}")
            raise

    async def _fetch_token_info(self) -> None:
        """Fetch token information from the GitGuardian API."""
        if not self.access_token:
            return

        try:
            import httpx  # Import here to avoid circular imports

            async with httpx.AsyncClient() as client:
                # Use the correct API endpoint with the full path
                response = await client.get(
                    f"{self.api_url}/api_tokens/self",
                    headers={"Authorization": f"Token {self.access_token}"},
                )

                if response.status_code == 200:
                    self.token_info = response.json()
                    logger.info(f"Retrieved token info with scopes: {self.token_info.get('scopes', [])}")
                else:
                    # Log the error but don't raise an exception
                    logger.warning(f"Failed to retrieve token info: HTTP {response.status_code}")
                    if response.content:
                        logger.debug(f"Response content: {response.text}")
        except Exception as e:
            logger.warning(f"Failed to retrieve token info: {e}")

    def get_token_info(self) -> dict | None:
        """Return the token information."""
        return self.token_info
