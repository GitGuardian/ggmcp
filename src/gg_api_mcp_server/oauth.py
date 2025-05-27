"""OAuth authentication implementation for GitGuardian API using MCP SDK."""

import logging
import os
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

from mcp.client.auth import TokenStorage
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

# Configure logger
logger = logging.getLogger(__name__)

# Port range for callback server
CALLBACK_PORT_RANGE = (8000, 8999)


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
            force_local_page = self.callback_data.get("force_local_page", False)
            redirect_url = None
            if dashboard_url and not force_local_page:
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

    def __init__(self, port_range=CALLBACK_PORT_RANGE, dashboard_url=None, force_local_page=False):
        """Initialize the callback server with a range of ports to try.

        Args:
            port_range: Tuple of (min_port, max_port) to try
            dashboard_url: URL of the GitGuardian dashboard for redirect
            force_local_page: If True, always show the local success page instead of redirecting
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
            "force_local_page": force_local_page,
        }

    def _create_handler_with_data(self):
        """Create a handler class with access to callback data."""
        callback_data = self.callback_data

        class DataCallbackHandler(CallbackHandler):
            def __init__(self, request, client_address, server):
                super().__init__(request, client_address, server, callback_data)

        return DataCallbackHandler

    def start(self):
        """Start the callback server in a background thread."""
        handler_class = self._create_handler_with_data()

        # Try ports in the specified range until we find an available one
        for port in range(self.port_range[0], self.port_range[1] + 1):
            try:
                self.server = HTTPServer(("localhost", port), handler_class)
                self.port = port  # Save the successful port
                break
            except OSError:
                # Port already in use, try the next one
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

    def __init__(self, api_url: str, dashboard_url: str, scopes: list[str] | None = None):
        """Initialize the OAuth client.

        Args:
            api_url: GitGuardian API URL (e.g., https://api.gitguardian.com/v1)
            dashboard_url: GitGuardian dashboard URL (e.g., https://dashboard.gitguardian.com)
            scopes: List of OAuth scopes to request (default: ["scan"])
        """
        self.api_url = api_url
        self.dashboard_url = dashboard_url
        self.scopes = scopes or ["scan"]
        self.token_storage = InMemoryTokenStorage()
        self.oauth_provider = None
        self.access_token = None
        self.token_info = None

    async def oauth_process(self, login_path: str | None = None) -> str:
        """Execute the OAuth authentication flow.

        Args:
            login_path: Optional custom login path (default: "auth/login")

        Returns:
            The access token if successful

        Raises:
            Exception: If authentication fails
        """
        # Handle the base URL correctly
        base_url = self.dashboard_url
        server_url = base_url.rstrip("/")

        logger.info(f"Starting OAuth authentication with GitGuardian at {server_url}")

        # Check if we should force the local page from environment variable
        force_local_page = os.environ.get("GITGUARDIAN_FORCE_LOCAL_PAGE", "").lower() in ("true", "1", "yes")

        # Set up callback server with the force_local_page option
        callback_server = CallbackServer(dashboard_url=self.dashboard_url, force_local_page=force_local_page)
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

            # Generate random state
            state = "".join(random.choices(string.ascii_letters + string.digits, k=16))

            # Generate PKCE code verifier and challenge
            code_verifier = "".join(random.choices(string.ascii_letters + string.digits + "-._~", k=128))
            code_challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip("=")
            )

            # 2. Create the authorization URL with the appropriate parameters
            auth_url = f"{server_url}/auth/login?"
            params = {
                "response_type": "code",
                "client_id": "ggshield_oauth",  # Using the same client ID as ggshield
                "redirect_uri": f"http://localhost:{callback_server.port}",
                "scope": " ".join(self.scopes),
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "auth_mode": "ggshield_login",
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
            if received_state != state:
                raise Exception(f"State mismatch: expected {state}, got {received_state}")

            logger.info("Received authorization code")

            # 6. Exchange the authorization code for an access token
            token_url = f"{server_url}/exposed/v1/oauth/token"
            token_params = {
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": f"http://localhost:{callback_server.port}",
                "client_id": "ggshield_oauth",
                "code_verifier": code_verifier,  # Include the PKCE code verifier
            }

            # Make the token request
            import httpx

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    token_url, data=token_params, headers={"Content-Type": "application/x-www-form-urlencoded"}
                )

                if response.status_code == 200:
                    token_data = response.json()
                    self.access_token = token_data.get("access_token") or token_data.get("key")
                    if not self.access_token:
                        logger.error(f"No access token in response: {token_data}")
                        raise Exception("No access token in response")
                else:
                    logger.error(f"Failed to get token: {response.status_code} {response.text}")
                    raise Exception(f"Failed to get token: {response.status_code}")

            # Get token info by calling the GitGuardian API
            if self.access_token:
                await self._fetch_token_info()
                logger.info("OAuth authentication successful")
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
