"""
Authentication handler for Pwno MCP Server

Provides X-Nonce header authentication using MCP's auth framework.
Allows access to HTTP headers in MCP tools when running in streamable HTTP mode.
"""

from pathlib import Path
from typing import Optional
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from pydantic import AnyHttpUrl
from starlette.requests import Request

from pwnomcp.logger import logger


class NonceAuthProvider:
    """
    Custom authentication provider that validates X-Nonce header tokens.

    This provider integrates with MCP's auth framework to enable header access
    in tools when running in streamable HTTP mode.
    """

    def __init__(self, nonce_file_path: str = "/app/.nonce"):
        """
        Initialize the Nonce authentication provider.

        :param nonce_file_path: Path to the file containing the valid nonce
        """
        self.nonce_file_path = nonce_file_path
        self._local_nonce: Optional[str] = None
        self._load_local_nonce()

    def _load_local_nonce(self):
        """
        Load the nonce from the filesystem.

        If no nonce file exists or is empty, authentication will be disabled.
        """
        try:
            nonce_file = Path(self.nonce_file_path)
            if nonce_file.exists() and nonce_file.is_file():
                with open(nonce_file, "r") as f:
                    nonce_content = f.read().strip()
                    if nonce_content:
                        self._local_nonce = nonce_content
                        logger.info(
                            f"Loaded nonce from {self.nonce_file_path}, authentication enabled"
                        )
                    else:
                        logger.warning(
                            f"Nonce file {self.nonce_file_path} is empty, authentication disabled"
                        )
                        self._local_nonce = None
            else:
                logger.info(
                    f"Nonce file {self.nonce_file_path} not found, authentication disabled"
                )
                self._local_nonce = None
        except Exception as e:
            logger.error(f"Error loading nonce: {e}, authentication disabled")
            self._local_nonce = None

    async def load_access_token(self, token: str) -> Optional[AccessToken]:
        """
        Validate the provided token against the local nonce.

        :param token: Token to validate (extracted from X-Nonce header)
        :returns: AccessToken if valid, None otherwise
        """
        # If no local nonce is set, allow all requests (for development/testing)
        if not self._local_nonce:
            logger.debug("No local nonce set, allowing request")
            return AccessToken(
                token=token or "no-auth",
                client_id="anonymous",
                scopes=["api"],
                expires_at=None,
            )

        # Validate the provided token
        if token and token == self._local_nonce:
            logger.debug("Nonce validation successful")
            return AccessToken(
                token=token,
                client_id="authenticated-client",
                scopes=["api"],
                expires_at=None,
            )

        logger.warning(f"Invalid nonce provided")
        return None

    async def extract_token_from_request(self, request: Request) -> Optional[str]:
        """
        Extract the nonce from the X-Nonce header.

        This method is called by MCP's auth middleware to get the token
        from incoming HTTP requests.

        :param request: Starlette request object
        :returns: Token string if found in headers
        """
        # Try X-Nonce header first (preferred)
        x_nonce = request.headers.get("X-Nonce")
        if x_nonce:
            logger.debug("Found X-Nonce header")
            return x_nonce

        # Fallback to Authorization header for backward compatibility
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            logger.debug("Found Bearer token in Authorization header (fallback)")
            return auth_header[7:].strip()

        logger.debug("No authentication token found in headers")
        return None

    @property
    def is_auth_enabled(self) -> bool:
        """
        Check if authentication is enabled (i.e., a nonce is configured).

        :returns: True if authentication is enabled
        """
        return self._local_nonce is not None


def create_auth_settings(
    issuer_url: str = "http://localhost:5500",
    resource_server_url: str = "http://localhost:5500",
) -> AuthSettings:
    """
    Create MCP auth settings for the Nonce authentication system.

    :param issuer_url: URL of the auth issuer (the MCP server itself)
    :param resource_server_url: URL of the resource server (typically same as issuer)
    :returns: Configured AuthSettings instance
    """
    return AuthSettings(
        issuer_url=AnyHttpUrl(issuer_url),
        resource_server_url=AnyHttpUrl(resource_server_url),
        client_registration_options=ClientRegistrationOptions(
            enabled=False,  # Disable dynamic client registration
            valid_scopes=["api"],
            default_scopes=["api"],
        ),
        required_scopes=["api"],
    )
