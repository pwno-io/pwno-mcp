"""
Example showing how to use the new X-Nonce authentication with Pwno MCP Server

The authentication system now integrates with MCP's auth framework, allowing
access to HTTP headers in tools when running in streamable HTTP mode.
"""

# Client-side example: How to send requests with X-Nonce header
import requests

# Server expects X-Nonce header for authentication
headers = {
    "X-Nonce": "your-secret-nonce-here",
    "Content-Type": "application/json"
}

# Example MCP request
mcp_request = {
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "execute",
        "arguments": {
            "command": "info registers"
        }
    },
    "id": 1
}

response = requests.post(
    "http://localhost:5500/",
    json=mcp_request,
    headers=headers
)

print(response.json())


# Server-side example: How to access the token in a tool (already implemented in mcp.py)
"""
from mcp.server.auth.middleware.auth_context import get_access_token

@mcp.tool()
async def custom_tool_with_auth() -> str:
    # Access the token/nonce that was provided by the client
    access_token = get_access_token()
    
    if access_token:
        # Token is available - client is authenticated
        token_value = access_token.token  # This is the X-Nonce value
        client_id = access_token.client_id
        scopes = access_token.scopes
        
        # You can use this information for additional authorization logic
        # or to make authenticated requests to other services
        
        return f"Authenticated request from client: {client_id}"
    else:
        # No token - running without authentication
        return "Running in unauthenticated mode"
"""

# Authentication behavior:
# 1. If /app/.nonce file exists and contains a nonce:
#    - Server requires X-Nonce header matching the file content
#    - Requests without valid X-Nonce are rejected
#
# 2. If /app/.nonce file doesn't exist or is empty:
#    - Authentication is disabled
#    - All requests are allowed (development mode)
#
# 3. The server also accepts Bearer token in Authorization header
#    for backward compatibility

print("""
Authentication Notes:
- Place your nonce in /app/.nonce file on the server
- Send it via X-Nonce header in requests
- Or use "Authorization: Bearer <nonce>" for compatibility
- Tools can access the token via get_access_token() when needed
""")
