"""
Entry point for Pwno MCP server
"""

import os
from pwnomcp.server import run_server, run_stdio

if __name__ == "__main__":
    # Use stdio mode for MCP clients (Claude Desktop, etc.)
    # Use HTTP mode when PWNOMCP_HTTP_MODE=1 is set
    if os.getenv("PWNOMCP_HTTP_MODE") == "1":
        run_server()
    else:
        run_stdio()