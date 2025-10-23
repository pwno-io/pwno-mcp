"""
Entry point for Pwno MCP server
"""

import argparse
import os

from pwnomcp.server import run_server, run_stdio


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Pwno MCP Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host address for the main MCP server (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5500, help="Port for the main MCP server (default: 5500)")
    parser.add_argument("--attach-host", default="127.0.0.1", help="Host address for the attach API server (default: 127.0.0.1)")
    parser.add_argument("--attach-port", type=int, default=5501, help="Port for the attach API server (default: 5501)")
    return parser.parse_args()


if __name__ == "__main__":
    # Use stdio mode for MCP clients (Claude Desktop, etc.)
    # Use HTTP mode when PWNOMCP_HTTP_MODE=1 is set
    if os.getenv("PWNOMCP_HTTP_MODE") == "1":
        cli_args = _parse_args()
        run_server(
            host=cli_args.host,
            port=cli_args.port,
            attach_host=cli_args.attach_host,
            attach_port=cli_args.attach_port,
        )
    else:
        run_stdio()
