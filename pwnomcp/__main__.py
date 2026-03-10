"""
Entry point for Pwno MCP server
"""

import argparse

from pwnomcp.runtime import run_http, run_stdio


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Pwno MCP Server")
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host address for the main MCP server (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5500,
        help="Port for the main MCP server (default: 5500)",
    )
    parser.add_argument(
        "--attach-host",
        default="127.0.0.1",
        help="Host address for the attach API server (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--attach-port",
        type=int,
        default=5501,
        help="Port for the attach API server (default: 5501)",
    )
    parser.add_argument(
        "--http-path",
        default="/mcp",
        help="URL path for the HTTP transport (default: /mcp)",
    )
    parser.add_argument(
        "--stdio",
        action="store_true",
        help="Run using stdio transport (default is HTTP)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    cli_args = _parse_args()
    if cli_args.stdio:
        run_stdio()
    else:
        run_http(
            host=cli_args.host,
            port=cli_args.port,
            attach_host=cli_args.attach_host,
            attach_port=cli_args.attach_port,
            http_path=cli_args.http_path,
        )
