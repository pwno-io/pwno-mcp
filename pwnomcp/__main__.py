"""
Entry point for Pwno MCP server
"""

import argparse

from pwnomcp.server import run_server, run_stdio


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
        "--streamable-http-path",
        default="/debug",
        help="URL path for the Streamable HTTP transport (default: /debug)",
    )
    parser.add_argument(
        "--stdio",
        action="store_true",
        help="Run using stdio transport (default is Streamable HTTP)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    cli_args = _parse_args()
    if cli_args.stdio:
        run_stdio()
    else:
        run_server(
            host=cli_args.host,
            port=cli_args.port,
            attach_host=cli_args.attach_host,
            attach_port=cli_args.attach_port,
            streamable_http_path=cli_args.streamable_http_path,
        )
