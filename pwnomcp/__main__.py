"""
Entry point for Pwno MCP server
"""

import argparse
from pwnomcp.server import run_server

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pwno MCP Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host address for the main MCP server (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5500, help="Port for the main MCP server (default: 5500)")
    parser.add_argument("--attach-host", default="127.0.0.1", help="Host address for the attach API server (default: 127.0.0.1)")
    parser.add_argument("--attach-port", type=int, default=5501, help="Port for the attach API server (default: 5501)")
    
    args = parser.parse_args()
    run_server(host=args.host, port=args.port, attach_host=args.attach_host, attach_port=args.attach_port)