"""
Entry point for Pwno MCP server
"""

import argparse
from pwnomcp.mcp import run_server

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pwno MCP Server")
    parser.add_argument("--nonce", type=str, help="Authentication nonce", default=None)
    args = parser.parse_args()
    
    run_server(args.nonce) 