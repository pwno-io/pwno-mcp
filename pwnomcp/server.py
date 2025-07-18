"""
PwnoMCP Server - MCP server for autonomous low-level security research
"""

import asyncio
import logging

# Import all tool modules to register them
from pwnomcp.tools import pwndbg, memory, breakpoint, stdio
from pwnomcp.gdb_controller import gdb_controller
from pwnomcp.mcp_server import mcp

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@mcp.tool()
async def initialize_debugger() -> str:
    """Initialize the GDB debugger if not already initialized"""
    if not gdb_controller.controller:
        success = gdb_controller.initialize()
        if success:
            return "GDB debugger initialized successfully"
        else:
            return "Failed to initialize GDB debugger"
    return "GDB debugger already initialized"


async def main():
    """Main entry point"""
    # Initialize GDB controller
    if not gdb_controller.initialize():
        logger.error("Failed to initialize GDB controller")
        return
        
    logger.info("PwnoMCP server starting...")
    
    # Start WebSocket server for live updates
    from pwnomcp.websocket import ws_manager
    await ws_manager.start(host="0.0.0.0", port=8765)
    
    try:
        # Run the FastMCP server
        await mcp.run()
    except asyncio.CancelledError:
        logger.info("Server shutdown requested")
    finally:
        # Cleanup
        await ws_manager.stop()
        gdb_controller.shutdown()


if __name__ == "__main__":
    asyncio.run(main())