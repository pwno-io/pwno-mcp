"""
Pwno MCP Server

FastMCP server for autonomous low-level security research.
Provides GDB/pwndbg functionality via MCP tools for LLM interaction.
"""

import logging
from typing import Dict, Any, Optional
from mcp.server.fastmcp import FastMCP
from contextlib import asynccontextmanager
from pwnomcp.utils.format import *

from pwnomcp.gdb import GdbController
from pwnomcp.state import SessionState
from pwnomcp.tools import PwndbgTools

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

gdb_controller: Optional[GdbController] = None
session_state: Optional[SessionState] = None
pwndbg_tools: Optional[PwndbgTools] = None


@asynccontextmanager
async def lifespan(app: FastMCP):
    """
    Lifespan context manager for initializing and cleaning up resources.
    
    :param app: FastMCP application instance
    :yields: None
    """
    global gdb_controller, session_state, pwndbg_tools
    
    logger.info("Initializing Pwno MCP server...")
    
    # Create instances
    gdb_controller = GdbController()
    session_state = SessionState()
    pwndbg_tools = PwndbgTools(gdb_controller, session_state)
    
    # Initialize GDB with pwndbg
    init_result = gdb_controller.initialize()
    logger.info(f"GDB initialization: {init_result['status']}")
    
    yield  # Server runs here
    
    # Cleanup on shutdown
    logger.info("Shutting down Pwno MCP server...")
    if gdb_controller:
        gdb_controller.close()


# Create FastMCP instance with lifespan
mcp = FastMCP("pwno-mcp", lifespan=lifespan)

@mcp.tool()
def execute(command: str) -> str:
    """
    Execute arbitrary GDB/pwndbg command.

    :param command: GDB command to execute
    :returns: Command output and state information
    """
    result = pwndbg_tools.execute(command)
    return format_execute_result(result)


@mcp.tool()
def set_file(binary_path: str) -> str:
    """
    Load a binary file for debugging.

    :param binary_path: Path to the binary to load
    :returns: Loading status and binary information
    """
    result = pwndbg_tools.set_file(binary_path)
    return result


@mcp.tool()
def run(args: str = "") -> str:
    """
    Run the loaded binary.

    :param args: Arguments to pass to the binary
    :returns: Execution results and state
    """
    result = pwndbg_tools.run(args)
    return format_step_result(result)


@mcp.tool()
def step_control(command: str) -> str:
    """
    Execute stepping commands (continue, next, step, nexti, stepi).

    :param command: Stepping command (c, n, s, ni, si or full name)
    :returns: Execution results and new state
    """
    result = pwndbg_tools.step_control(command)
    return format_step_result(result)


@mcp.tool()
def get_context(context_type: str = "all") -> str:
    """
    Get debugging context (registers, stack, disassembly, code, backtrace).

    :param context_type: Type of context (all, regs, stack, disasm, code, backtrace)
    :returns: Requested context information
    """
    result = pwndbg_tools.get_context(context_type)
    return format_context_result(result)


@mcp.tool()
def set_breakpoint(location: str, condition: Optional[str] = None) -> str:
    """
    Set a breakpoint at the specified location.

    :param location: Address or symbol for breakpoint
    :param condition: Optional breakpoint condition
    :returns: Breakpoint information
    """
    result = pwndbg_tools.set_breakpoint(location, condition)
    return format_breakpoint_result(result)


@mcp.tool()
def get_memory(
    address: str, 
    size: int = 64, 
    format: str = "hex"
) -> str:
    """
    Read memory at the specified address.

    :param address: Memory address to read
    :param size: Number of bytes to read
    :param format: Output format (hex, string, int)
    :returns: Memory contents in the requested format
    """
    result = pwndbg_tools.get_memory(address, size, format)
    return format_memory_result(result)


@mcp.tool()
def get_session_info() -> str:
    """
    Get current debugging session information.

    :returns: Session state and debugging artifacts
    """
    result = pwndbg_tools.get_session_info()
    return format_session_result(result)


def run_server():
    mcp.run(
        transport="streamable-http"
    )


if __name__ == "__main__":
    run_server() 