"""
Pwno MCP Server

FastMCP server for autonomous low-level security research.
Provides GDB/pwndbg functionality via MCP tools for LLM interaction.
"""

import logging
from typing import Dict, Any, Optional
from mcp.server.fastmcp import FastMCP
import asyncio

from pwnomcp.gdb import GdbController
from pwnomcp.state import SessionState
from pwnomcp.tools import PwndbgTools

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

mcp = FastMCP("pwno-mcp")

gdb_controller: Optional[GdbController] = None
session_state: Optional[SessionState] = None
pwndbg_tools: Optional[PwndbgTools] = None


def format_execute_result(result: Dict[str, Any]) -> str:
    """Format execute command result"""
    output = f"Command: {result['command']}\n"
    if result.get('error'):
        output += f"Error: {result['error']}\n"
    if result.get('output'):
        output += f"Output:\n{result['output']}"
    output += f"\nState: {result['state']}"
    return output


def format_launch_result(result: Dict[str, Any]) -> str:
    """Format launch command result"""
    if not result['success']:
        return f"Launch failed: {result['error']}"
    
    output = f"Launch successful\nState: {result['state']}\n"
    
    # Add load information
    if 'load' in result.get('results', {}):
        load_info = result['results']['load']
        if load_info.get('output'):
            output += f"\nLoad output:\n{load_info['output']}"
    
    # Add context if available
    if 'context' in result.get('results', {}):
        output += "\n\nInitial context:"
        for ctx_type, ctx_data in result['results']['context'].items():
            output += f"\n\n[{ctx_type.upper()}]\n{ctx_data}"
    
    return output


def format_step_result(result: Dict[str, Any]) -> str:
    """Format step control result"""
    if not result['success']:
        return f"Step failed: {result['error']}\nState: {result['state']}"
    
    output = f"Command: {result['command']}\n"
    if result.get('output'):
        output += f"Output:\n{result['output']}\n"
    output += f"State: {result['state']}"
    
    # Add context if stopped
    if result.get('context'):
        output += "\n\nContext after step:"
        for ctx_type, ctx_data in result['context'].items():
            output += f"\n\n[{ctx_type.upper()}]\n{ctx_data}"
    
    return output


def format_context_result(result: Dict[str, Any]) -> str:
    """Format context result"""
    if not result['success']:
        return f"Context error: {result['error']}"
    
    if 'context' in result:
        # Full context
        output = "Full debugging context:"
        for ctx_type, ctx_data in result['context'].items():
            output += f"\n\n[{ctx_type.upper()}]\n{ctx_data}"
        return output
    else:
        # Single context type
        return f"[{result['context_type'].upper()}]\n{result['data']}"


def format_breakpoint_result(result: Dict[str, Any]) -> str:
    """Format breakpoint result"""
    if not result['success']:
        return f"Breakpoint error: {result['error']}"
    return result['output']


def format_memory_result(result: Dict[str, Any]) -> str:
    """Format memory read result"""
    if not result['success']:
        return f"Memory read error: {result['error']}"
    
    output = f"Memory at {result['address']} ({result['size']} bytes, {result['format']} format):\n"
    output += result['data']
    return output


def format_session_result(result: Dict[str, Any]) -> str:
    """Format session info result"""
    import json
    return json.dumps(result, indent=2)


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
def launch(
    binary_path: str, 
    args: str = "", 
    mode: str = "run"
) -> str:
    """
    Launch binary for debugging with execution control.

    :param binary_path: Path to binary to debug
    :param args: Arguments to pass to the binary
    :param mode: Launch mode ('run' to start fresh or 'start' to break at entry)
    :returns: Launch results and initial state
    """
    result = pwndbg_tools.launch(binary_path, args, mode)
    return format_launch_result(result)


@mcp.tool()
def step_control(command: str) -> str:
    """
    Execute stepping commands (run, continue, next, step, nexti, stepi).

    :param command: Stepping command (run, c, n, s, ni, si or full name)
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