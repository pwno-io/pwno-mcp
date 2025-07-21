"""
Pwno MCP Server

FastMCP server for autonomous low-level security research.
Provides GDB/pwndbg functionality via MCP tools for LLM interaction.
"""

import logging
import json
from typing import Optional
from mcp.server.fastmcp import FastMCP
from contextlib import asynccontextmanager

from pwnomcp.utils.format import *
from pwnomcp.gdb import GdbController
from pwnomcp.state import SessionState
from pwnomcp.tools import PwndbgTools, SubprocessTools, GitTools

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

gdb_controller: Optional[GdbController] = None
session_state: Optional[SessionState] = None
pwndbg_tools: Optional[PwndbgTools] = None
subprocess_tools: Optional[SubprocessTools] = None
git_tools: Optional[GitTools] = None


@asynccontextmanager
async def lifespan(app: FastMCP):
    """
    Lifespan context manager for initializing and cleaning up resources.
    
    :param app: FastMCP application instance
    :yields: None
    """
    global gdb_controller, session_state, pwndbg_tools, subprocess_tools, git_tools
    
    logger.info("Initializing Pwno MCP server...")
    
    # Create instances
    gdb_controller = GdbController()
    session_state = SessionState()
    pwndbg_tools = PwndbgTools(gdb_controller, session_state)
    subprocess_tools = SubprocessTools()
    git_tools = GitTools()
    
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
mcp.settings.host = "0.0.0.0"
mcp.settings.port = 5500

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
    return format_file_result(result)


@mcp.tool()
def run(args: str = "", interrupt_after: Optional[float] = None) -> str:
    """
    Run the loaded binary.
    
    Before running, you should either:
    1. Set breakpoints at key locations (recommended), OR
    2. Use interrupt_after to pause execution after N seconds

    :param args: Arguments to pass to the binary
    :param interrupt_after: Optional - interrupt execution after N seconds
    :returns: Execution results and state
    """
    result = pwndbg_tools.run(args, interrupt_after)
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


@mcp.tool()
def run_command(command: str, cwd: Optional[str] = None, timeout: float = 30.0) -> str:
    """
    Execute a system command and wait for completion.
    
    Primarily for compilation with sanitizers like:
    - gcc -g -fsanitize=address program.c -o program
    - clang -O0 -g -fno-omit-frame-pointer vuln.c
    - make clean && make

    :param command: Command to execute
    :param cwd: Working directory (optional)
    :param timeout: Timeout in seconds (default: 30)
    :returns: Command execution results
    """
    result = subprocess_tools.run_command(command, cwd=cwd, timeout=timeout)
    import json
    return json.dumps(result, indent=2)


@mcp.tool()
def spawn_process(command: str, cwd: Optional[str] = None) -> str:
    """
    Spawn a background process and return immediately with PID.
    
    Useful for:
    - Starting servers for exploitation
    - Running network listeners
    - Background monitoring scripts

    :param command: Command to execute
    :param cwd: Working directory (optional)
    :returns: Process information including PID
    """
    result = subprocess_tools.spawn_process(command, cwd=cwd)
    return json.dumps(result, indent=2)


@mcp.tool()
def get_process_status(pid: int) -> str:
    """
    Get status of a spawned process.

    :param pid: Process ID to check
    :returns: Process status information
    """
    result = subprocess_tools.get_process_status(pid)
    return json.dumps(result, indent=2)


@mcp.tool()
def kill_process(pid: int, signal: int = 15) -> str:
    """
    Kill a process.

    :param pid: Process ID to kill
    :param signal: Signal to send (15=SIGTERM, 9=SIGKILL)
    :returns: Kill operation result
    """
    result = subprocess_tools.kill_process(pid, signal)
    return json.dumps(result, indent=2)


@mcp.tool()
def list_processes() -> str:
    """
    List all tracked background processes.

    :returns: List of running background processes
    """
    result = subprocess_tools.list_processes()
    return json.dumps(result, indent=2)


@mcp.tool()
def fetch_repo(
    repo_url: str,
    version: Optional[str] = None,
    target_dir: Optional[str] = None,
    shallow: bool = True
) -> str:
    """
    Fetch a specific version of a git repository.
    
    Useful for analyzing vulnerable versions of software or specific commits.

    :param repo_url: Git repository URL (https or ssh)
    :param version: Specific version to checkout (branch/tag/commit). If None, uses default branch
    :param target_dir: Target directory name. If None, derives from repo URL
    :param shallow: Whether to perform shallow clone (faster for large repos)
    :returns: Repository fetch results including local path
    """
    result = git_tools.fetch_repo(repo_url, version, target_dir, shallow)
    return json.dumps(result, indent=2)


def run_server():
    mcp.run(
        transport="streamable-http",
    )


if __name__ == "__main__":
    run_server() 