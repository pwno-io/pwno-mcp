"""
Pwno MCP Server

FastMCP server for autonomous low-level security research.
Provides GDB/pwndbg functionality via MCP tools for LLM interaction.
"""

import logging
import json
import os
from typing import Optional, Dict, Any
from mcp.server.fastmcp import FastMCP
from contextlib import asynccontextmanager
from fastapi import HTTPException
from pydantic import BaseModel

from pwnomcp.utils.format import *
from pwnomcp.gdb import GdbController
from pwnomcp.state import SessionState
from pwnomcp.tools import PwndbgTools, SubprocessTools, GitTools, PythonTools

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Default workspace directory for command execution
DEFAULT_WORKSPACE = "/workspace"

gdb_controller: Optional[GdbController] = None
session_state: Optional[SessionState] = None
pwndbg_tools: Optional[PwndbgTools] = None
subprocess_tools: Optional[SubprocessTools] = None
git_tools: Optional[GitTools] = None
python_tools: Optional[PythonTools] = None


@asynccontextmanager
async def lifespan(app: FastMCP):
    """
    Lifespan context manager for initializing and cleaning up resources.
    
    :param app: FastMCP application instance
    :yields: None
    """
    global gdb_controller, session_state, pwndbg_tools, subprocess_tools, git_tools, python_tools
    
    logger.info("Initializing Pwno MCP server...")
    
    # Create default workspace directory if it doesn't exist
    if not os.path.exists(DEFAULT_WORKSPACE):
        os.makedirs(DEFAULT_WORKSPACE, exist_ok=True)
        logger.info(f"Created default workspace directory: {DEFAULT_WORKSPACE}")
    
    # Create instances
    gdb_controller = GdbController()
    session_state = SessionState()
    pwndbg_tools = PwndbgTools(gdb_controller, session_state)
    subprocess_tools = SubprocessTools()
    git_tools = GitTools()
    python_tools = PythonTools()
    
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


# Pydantic models for HTTP endpoints
class ShellCommandRequest(BaseModel):
    """
    Request model for shell command execution.
    
    :param command: Shell command to execute
    :param cwd: Working directory (default: /workspace)
    :param timeout: Optional timeout in seconds (default: 30)
    """
    command: str
    cwd: Optional[str] = DEFAULT_WORKSPACE
    timeout: float = 30.0


class ShellCommandResponse(BaseModel):
    """
    Response model for shell command execution.
    
    :param success: Whether the command executed successfully
    :param command: The command that was executed
    :param returncode: Process return code (None if failed to execute)
    :param stdout: Standard output from the command
    :param stderr: Standard error from the command
    :param cwd: Working directory where command was executed
    :param error: Error message if execution failed
    """
    success: bool
    command: str
    returncode: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    cwd: str
    error: Optional[str] = None


# Health check endpoint
@mcp.app.get("/health")
async def health_check() -> Dict[str, Any]:
    """
    Health check endpoint to verify server is running.
    
    :returns: Server status and available tools
    """
    return {
        "status": "healthy",
        "server": "pwno-mcp",
        "endpoints": {
            "shell_execution": "/execute-shell",
            "spawn_process": "/spawn-process",
            "process_status": "/process/{pid}",
            "kill_process": "/kill-process/{pid}",
            "list_processes": "/processes"
        },
        "tools_initialized": {
            "subprocess": subprocess_tools is not None,
            "gdb": gdb_controller is not None,
            "pwndbg": pwndbg_tools is not None,
            "git": git_tools is not None,
            "python": python_tools is not None
        }
    }


# Direct HTTP endpoint for shell command execution
@mcp.app.post("/execute-shell", response_model=ShellCommandResponse)
async def execute_shell_command(request: ShellCommandRequest) -> ShellCommandResponse:
    """
    Execute a shell command directly on the VM.
    
    WARNING: This endpoint executes arbitrary shell commands.
    Only use in trusted environments!
    
    :param request: Shell command request with command, optional cwd and timeout
    :returns: Command execution results
    """
    global subprocess_tools
    
    if not subprocess_tools:
        raise HTTPException(status_code=503, detail="Subprocess tools not initialized")
    
    try:
        # Execute the command using existing subprocess tools
        result = subprocess_tools.run_command(
            command=request.command,
            cwd=request.cwd,
            timeout=request.timeout
        )
        
        # Convert result to response model
        return ShellCommandResponse(
            success=result.get("success", False),
            command=result.get("command", request.command),
            returncode=result.get("returncode"),
            stdout=result.get("stdout"),
            stderr=result.get("stderr"),
            cwd=result.get("cwd", ""),
            error=result.get("error")
        )
    except Exception as e:
        logger.error(f"Failed to execute shell command: {e}")
        return ShellCommandResponse(
            success=False,
            command=request.command,
            cwd=request.cwd or "",
            error=str(e)
        )


# Model for spawning background processes
class SpawnProcessRequest(BaseModel):
    """
    Request model for spawning background processes.
    
    :param command: Command to execute in background
    :param cwd: Working directory (default: /workspace)
    """
    command: str
    cwd: Optional[str] = DEFAULT_WORKSPACE


# Endpoint for spawning background processes
@mcp.app.post("/spawn-process")
async def spawn_process_endpoint(request: SpawnProcessRequest) -> Dict[str, Any]:
    """
    Spawn a background process that runs independently.
    
    :param request: Process spawn request
    :returns: Process information including PID
    """
    global subprocess_tools
    
    if not subprocess_tools:
        raise HTTPException(status_code=503, detail="Subprocess tools not initialized")
    
    return subprocess_tools.spawn_process(request.command, request.cwd)


# Endpoint for getting process status
@mcp.app.get("/process/{pid}")
async def get_process_status(pid: int) -> Dict[str, Any]:
    """
    Get status and output of a process.
    
    :param pid: Process ID
    :returns: Process status and outputs
    """
    global subprocess_tools
    
    if not subprocess_tools:
        raise HTTPException(status_code=503, detail="Subprocess tools not initialized")
    
    return subprocess_tools.get_process(pid)


# Endpoint for killing a process
@mcp.app.delete("/kill-process/{pid}")
async def kill_process_endpoint(pid: int, signal: int = 15) -> Dict[str, Any]:
    """
    Kill a process by PID.
    
    :param pid: Process ID to kill
    :param signal: Signal to send (15=SIGTERM, 9=SIGKILL)
    :returns: Kill operation result
    """
    global subprocess_tools
    
    if not subprocess_tools:
        raise HTTPException(status_code=503, detail="Subprocess tools not initialized")
    
    return subprocess_tools.kill_process(pid, signal)


# Endpoint for listing all tracked processes
@mcp.app.get("/processes")
async def list_processes_endpoint() -> Dict[str, Any]:
    """
    List all tracked background processes.
    
    :returns: List of running processes
    """
    global subprocess_tools
    
    if not subprocess_tools:
        raise HTTPException(status_code=503, detail="Subprocess tools not initialized")
    
    return subprocess_tools.list_processes()

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
    :param cwd: Working directory (default: /workspace)
    :param timeout: Timeout in seconds (default: 30)
    :returns: Command execution results
    """
    # Use default workspace if cwd not specified
    if cwd is None:
        cwd = DEFAULT_WORKSPACE
    result = subprocess_tools.run_command(command, cwd=cwd, timeout=timeout)
    return json.dumps(result, indent=2)


@mcp.tool()
def spawn_process(command: str, cwd: Optional[str] = None) -> str:
    """
    Spawn a background process and return immediately with PID.
    
    Useful for:
    - Compiling with sanitizers (e.g., `cmake --build .`, `make -j4`)
    - Starting servers for exploitation
    - Running network listeners

    :param command: Command to execute
    :param cwd: Working directory (default: /workspace)
    :returns: Process information including PID
    """
    # Use default workspace if cwd not specified
    if cwd is None:
        cwd = DEFAULT_WORKSPACE
    result = subprocess_tools.spawn_process(command, cwd=cwd)
    return json.dumps(result, indent=2)


@mcp.tool()
def get_process(pid: int) -> str:
    """
    Get status of a spawned process, including stdout and stderr output or paths.

    :param pid: Process ID to check
    :returns: Process status and outputs
    """
    result = subprocess_tools.get_process(pid)
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
    :param target_dir: Target directory name relative to /workspace. If None, derives from repo URL
    :param shallow: Whether to perform shallow clone (faster for large repos)
    :returns: Repository fetch results including local path
    """
    # If target_dir is provided and not absolute, make it relative to workspace
    if target_dir and not os.path.isabs(target_dir):
        target_dir = os.path.join(DEFAULT_WORKSPACE, target_dir)
    elif not target_dir:
        # Derive from repo URL and place in workspace
        repo_name = repo_url.rstrip('/').split('/')[-1].replace('.git', '')
        target_dir = os.path.join(DEFAULT_WORKSPACE, repo_name)
    
    result = git_tools.fetch_repo(repo_url, version, target_dir, shallow)
    return json.dumps(result, indent=2)


@mcp.tool()
def execute_python_script(
    script_path: str,
    args: Optional[str] = None,
    cwd: Optional[str] = None,
    timeout: float = 300.0
) -> str:
    """
    Execute a Python script in the shared preconfigured environment.
    
    The environment includes: pwntools, requests, cryptography, numpy,
    ipython, hexdump, pycryptodome.

    :param script_path: Path to the Python script to execute
    :param args: Space-separated arguments to pass to the script
    :param cwd: Working directory for script execution (default: /workspace)
    :param timeout: Execution timeout in seconds
    :returns: Execution results with stdout, stderr, and status
    """
    # Use default workspace if cwd not specified
    if cwd is None:
        cwd = DEFAULT_WORKSPACE
    args_list = args.split() if args else None
    result = python_tools.execute_script(script_path, args_list, cwd, timeout)
    return json.dumps(result, indent=2)


@mcp.tool()
def execute_python_code(
    code: str,
    cwd: Optional[str] = None,
    timeout: float = 300.0
) -> str:
    """
    Execute Python code directly in the shared environment.
    
    Useful for quick scripts or analysis code using preinstalled packages.

    :param code: Python code to execute
    :param cwd: Working directory for execution (default: /workspace)
    :param timeout: Execution timeout in seconds
    :returns: Execution results
    """
    # Use default workspace if cwd not specified
    if cwd is None:
        cwd = DEFAULT_WORKSPACE
    result = python_tools.execute_code(code, cwd, timeout)
    return json.dumps(result, indent=2)


@mcp.tool()
def install_python_packages(
    packages: str,
    upgrade: bool = False
) -> str:
    """
    Install additional Python packages using UV.
    
    UV is significantly faster than pip for package installation.

    :param packages: Space-separated list of packages (e.g., "beautifulsoup4 lxml")
    :param upgrade: Whether to upgrade existing packages
    :returns: Installation results
    """
    packages_list = packages.split()
    result = python_tools.install_packages(packages_list, upgrade)
    return json.dumps(result, indent=2)


@mcp.tool()
def list_python_packages() -> str:
    """
    List installed packages in the shared Python environment.

    :returns: List of installed packages
    """
    result = python_tools.get_installed_packages()
    return json.dumps(result, indent=2)


def run_server():
    mcp.run(
        transport="streamable-http",
    )


if __name__ == "__main__":
    run_server() 