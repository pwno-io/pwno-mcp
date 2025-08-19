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
from mcp.server.auth.middleware.auth_context import get_access_token
from contextlib import asynccontextmanager
from pydantic import BaseModel
from fastapi import FastAPI
import uvicorn

from pwnomcp.utils.format import *
from pwnomcp.gdb import GdbController
from pwnomcp.state import SessionState
from pwnomcp.tools import PwndbgTools, SubprocessTools, GitTools, PythonTools
from pwnomcp.utils.auth.handler import NonceAuthProvider, create_auth_settings
from pwnomcp.retdec.retdec import RetDecAnalyzer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize authentication provider
auth_provider = NonceAuthProvider()
auth_settings = create_auth_settings()

# Default workspace directory for command execution
DEFAULT_WORKSPACE = "/workspace"

gdb_controller: Optional[GdbController] = None
session_state: Optional[SessionState] = None
pwndbg_tools: Optional[PwndbgTools] = None
subprocess_tools: Optional[SubprocessTools] = None
git_tools: Optional[GitTools] = None
python_tools: Optional[PythonTools] = None
retdec_analyzer: Optional[RetDecAnalyzer] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for initializing and cleaning up resources.
    This runs when the FastAPI/uvicorn app starts, not just the MCP portion.
    
    :param app: FastAPI application instance
    :yields: None
    """
    global gdb_controller, session_state, pwndbg_tools, subprocess_tools, git_tools, python_tools, retdec_analyzer
    
    logger.info("Initializing Pwno MCP server...")
    
    # Try to create default workspace directory if it doesn't exist
    if not os.path.exists(DEFAULT_WORKSPACE):
        try:
            os.makedirs(DEFAULT_WORKSPACE, exist_ok=True)
            logger.info(f"Created default workspace directory: {DEFAULT_WORKSPACE}")
        except OSError as e:
            logger.warning(f"Could not create workspace directory {DEFAULT_WORKSPACE}: {e}")
            logger.info("Continuing without default workspace directory")
    
    # Create instances
    gdb_controller      = GdbController()
    session_state       = SessionState()
    pwndbg_tools        = PwndbgTools(gdb_controller, session_state)
    subprocess_tools    = SubprocessTools()
    git_tools           = GitTools()
    python_tools        = PythonTools()
    retdec_analyzer     = RetDecAnalyzer()
    
    # Initialize GDB with pwndbg
    init_result = gdb_controller.initialize()
    logger.info(f"GDB initialization: {init_result['status']}")
    logger.info("RetDec analyzer created (lazy initialization)")
    
    async with mcp.session_manager.run():
        yield  
    
    # Cleanup on shutdown
    logger.info("Shutting down Pwno MCP server...")
    if gdb_controller:
        gdb_controller.close()


# Create FastMCP instance with authentication (lifespan handled by FastAPI)
mcp = FastMCP(
    name="pwno-mcp",
    # auth=auth_settings,
    # auth_server_provider=auth_provider
)
mcp.settings.host = "0.0.0.0"
mcp.settings.port = 5500

@mcp.tool()
async def execute(command: str) -> str:
    """
    Execute arbitrary GDB/pwndbg command.

    :param command: GDB command to execute
    :returns: Command output and state information
    """
    # Access token is available via get_access_token() if needed
    # token = get_access_token().token if get_access_token() else None
    result = pwndbg_tools.execute(command)
    return format_execute_result(result)


@mcp.tool()
async def set_file(binary_path: str) -> str:
    """
    Load a binary file for debugging.

    :param binary_path: Path to the binary to load
    :returns: Loading status and binary information
    """
    result = pwndbg_tools.set_file(binary_path)
    return format_file_result(result)


@mcp.tool()
async def attach(pid: int) -> str:
    """
    Attach to an existing process by PID.

    :param pid: Process ID to attach to
    :returns: Attach status and initial context if stopped
    """
    result = pwndbg_tools.attach(pid)
    # Reuse step-style formatter to include state and context if present
    return format_step_result(result)


@mcp.tool()
async def run(args: str = "", start: bool = False) -> str:
    """
    Run the loaded binary.
    
    Requires at least one enabled breakpoint to be set before running.

    :param args: Arguments to pass to the binary
    :param start: Optional - stop at program entry (equivalent to --start)
    :returns: Execution results and state
    """
    result = pwndbg_tools.run(args, start)
    return format_launch_result(result)


@mcp.tool()
async def step_control(command: str) -> str:
    """
    Execute stepping commands (continue, next, step, nexti, stepi).

    :param command: Stepping command (c, n, s, ni, si or full name)
    :returns: Execution results and new state
    """
    result = pwndbg_tools.step_control(command)
    return format_step_result(result)


@mcp.tool()
async def finish() -> str:
    """
    Run until the current function returns.

    :returns: Execution results and new state
    """
    result = pwndbg_tools.finish()
    return format_step_result(result)


@mcp.tool()
async def jump(locspec: str) -> str:
    """
    Resume execution at the specified location.

    :param locspec: Location specification (e.g., "main", "file.c:123", "*0x401000")
    :returns: Execution results and state
    """
    result = pwndbg_tools.jump(locspec)
    return format_step_result(result)


@mcp.tool()
async def return_from_function() -> str:
    """
    Make the current function return immediately.

    :returns: Execution results and state
    """
    result = pwndbg_tools.return_from_function()
    return format_step_result(result)


@mcp.tool()
async def until(locspec: Optional[str] = None) -> str:
    """
    Run until a specified location, or the next source line if none provided.

    :param locspec: Optional location specification (e.g., "file.c:45")
    :returns: Execution results and state
    """
    result = pwndbg_tools.until(locspec)
    return format_step_result(result)


@mcp.tool()
async def get_context(context_type: str = "all") -> str:
    """
    Get debugging context (registers, stack, disassembly, code, backtrace).

    :param context_type: Type of context (all, regs, stack, disasm, code, backtrace)
    :returns: Requested context information
    """
    result = pwndbg_tools.get_context(context_type)
    return format_context_result(result)


@mcp.tool()
async def set_breakpoint(location: str, condition: Optional[str] = None) -> str:
    """
    Set a breakpoint at the specified location.

    :param location: Address or symbol for breakpoint
    :param condition: Optional breakpoint condition
    :returns: Breakpoint information
    """
    result = pwndbg_tools.set_breakpoint(location, condition)
    return format_breakpoint_result(result)


@mcp.tool()
async def get_memory(
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
async def get_session_info() -> str:
    """
    Get current debugging session information.

    :returns: Session state and debugging artifacts
    """
    result = pwndbg_tools.get_session_info()
    return format_session_result(result)


@mcp.tool()
async def run_command(command: str, cwd: Optional[str] = None, timeout: float = 30.0) -> str:
    """
    Execute a system command and wait for completion.
    **Do not use this to run targeted binaries**
    
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
async def spawn_process(command: str, cwd: Optional[str] = None) -> str:
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
async def get_process(pid: int) -> str:
    """
    Get status of a spawned process, including stdout and stderr output or paths.

    :param pid: Process ID to check
    :returns: Process status and outputs
    """
    result = subprocess_tools.get_process(pid)
    return json.dumps(result, indent=2)


@mcp.tool()
async def kill_process(pid: int, signal: int = 15) -> str:
    """
    Kill a process.

    :param pid: Process ID to kill
    :param signal: Signal to send (15=SIGTERM, 9=SIGKILL)
    :returns: Kill operation result
    """
    result = subprocess_tools.kill_process(pid, signal)
    return json.dumps(result, indent=2)


@mcp.tool()
async def list_processes() -> str:
    """
    List all tracked background processes.

    :returns: List of running background processes
    """
    result = subprocess_tools.list_processes()
    return json.dumps(result, indent=2)


@mcp.tool()
async def fetch_repo(
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
async def execute_python_script(
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
async def execute_python_code(
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
async def execute_python_code_bg(
    code: str,
    cwd: Optional[str] = None
) -> str:
    """
    Execute Python code in the background (decoupled execution).

    This writes the code to a temporary script and spawns it using the
    shared Python environment. Returns immediately with PID and log paths.

    :param code: Python code to execute
    :param cwd: Working directory for execution (default: /workspace)
    :returns: JSON with pid, stdout/stderr file paths, and status
    """
    if cwd is None:
        cwd = DEFAULT_WORKSPACE
    # Create a temp script and spawn via subprocess tools to unify tracking
    script_path = python_tools.create_temp_script(code)
    python_exe = python_tools.get_python_executable()
    cmd = f"{python_exe} {script_path}"
    result = subprocess_tools.spawn_process(cmd, cwd=cwd)
    # Include the temp script path so callers can manage/cleanup if desired
    result["script_path"] = script_path
    return json.dumps(result, indent=2)


@mcp.tool()
async def install_python_packages(
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
async def list_python_packages() -> str:
    """
    List installed packages in the shared Python environment.

    :returns: List of installed packages
    """
    result = python_tools.get_installed_packages()
    return json.dumps(result, indent=2)


@mcp.tool()
async def get_retdec_status() -> str:
    """
    Get the status of RetDec binary analysis.
    
    Returns information about whether a binary was analyzed.
    Will automatically initialize analysis on first call if BINARY_URL is set.

    :returns: RetDec analysis status information
    """
    if not retdec_analyzer:
        return json.dumps({
            "status": "not_initialized",
            "message": "RetDec analyzer not initialized"
        }, indent=2)
    
    # Lazy initialization on first use
    if not retdec_analyzer._initialized:
        logger.info("Performing lazy initialization of RetDec analyzer")
        await retdec_analyzer.initialize()
    
    status = retdec_analyzer.get_status()
    return json.dumps(status, indent=2)


@mcp.tool()
async def get_decompiled_code() -> str:
    """
    Get the decompiled C code from RetDec analysis.
    
    Returns the decompiled code if analysis was successful,
    or an error message if analysis failed or was not performed.
    Will automatically initialize analysis on first call if BINARY_URL is set.

    :returns: Decompiled C code or error information
    """
    if not retdec_analyzer:
        return json.dumps({
            "status": "error",
            "message": "RetDec analyzer not initialized"
        }, indent=2)
    
    # Lazy initialization on first use
    if not retdec_analyzer._initialized:
        logger.info("Performing lazy initialization of RetDec analyzer")
        await retdec_analyzer.initialize()
    
    code = retdec_analyzer.get_decompiled_code()
    
    if code:
        return json.dumps({
            "status": "success",
            "decompiled_code": code
        }, indent=2)
    else:
        # Get status to provide more information about why code is not available
        status = retdec_analyzer.get_status()
        return json.dumps({
            "status": "unavailable",
            "reason": status.get("status"),
            "details": status
        }, indent=2)


# Create FastAPI app with proper lifespan
app = FastAPI(lifespan=lifespan)

# Health check endpoint (no authentication required)

@app.get("/")
async def root():
    return {"message": "Pwno MCP Server"}

@app.get("/health")
async def health_check():
    """
    Health check endpoint for monitoring.
    This endpoint does not require authentication.
    """
    health_status = {
        "status": "healthy",
        "server": "pwno-mcp",
        "version": "1.0.0",
        "workspace": {
            "path": DEFAULT_WORKSPACE,
            "exists": os.path.exists(DEFAULT_WORKSPACE)
        },
        "authentication": {
            "enabled": auth_provider.is_auth_enabled
        },
        "components": {}
    }
    
    # Check GDB responsiveness
    if gdb_controller:
        try:
            # Check if GDB controller is initialized
            health_status["components"]["gdb_initialized"] = gdb_controller._initialized
            health_status["components"]["gdb_state"] = gdb_controller.get_state()
        except Exception as e:
            health_status["components"]["gdb_error"] = str(e)
            health_status["status"] = "degraded"
    
    # Check active subprocess count
    if subprocess_tools:
        try:
            active_processes = len(subprocess_tools.background_processes)
            health_status["active_processes"] = active_processes
        except:
            health_status["active_processes"] = 0
    
    return health_status

# Mount MCP app
app.mount("/", mcp.streamable_http_app())

def run_server():
    uvicorn.run(app, host="0.0.0.0", port=5500)


if __name__ == "__main__":
    run_server() 