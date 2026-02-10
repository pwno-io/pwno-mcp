import logging
import json
import os
import shlex
from typing import Optional, Dict, Any, Tuple, List
from functools import wraps
import time

from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP

from pwnomcp.gdb import GdbController
from pwnomcp.state import SessionState
from pwnomcp.tools import PwndbgTools, SubprocessTools, GitTools, PythonTools
from pwnomcp.utils.auth.handler import NonceAuthProvider, create_auth_settings
from pwnomcp.retdec.retdec import RetDecAnalyzer
from pwnomcp.pwnpipe import PwnPipe

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Default workspace directory for command execution
DEFAULT_WORKSPACE = "/workspace"

# Shared runtime context set by the server during startup
gdb_controller: Optional[GdbController] = None
session_state: Optional[SessionState] = None
pwndbg_tools: Optional[PwndbgTools] = None
subprocess_tools: Optional[SubprocessTools] = None
git_tools: Optional[GitTools] = None
python_tools: Optional[PythonTools] = None
retdec_analyzer: Optional[RetDecAnalyzer] = None
current_pwnpipe: Optional[PwnPipe] = None

# Authentication (not currently enabled for FastMCP)
auth_provider = NonceAuthProvider()
auth_settings = create_auth_settings()


def set_runtime_context(
    gdb: GdbController,
    session: SessionState,
    pwndbg: PwndbgTools,
    subprocess_: SubprocessTools,
    git_: GitTools,
    python_: PythonTools,
    retdec: RetDecAnalyzer,
) -> None:
    global gdb_controller, session_state, pwndbg_tools, subprocess_tools, git_tools, python_tools, retdec_analyzer
    gdb_controller = gdb
    session_state = session
    pwndbg_tools = pwndbg
    subprocess_tools = subprocess_
    git_tools = git_
    python_tools = python_
    retdec_analyzer = retdec


# Create FastMCP instance (FastAPI app and lifespan managed by server)
mcp = FastMCP(
    name="pwno-mcp",
    host="0.0.0.0",
    port=5500,
    streamable_http_path="/debug",
    # auth=auth_settings,
    # auth_server_provider=auth_provider
)


def catch_errors(tuple_on_error: bool = False):
    def decorator(fn):
        @wraps(fn)
        async def wrapper(*args, **kwargs):
            try:
                return await fn(*args, **kwargs)
            except Exception as e:
                logger.exception("tool error in %s", fn.__name__)
                if tuple_on_error:
                    return {
                        "success": False,
                        "error": str(e),
                        "type": type(e).__name__,
                    }, []
                return {"success": False, "error": str(e), "type": type(e).__name__}

        return wrapper

    return decorator


@mcp.tool()
@catch_errors()
async def execute(command: str) -> Dict[str, Any]:
    """Execute an arbitrary GDB/pwndbg command.

    Args:
        command: Raw GDB/pwndbg command to execute (e.g., "info registers", "vmmap").

    Returns:
        Dict containing the raw MI/console responses, a success flag, and the current GDB state.
    """
    return pwndbg_tools.execute(command)


@mcp.tool()
@catch_errors()
async def pwncli(file: str, argument: str = "") -> Dict[str, Any]:
    """Run a pwncli exploit script via uv and manage its I/O through a global PwnPipe.

    Behavior:
    - Writes the provided script content to /workspace/exp.py
    - Launches: uv run /workspace/exp.py debug /workspace/target <argument>
    - Maintains a single global PwnPipe to stream stdout/stderr and accept stdin
    - Detects a single-line marker printed by pwncli after attach:
      "PWNCLI_ATTACH_RESULT:{...json...}" and exposes it as attachment.result

    Args:
        file: The full contents of a pwncli-style Python script that calls cli_script(). (e.g., interacting I/O with `sa()`, with binary using `ia()`)
        argument: Additional pwncli arguments after "debug /workspace/target" (e.g., "-vv -b malloc").

    Returns:
        {
          "io": {
            "pipeinput": bool,    # whether stdin is available
            "pipeoutput": bool,   # whether output collection succeeded for this call
            "current_output": str # any currently buffered output consumed by this call
          },
          "attachment": {
            "result": dict | None # parsed attach result from the marker if present
          }
        }
    """
    global current_pwnpipe
    # Write script to /workspace/exp.py
    os.makedirs(DEFAULT_WORKSPACE, exist_ok=True)
    script_path = os.path.join(DEFAULT_WORKSPACE, "exp.py")
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(file)

    # Kill previous pipe if alive
    if current_pwnpipe and current_pwnpipe.is_alive():
        current_pwnpipe.kill()
    current_pwnpipe = None

    # Build command and start
    cmd = f"uv run {script_path} debug {os.path.join(DEFAULT_WORKSPACE, 'target')} {argument}".strip()
    pipe = PwnPipe(command=cmd, cwd=DEFAULT_WORKSPACE, env={"PYTHONUNBUFFERED": "1"})
    current_pwnpipe = pipe

    # Read whatever is available immediately
    time.sleep(3)  # FIXME:
    output = pipe.release()
    attach_result = pipe.get_attach_result()

    return {
        "io": {
            "pipeinput": True,
            "pipeoutput": True,
            "current_output": output,
        },
        "attachment": {
            "result": attach_result,
        },
    }


@mcp.tool()
@catch_errors()
async def sendinput(data: str) -> Dict[str, Any]:
    """Send raw input to the active pwncli process' stdin via PwnPipe.

    Important:
        This call does not append a newline. If the target expects a line, include "\\n" yourself.

    Args:
        data: Raw text to write to stdin.

    Returns:
        { "success": bool } indicating whether the input was written successfully.
    """
    if not current_pwnpipe or not current_pwnpipe.is_alive():
        return {"success": False, "error": "No active PwnPipe"}
    ok = current_pwnpipe.send(data)
    return {"success": bool(ok)}


@mcp.tool()
@catch_errors()
async def checkoutput() -> Dict[str, Any]:
    """Release and return accumulated output from the active PwnPipe.

    Returns:
        { "success": True, "output": str } on success, or a failure object when no pipe exists.
        The internal buffer is cleared by this call (subsequent calls only return new output).
    """
    if not current_pwnpipe:
        return {"success": False, "error": "No active PwnPipe"}
    out = current_pwnpipe.release()
    return {"success": True, "output": out}


@mcp.tool()
@catch_errors()
async def set_file(binary_path: str) -> Dict[str, Any]:
    """Load an executable file into GDB/pwndbg for debugging.

    Args:
        binary_path: Absolute path to the ELF to debug.

    Returns:
        Dict with MI command responses and state.
    """
    return pwndbg_tools.set_file(binary_path)


@mcp.tool()
@catch_errors(tuple_on_error=True)
async def attach(pid: int) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Attach to an existing process by PID using GDB/MI.

    Args:
        pid: Target process ID to attach to.

    Returns:
        (result, context) where result is the MI attach result and context is a list of
        quick context snapshots (e.g., backtrace/heap) captured immediately after attach.
    """
    result, context = pwndbg_tools.attach(pid)
    return result, context


@mcp.tool()
@catch_errors()
async def run(args: str = "", start: bool = False) -> Dict[str, Any]:
    """Run the loaded program under GDB control.

    Args:
        args: Argument string passed to the inferior.
        start: If True, stop at the program entry (equivalent to --start).

    Returns:
        MI run/continue results and state.
    """
    return pwndbg_tools.run(args, start)


@mcp.tool()
@catch_errors()
async def step_control(command: str) -> Dict[str, Any]:
    """Execute a stepping command (c, n, s, ni, si).

    Args:
        command: One of {c, n, s, ni, si} or their long forms.

    Returns:
        Dict with MI responses and state.
    """
    return pwndbg_tools.step_control(command)


@mcp.tool()
@catch_errors()
async def finish() -> Dict[str, Any]:
    """Run until the current function returns (MI -exec-finish)."""
    return pwndbg_tools.finish()


@mcp.tool()
@catch_errors()
async def jump(locspec: str) -> Dict[str, Any]:
    """Resume execution at a specified location (MI -exec-jump).

    Args:
        locspec: Location such as a symbol name, file:line, or address (*0x... ).
    """
    return pwndbg_tools.jump(locspec)


@mcp.tool()
@catch_errors()
async def return_from_function() -> Dict[str, Any]:
    """Force the current function to return immediately (MI -exec-return)."""
    return pwndbg_tools.return_from_function()


@mcp.tool()
@catch_errors()
async def until(locspec: Optional[str] = None) -> Dict[str, Any]:
    """Run until a specified location or next source line (MI -exec-until)."""
    return pwndbg_tools.until(locspec)


@mcp.tool()
@catch_errors()
async def get_context(context_type: str = "all") -> Dict[str, Any]:
    """Get the current debugging context.

    Args:
        context_type: "all" for a quick MI snapshot, or one of {regs, stack, disasm, code, backtrace}
                      to request a specific pwndbg context.
    """
    return pwndbg_tools.get_context(context_type)


@mcp.tool()
@catch_errors()
async def set_breakpoint(
    location: str, condition: Optional[str] = None
) -> Dict[str, Any]:
    """Set a breakpoint using MI (-break-insert).

    Args:
        location: Breakpoint location (symbol/address/file:line).
        condition: Optional breakpoint condition expression.
    """
    return pwndbg_tools.set_breakpoint(location, condition)


@mcp.tool()
@catch_errors()
async def get_memory(
    address: str, size: int = 64, format: str = "hex"
) -> Dict[str, Any]:
    """Read memory at the specified address.

    Args:
        address: Start address expression (e.g., "$rsp", "0xdeadbeef").
        size: Number of bytes to read.
        format: "hex" for raw bytes (fast path), "string" for x/s, otherwise MI grid format.
    """
    return pwndbg_tools.get_memory(address, size, format)


@mcp.tool()
@catch_errors()
async def get_session_info() -> Dict[str, Any]:
    """Return current session info (session state + GDB state) without issuing new GDB commands."""
    return pwndbg_tools.get_session_info()


@mcp.tool()
async def run_command(
    command: str, cwd: Optional[str] = None, timeout: float = 30.0
) -> str:
    """Execute a system command and wait for completion.

    Note:
        Do not use this to run the target binary under analysis; use the dedicated tools instead.

    Args:
        command: Shell command to run.
        cwd: Working directory (defaults to /workspace).
        timeout: Timeout in seconds.

    Returns:
        JSON string with stdout/stderr/exit code.
    """
    if cwd is None:
        cwd = DEFAULT_WORKSPACE
    result = subprocess_tools.run_command(command, cwd=cwd, timeout=timeout)
    return json.dumps(result, indent=2)


@mcp.tool()
async def spawn_process(command: str, cwd: Optional[str] = None) -> str:
    """Spawn a long-running background process and return its PID and log paths.

    Args:
        command: Shell command to spawn.
        cwd: Working directory (defaults to /workspace).
    """
    if cwd is None:
        cwd = DEFAULT_WORKSPACE
    result = subprocess_tools.spawn_process(command, cwd=cwd)
    return json.dumps(result, indent=2)


@mcp.tool()
async def get_process(pid: int) -> str:
    """Get information about a tracked background process by PID."""
    result = subprocess_tools.get_process(pid)
    return json.dumps(result, indent=2)


@mcp.tool()
async def kill_process(pid: int, signal: int = 15) -> str:
    """Send a signal to a tracked background process (default SIGTERM=15)."""
    result = subprocess_tools.kill_process(pid, signal)
    return json.dumps(result, indent=2)


@mcp.tool()
async def list_processes() -> str:
    """List all tracked background processes and their metadata (PID, command, log paths)."""
    result = subprocess_tools.list_processes()
    return json.dumps(result, indent=2)


@mcp.tool()
async def fetch_repo(
    repo_url: str,
    version: Optional[str] = None,
    target_dir: Optional[str] = None,
    shallow: bool = True,
) -> str:
    """Fetch a git repository into /workspace.

    Args:
        repo_url: Repository URL (https or ssh).
        version: Branch/tag/commit to checkout (None = default branch).
        target_dir: Optional specific directory; defaults to a name derived from the URL.
        shallow: Whether to clone shallowly.
    """
    if target_dir and not os.path.isabs(target_dir):
        target_dir = os.path.join(DEFAULT_WORKSPACE, target_dir)
    elif not target_dir:
        repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        target_dir = os.path.join(DEFAULT_WORKSPACE, repo_name)
    result = git_tools.fetch_repo(repo_url, version, target_dir, shallow)
    return json.dumps(result, indent=2)


@mcp.tool()
async def execute_python_script(
    script_path: str,
    args: Optional[str] = None,
    cwd: Optional[str] = None,
    timeout: float = 300.0,
) -> str:
    """Execute an existing Python script within the shared environment.

    Args:
        script_path: Path to the script.
        args: Space-separated args for the script.
        cwd: Working directory (default /workspace).
        timeout: Seconds to wait before termination.
    """
    if cwd is None:
        cwd = DEFAULT_WORKSPACE
    args_list = args.split() if args else None
    result = python_tools.execute_script(script_path, args_list, cwd, timeout)
    return json.dumps(result, indent=2)


@mcp.tool()
async def execute_python_code(
    code: str, cwd: Optional[str] = None, timeout: float = 300.0
) -> str:
    """Execute Python code dynamically in the shared environment.

    Args:
        code: Python source code to run.
        cwd: Working directory (default /workspace).
        timeout: Seconds to wait before termination.
    """
    if cwd is None:
        cwd = DEFAULT_WORKSPACE
    result = python_tools.execute_code(code, cwd, timeout)
    return json.dumps(result, indent=2)


@mcp.tool()
async def install_python_packages(packages: str, upgrade: bool = False) -> str:
    """Install additional Python packages using the shared package manager (uv).

    Args:
        packages: Space-separated package list.
        upgrade: If True, perform upgrades when applicable.
    """
    packages_list = packages.split()
    result = python_tools.install_packages(packages_list, upgrade)
    return json.dumps(result, indent=2)


@mcp.tool()
async def list_python_packages() -> str:
    """List all packages installed in the shared Python environment."""
    result = python_tools.get_installed_packages()
    return json.dumps(result, indent=2)


@mcp.tool()
async def get_retdec_status() -> str:
    """Get the current RetDec decompilation status, lazily initializing as needed."""
    if not retdec_analyzer:
        return json.dumps(
            {"status": "not_initialized", "message": "RetDec analyzer not initialized"},
            indent=2,
        )
    if not retdec_analyzer._initialized:
        logger.info("Performing lazy initialization of RetDec analyzer")
        await retdec_analyzer.initialize()
    status = retdec_analyzer.get_status()
    return json.dumps(status, indent=2)


@mcp.tool()
async def get_decompiled_code() -> str:
    """Return RetDec decompiled C code if available, or a status describing why not."""
    if not retdec_analyzer:
        return json.dumps(
            {"status": "error", "message": "RetDec analyzer not initialized"}, indent=2
        )
    if not retdec_analyzer._initialized:
        logger.info("Performing lazy initialization of RetDec analyzer")
        await retdec_analyzer.initialize()
    code = retdec_analyzer.get_decompiled_code()
    if code:
        return json.dumps({"status": "success", "decompiled_code": code}, indent=2)
    else:
        status = retdec_analyzer.get_status()
        return json.dumps(
            {
                "status": "unavailable",
                "reason": status.get("status"),
                "details": status,
            },
            indent=2,
        )


def get_mcp_app() -> FastAPI:
    return mcp
