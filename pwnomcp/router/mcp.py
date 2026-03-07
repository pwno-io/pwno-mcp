import logging
import json
import os
import shlex
import time
from typing import Optional, Dict, Any, Tuple, List
from functools import wraps
import threading

from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP

from pwnomcp.gdb import GdbController
from pwnomcp.state import DebugSession, DebugSessionRegistry, SessionState
from pwnomcp.tools import PwndbgTools, SubprocessTools, GitTools, PythonTools
from pwnomcp.utils.auth.handler import NonceAuthProvider, create_auth_settings
from pwnomcp.utils.paths import (
    DEFAULT_WORKSPACE,
    RuntimePaths,
    resolve_workspace_cwd,
    resolve_workspace_path,
)
from pwnomcp.retdec.retdec import RetDecAnalyzer
from pwnomcp.pwnpipe import PwnPipe

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Shared runtime context set by the server during startup
gdb_controller: Optional[GdbController] = None
session_state: Optional[SessionState] = None
pwndbg_tools: Optional[PwndbgTools] = None
session_registry: Optional[DebugSessionRegistry] = None
default_session_id: Optional[str] = None
runtime_paths: Optional[RuntimePaths] = None
subprocess_tools: Optional[SubprocessTools] = None
git_tools: Optional[GitTools] = None
python_tools: Optional[PythonTools] = None
retdec_analyzer: Optional[RetDecAnalyzer] = None
pwnpipe_sessions: Dict[str, PwnPipe] = {}
_pwnpipe_lock = threading.Lock()

# Authentication (not currently enabled for FastMCP)
auth_provider = NonceAuthProvider()
auth_settings = create_auth_settings()


def set_runtime_context(
    session_registry_: DebugSessionRegistry,
    default_session_id_: str,
    subprocess_: SubprocessTools,
    git_: GitTools,
    python_: PythonTools,
    retdec: RetDecAnalyzer,
    runtime_paths_: RuntimePaths,
) -> None:
    global gdb_controller, session_state, pwndbg_tools
    global subprocess_tools, git_tools, python_tools, retdec_analyzer
    global session_registry, default_session_id, runtime_paths
    global pwnpipe_sessions

    session_registry = session_registry_
    default_session_id = default_session_id_
    runtime_paths = runtime_paths_

    default_session = session_registry.ensure_session(default_session_id)
    gdb_controller = default_session.gdb
    session_state = default_session.state
    pwndbg_tools = default_session.tools
    subprocess_tools = subprocess_
    git_tools = git_
    python_tools = python_
    retdec_analyzer = retdec
    pwnpipe_sessions = {}


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


def _require_session_registry() -> DebugSessionRegistry:
    if not session_registry:
        raise RuntimeError("Debug session registry not initialized")
    return session_registry


def _resolve_debug_session(
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
    create_if_missing: bool = True,
) -> DebugSession:
    registry = _require_session_registry()

    if process_id is not None:
        found = registry.get_session_for_pid(process_id)
        if found:
            return found
        if session_id is None and not create_if_missing:
            raise RuntimeError(
                f"No debug session found for process_id={process_id}. "
                "Pass a valid session_id or create a new session."
            )

    if session_id is not None:
        existing = registry.get_session(session_id)
        if existing:
            return existing
        if not create_if_missing:
            raise RuntimeError(f"Debug session '{session_id}' not found")
        return registry.create_session(session_id)

    if not create_if_missing:
        raise RuntimeError("session_id is required")
    return registry.ensure_session(default_session_id)


def _sync_session_pid(session: DebugSession) -> None:
    pid = session.gdb.get_inferior_pid() or session.state.pid
    _require_session_registry().register_inferior_pid(session.session_id, pid)


def _resolve_binary_path(
    binary_path: Optional[str],
    session: DebugSession,
    require_exists: bool = True,
) -> str:
    if binary_path:
        return resolve_workspace_path(
            binary_path,
            workspace_root=DEFAULT_WORKSPACE,
            require_exists=require_exists,
            kind="binary_path",
        )

    if session.state.binary_path:
        return resolve_workspace_path(
            session.state.binary_path,
            workspace_root=DEFAULT_WORKSPACE,
            require_exists=require_exists,
            kind="binary_path",
        )

    fallback = os.path.join(DEFAULT_WORKSPACE, "target")
    if os.path.exists(fallback):
        return fallback
    raise RuntimeError(
        "No binary selected. Provide binary_path or call set_file first. "
        "Binaries are expected under /workspace."
    )


def _resolve_pipe_session_id(
    session_id: Optional[str], process_id: Optional[int]
) -> str:
    if session_id is None and process_id is None:
        return _resolve_debug_session(create_if_missing=True).session_id
    session = _resolve_debug_session(
        session_id=session_id, process_id=process_id, create_if_missing=False
    )
    return session.session_id


def _get_pwnpipe(
    session_id: Optional[str] = None, process_id: Optional[int] = None
) -> Tuple[str, PwnPipe]:
    resolved_session_id = _resolve_pipe_session_id(session_id, process_id)
    with _pwnpipe_lock:
        pipe = pwnpipe_sessions.get(resolved_session_id)
        if not pipe:
            raise RuntimeError(
                f"No active pwncli session for session_id='{resolved_session_id}'"
            )
        return resolved_session_id, pipe


@mcp.tool()
@catch_errors()
async def create_debug_session(session_id: Optional[str] = None) -> Dict[str, Any]:
    """Create or return a debug session by id."""
    session = _resolve_debug_session(session_id=session_id, create_if_missing=True)
    return {"success": True, "session": session.to_dict()}


@mcp.tool()
@catch_errors()
async def list_debug_sessions() -> Dict[str, Any]:
    """List all active debug sessions and metadata."""
    sessions = _require_session_registry().list_sessions()
    return {"success": True, "count": len(sessions), "sessions": sessions}


@mcp.tool()
@catch_errors()
async def close_debug_session(session_id: str) -> Dict[str, Any]:
    """Close an active debug session and stop any attached pwncli driver."""
    with _pwnpipe_lock:
        pipe = pwnpipe_sessions.pop(session_id, None)
    if pipe:
        pipe.kill()

    result = _require_session_registry().close_session(session_id)
    return result


@mcp.tool()
@catch_errors()
async def execute(
    command: str,
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Execute an arbitrary GDB/pwndbg command.

    Args:
        command: Raw GDB/pwndbg command to execute (e.g., "info registers", "vmmap").

    Returns:
        Dict containing the raw MI/console responses, a success flag, and the current GDB state.
    """
    session = _resolve_debug_session(session_id=session_id, process_id=process_id)
    with session.lock:
        result = session.tools.execute(command)
        _sync_session_pid(session)
    result["session_id"] = session.session_id
    return result


@mcp.tool()
@catch_errors()
async def pwncli(
    file: str,
    argument: str = "",
    wait_timeout: float = 3.0,
    binary_path: Optional[str] = None,
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Run a pwncli exploit script for a specific debug session.

    Behavior:
    - Writes the provided script content to a per-session runtime directory
    - Launches: uv run <session-script> debug <resolved binary> <argument>
    - Maintains one PwnPipe per debug session
    - Detects a single-line marker printed by pwncli after attach:
      "PWNCLI_ATTACH_RESULT:{...json...}" and exposes it as attachment.result
    - Waits up to wait_timeout seconds for attach/output/exit before returning

    Args:
        file: Full contents of a pwncli-style Python script.
        argument: Additional pwncli arguments after "debug <binary>".
        wait_timeout: Max time (seconds) to wait for initial attach/output/exit signal.
        binary_path: Optional target binary path (resolved under /workspace).
        session_id: Optional debug session id.
        process_id: Optional driver/inferior pid to look up the session.

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
    session = _resolve_debug_session(session_id=session_id, process_id=process_id)
    resolved_binary = _resolve_binary_path(binary_path, session, require_exists=True)

    runtime_dir = session.runtime_dir
    os.makedirs(runtime_dir, exist_ok=True)
    script_path = os.path.join(runtime_dir, f"exp_{int(time.time() * 1000)}.py")
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(file)

    replaced = False
    old_pipe: Optional[PwnPipe] = None
    with _pwnpipe_lock:
        old_pipe = pwnpipe_sessions.get(session.session_id)
        if old_pipe and old_pipe.is_alive():
            replaced = True
        pwnpipe_sessions.pop(session.session_id, None)

        cmd = (
            f"uv run {shlex.quote(script_path)} debug {shlex.quote(resolved_binary)} {argument}"
        ).strip()
        pipe = PwnPipe(
            command=cmd,
            cwd=os.path.dirname(resolved_binary),
            env={"PYTHONUNBUFFERED": "1"},
        )
        pwnpipe_sessions[session.session_id] = pipe

    if old_pipe and old_pipe.is_alive():
        old_pipe.kill()

    startup = pipe.wait_ready(timeout=wait_timeout)
    output = pipe.release()
    attach_result = pipe.get_attach_result()
    driver_pid = pipe.get_pid()
    if driver_pid is not None:
        _require_session_registry().register_driver_pid(session.session_id, driver_pid)

    return {
        "session_id": session.session_id,
        "runtime_dir": runtime_dir,
        "binary_path": resolved_binary,
        "io": {
            "pipeinput": True,
            "pipeoutput": True,
            "current_output": output,
        },
        "attachment": {
            "result": attach_result,
        },
        "startup": {
            "ready": startup.get("ready"),
            "reason": startup.get("reason"),
            "wait_ms": startup.get("wait_ms"),
            "alive": pipe.is_alive(),
            "pid": driver_pid,
            "replaced": replaced,
        },
    }


@mcp.tool()
@catch_errors()
async def sendinput(
    data: str,
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Send raw input to a session-scoped pwncli process stdin.

    Important:
        This call does not append a newline. If the target expects a line, include "\\n" yourself.

    Args:
        data: Raw text to write to stdin.

    Returns:
        { "success": bool } indicating whether the input was written successfully.
    """
    resolved_session_id, pipe = _get_pwnpipe(
        session_id=session_id, process_id=process_id
    )
    with _pwnpipe_lock:
        if not pipe.is_alive():
            return {
                "success": False,
                "session_id": resolved_session_id,
                "error": "No active PwnPipe",
            }
        ok = pipe.send(data)
    return {"success": bool(ok), "session_id": resolved_session_id}


@mcp.tool()
@catch_errors()
async def checkoutput(
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Release and return accumulated output from a session PwnPipe.

    Returns:
        { "success": True, "output": str } on success, or a failure object when no pipe exists.
        The internal buffer is cleared by this call (subsequent calls only return new output).
    """
    resolved_session_id, pipe = _get_pwnpipe(
        session_id=session_id, process_id=process_id
    )
    with _pwnpipe_lock:
        out = pipe.release()
    return {"success": True, "session_id": resolved_session_id, "output": out}


@mcp.tool()
@catch_errors()
async def checkevents(
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Release and return structured events from a session PwnPipe.

    Returns:
        {"success": True, "events": [...], "alive": bool, "exit_code": int|None}
    """
    resolved_session_id, pipe = _get_pwnpipe(
        session_id=session_id, process_id=process_id
    )
    with _pwnpipe_lock:
        events = pipe.release_events()
        alive = pipe.is_alive()
        exit_code = pipe.get_exit_code()
        driver_pid = pipe.get_pid()
    return {
        "success": True,
        "session_id": resolved_session_id,
        "driver_pid": driver_pid,
        "events": events,
        "alive": alive,
        "exit_code": exit_code,
    }


@mcp.tool()
@catch_errors()
async def pwncli_stop(
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Stop a pwncli driver session and clear its session pipe."""
    resolved_session_id = _resolve_pipe_session_id(
        session_id=session_id, process_id=process_id
    )
    with _pwnpipe_lock:
        pipe = pwnpipe_sessions.pop(resolved_session_id, None)
        if not pipe:
            return {
                "success": False,
                "session_id": resolved_session_id,
                "error": "No active PwnPipe",
            }
        was_alive = pipe.is_alive()
        exit_code = pipe.get_exit_code()
        pid = pipe.get_pid()
        pipe.kill()
    if pid is not None:
        _require_session_registry().unregister_driver_pid(pid)
    return {
        "success": True,
        "session_id": resolved_session_id,
        "was_alive": was_alive,
        "exit_code": exit_code,
    }


@mcp.tool()
@catch_errors()
async def list_pwncli_sessions() -> Dict[str, Any]:
    """List all active pwncli driver sessions."""
    sessions: List[Dict[str, Any]] = []
    with _pwnpipe_lock:
        for sid, pipe in pwnpipe_sessions.items():
            sessions.append(
                {
                    "session_id": sid,
                    "driver_pid": pipe.get_pid(),
                    "alive": pipe.is_alive(),
                    "exit_code": pipe.get_exit_code(),
                }
            )
    return {"success": True, "count": len(sessions), "sessions": sessions}


@mcp.tool()
@catch_errors()
async def set_file(
    binary_path: str,
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Load an executable file into GDB/pwndbg for debugging.

    Args:
        binary_path: Absolute path to the ELF to debug.

    Returns:
        Dict with MI command responses and state.
    """
    session = _resolve_debug_session(session_id=session_id, process_id=process_id)
    resolved_binary = _resolve_binary_path(binary_path, session, require_exists=True)
    with session.lock:
        result = session.tools.set_file(resolved_binary)
        _sync_session_pid(session)
    result["session_id"] = session.session_id
    result["binary_path"] = resolved_binary
    return result


@mcp.tool()
@catch_errors(tuple_on_error=True)
async def attach(
    pid: int,
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Attach to an existing process by PID using GDB/MI.

    Args:
        pid: Target process ID to attach to.

    Returns:
        (result, context) where result is the MI attach result and context is a list of
        quick context snapshots (e.g., backtrace/heap) captured immediately after attach.
    """
    session = _resolve_debug_session(session_id=session_id, process_id=process_id)
    with session.lock:
        result, context = session.tools.attach(pid)
        _sync_session_pid(session)
    result["session_id"] = session.session_id
    return result, context


@mcp.tool()
@catch_errors()
async def run(
    args: str = "",
    start: bool = False,
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Run the loaded program under GDB control.

    Args:
        args: Argument string passed to the inferior.
        start: If True, stop at the program entry (equivalent to --start).

    Returns:
        MI run/continue results and state.
    """
    session = _resolve_debug_session(session_id=session_id, process_id=process_id)
    with session.lock:
        result = session.tools.run(args, start)
        _sync_session_pid(session)
    result["session_id"] = session.session_id
    return result


@mcp.tool()
@catch_errors()
async def step_control(
    command: str,
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Execute a stepping command (c, n, s, ni, si).

    Args:
        command: One of {c, n, s, ni, si} or their long forms.

    Returns:
        Dict with MI responses and state.
    """
    session = _resolve_debug_session(session_id=session_id, process_id=process_id)
    with session.lock:
        result = session.tools.step_control(command)
        _sync_session_pid(session)
    result["session_id"] = session.session_id
    return result


@mcp.tool()
@catch_errors()
async def gdb_poll(
    timeout: float = 0.0,
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Drain pending async GDB notifications.

    Args:
        timeout: Maximum time to wait (seconds) for the first event.
    """
    session = _resolve_debug_session(session_id=session_id, process_id=process_id)
    with session.lock:
        result = session.tools.gdb_poll(timeout)
        _sync_session_pid(session)
    result["session_id"] = session.session_id
    return result


@mcp.tool()
@catch_errors()
async def gdb_interrupt(
    timeout: float = 1.0,
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Interrupt the inferior and drain async notifications.

    Args:
        timeout: Maximum time to wait (seconds) for stop notifications.
    """
    session = _resolve_debug_session(session_id=session_id, process_id=process_id)
    with session.lock:
        result = session.tools.gdb_interrupt(timeout)
        _sync_session_pid(session)
    result["session_id"] = session.session_id
    return result


@mcp.tool()
@catch_errors()
async def finish(
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Run until the current function returns (MI -exec-finish)."""
    session = _resolve_debug_session(session_id=session_id, process_id=process_id)
    with session.lock:
        result = session.tools.finish()
        _sync_session_pid(session)
    result["session_id"] = session.session_id
    return result


@mcp.tool()
@catch_errors()
async def jump(
    locspec: str,
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Resume execution at a specified location (MI -exec-jump).

    Args:
        locspec: Location such as a symbol name, file:line, or address (*0x... ).
    """
    session = _resolve_debug_session(session_id=session_id, process_id=process_id)
    with session.lock:
        result = session.tools.jump(locspec)
        _sync_session_pid(session)
    result["session_id"] = session.session_id
    return result


@mcp.tool()
@catch_errors()
async def return_from_function(
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Force the current function to return immediately (MI -exec-return)."""
    session = _resolve_debug_session(session_id=session_id, process_id=process_id)
    with session.lock:
        result = session.tools.return_from_function()
        _sync_session_pid(session)
    result["session_id"] = session.session_id
    return result


@mcp.tool()
@catch_errors()
async def until(
    locspec: Optional[str] = None,
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Run until a specified location or next source line (MI -exec-until)."""
    session = _resolve_debug_session(session_id=session_id, process_id=process_id)
    with session.lock:
        result = session.tools.until(locspec)
        _sync_session_pid(session)
    result["session_id"] = session.session_id
    return result


@mcp.tool()
@catch_errors()
async def get_context(
    context_type: str = "all",
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Get the current debugging context.

    Args:
        context_type: "all" for a quick MI snapshot, or one of {regs, stack, disasm, code, backtrace}
                      to request a specific pwndbg context.
    """
    session = _resolve_debug_session(session_id=session_id, process_id=process_id)
    with session.lock:
        result = session.tools.get_context(context_type)
        _sync_session_pid(session)
    result["session_id"] = session.session_id
    return result


@mcp.tool()
@catch_errors()
async def set_breakpoint(
    location: str,
    condition: Optional[str] = None,
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Set a breakpoint using MI (-break-insert).

    Args:
        location: Breakpoint location (symbol/address/file:line).
        condition: Optional breakpoint condition expression.
    """
    session = _resolve_debug_session(session_id=session_id, process_id=process_id)
    with session.lock:
        result = session.tools.set_breakpoint(location, condition)
        _sync_session_pid(session)
    result["session_id"] = session.session_id
    return result


@mcp.tool()
@catch_errors()
async def get_memory(
    address: str,
    size: int = 64,
    format: str = "hex",
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Read memory at the specified address.

    Args:
        address: Start address expression (e.g., "$rsp", "0xdeadbeef").
        size: Number of bytes to read.
        format: "hex" for raw bytes (fast path), "string" for x/s, otherwise MI grid format.
    """
    session = _resolve_debug_session(session_id=session_id, process_id=process_id)
    with session.lock:
        result = session.tools.get_memory(address, size, format)
        _sync_session_pid(session)
    result["session_id"] = session.session_id
    return result


@mcp.tool()
@catch_errors()
async def get_session_info(
    session_id: Optional[str] = None,
    process_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Return current session info (session state + GDB state) without issuing new GDB commands."""
    session = _resolve_debug_session(session_id=session_id, process_id=process_id)
    with session.lock:
        result = session.tools.get_session_info()
        _sync_session_pid(session)
    result["session_id"] = session.session_id
    result["runtime_dir"] = session.runtime_dir
    return result


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
    if not subprocess_tools:
        return json.dumps(
            {"success": False, "error": "Subprocess tools not initialized"},
            indent=2,
        )
    cwd = resolve_workspace_cwd(cwd, workspace_root=DEFAULT_WORKSPACE)
    result = subprocess_tools.run_command(command, cwd=cwd, timeout=timeout)
    return json.dumps(result, indent=2)


@mcp.tool()
async def spawn_process(command: str, cwd: Optional[str] = None) -> str:
    """Spawn a long-running background process and return its PID and log paths.

    Args:
        command: Shell command to spawn.
        cwd: Working directory (defaults to /workspace).
    """
    if not subprocess_tools:
        return json.dumps(
            {"success": False, "error": "Subprocess tools not initialized"},
            indent=2,
        )
    cwd = resolve_workspace_cwd(cwd, workspace_root=DEFAULT_WORKSPACE)
    result = subprocess_tools.spawn_process(command, cwd=cwd)
    return json.dumps(result, indent=2)


@mcp.tool()
async def get_process(pid: int) -> str:
    """Get information about a tracked background process by PID."""
    if not subprocess_tools:
        return json.dumps(
            {"success": False, "error": "Subprocess tools not initialized"},
            indent=2,
        )
    result = subprocess_tools.get_process(pid)
    return json.dumps(result, indent=2)


@mcp.tool()
async def kill_process(pid: int, signal: int = 15) -> str:
    """Send a signal to a tracked background process (default SIGTERM=15)."""
    if not subprocess_tools:
        return json.dumps(
            {"success": False, "error": "Subprocess tools not initialized"},
            indent=2,
        )
    result = subprocess_tools.kill_process(pid, signal)
    return json.dumps(result, indent=2)


@mcp.tool()
async def list_processes() -> str:
    """List all tracked background processes and their metadata (PID, command, log paths)."""
    if not subprocess_tools:
        return json.dumps(
            {"success": False, "error": "Subprocess tools not initialized"},
            indent=2,
        )
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
    if not git_tools:
        return json.dumps(
            {"success": False, "error": "Git tools not initialized"}, indent=2
        )
    if target_dir:
        target_dir = resolve_workspace_path(
            target_dir,
            workspace_root=DEFAULT_WORKSPACE,
            require_exists=False,
            kind="target_dir",
        )
    else:
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
    if not python_tools:
        return json.dumps(
            {"success": False, "error": "Python tools not initialized"},
            indent=2,
        )
    resolved_script_path = resolve_workspace_path(
        script_path,
        workspace_root=DEFAULT_WORKSPACE,
        require_exists=True,
        kind="script_path",
    )
    cwd = resolve_workspace_cwd(cwd, workspace_root=DEFAULT_WORKSPACE)
    args_list = args.split() if args else None
    result = python_tools.execute_script(resolved_script_path, args_list, cwd, timeout)
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
    if not python_tools:
        return json.dumps(
            {"success": False, "error": "Python tools not initialized"},
            indent=2,
        )
    cwd = resolve_workspace_cwd(cwd, workspace_root=DEFAULT_WORKSPACE)
    result = python_tools.execute_code(code, cwd, timeout)
    return json.dumps(result, indent=2)


@mcp.tool()
async def install_python_packages(packages: str, upgrade: bool = False) -> str:
    """Install additional Python packages using the shared package manager (uv).

    Args:
        packages: Space-separated package list.
        upgrade: If True, perform upgrades when applicable.
    """
    if not python_tools:
        return json.dumps(
            {"success": False, "error": "Python tools not initialized"},
            indent=2,
        )
    packages_list = packages.split()
    result = python_tools.install_packages(packages_list, upgrade)
    return json.dumps(result, indent=2)


@mcp.tool()
async def list_python_packages() -> str:
    """List all packages installed in the shared Python environment."""
    if not python_tools:
        return json.dumps(
            {"success": False, "error": "Python tools not initialized"},
            indent=2,
        )
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


def get_mcp_app() -> FastMCP:
    return mcp
