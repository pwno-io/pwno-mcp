import logging
import json
import os
import shlex
from typing import Optional, Dict, Any, Tuple, List
from functools import wraps

from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP

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
    retdec: RetDecAnalyzer
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
    # auth=auth_settings,
    # auth_server_provider=auth_provider
)
mcp.settings.host = "0.0.0.0"
mcp.settings.port = 5500


def catch_errors(tuple_on_error: bool = False):
    def decorator(fn):
        @wraps(fn)
        async def wrapper(*args, **kwargs):
            try:
                return await fn(*args, **kwargs)
            except Exception as e:
                logger.exception("tool error in %s", fn.__name__)
                if tuple_on_error:
                    return {"success": False, "error": str(e), "type": type(e).__name__}, []
                return {"success": False, "error": str(e), "type": type(e).__name__}
        return wrapper
    return decorator


@mcp.tool()
@catch_errors()
async def execute(command: str) -> Dict[str, Any]:
    return pwndbg_tools.execute(command)


@mcp.tool()
@catch_errors()
async def set_file(binary_path: str) -> Dict[str, Any]:
    return pwndbg_tools.set_file(binary_path)


@mcp.tool()
@catch_errors(tuple_on_error=True)
async def attach(pid: int) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    result, context = pwndbg_tools.attach(pid)
    return result, context


@mcp.tool()
@catch_errors()
async def run(args: str = "", start: bool = False) -> Dict[str, Any]:
    return pwndbg_tools.run(args, start)


@mcp.tool()
@catch_errors()
async def step_control(command: str) -> Dict[str, Any]:
    return pwndbg_tools.step_control(command)


@mcp.tool()
@catch_errors()
async def finish() -> Dict[str, Any]:
    return pwndbg_tools.finish()


@mcp.tool()
@catch_errors()
async def jump(locspec: str) -> Dict[str, Any]:
    return pwndbg_tools.jump(locspec)


@mcp.tool()
@catch_errors()
async def return_from_function() -> Dict[str, Any]:
    return pwndbg_tools.return_from_function()


@mcp.tool()
@catch_errors()
async def until(locspec: Optional[str] = None) -> Dict[str, Any]:
    return pwndbg_tools.until(locspec)


@mcp.tool()
@catch_errors()
async def get_context(context_type: str = "all") -> Dict[str, Any]:
    return pwndbg_tools.get_context(context_type)


@mcp.tool()
@catch_errors()
async def set_breakpoint(location: str, condition: Optional[str] = None) -> Dict[str, Any]:
    return pwndbg_tools.set_breakpoint(location, condition)


@mcp.tool()
@catch_errors()
async def get_memory(
    address: str,
    size: int = 64,
    format: str = "hex"
) -> Dict[str, Any]:
    return pwndbg_tools.get_memory(address, size, format)


@mcp.tool()
@catch_errors()
async def get_session_info() -> Dict[str, Any]:
    return pwndbg_tools.get_session_info()


@mcp.tool()
async def run_command(command: str, cwd: Optional[str] = None, timeout: float = 30.0) -> str:
    if cwd is None:
        cwd = DEFAULT_WORKSPACE
    result = subprocess_tools.run_command(command, cwd=cwd, timeout=timeout)
    return json.dumps(result, indent=2)


@mcp.tool()
async def spawn_process(command: str, cwd: Optional[str] = None) -> str:
    if cwd is None:
        cwd = DEFAULT_WORKSPACE
    result = subprocess_tools.spawn_process(command, cwd=cwd)
    return json.dumps(result, indent=2)


@mcp.tool()
async def get_process(pid: int) -> str:
    result = subprocess_tools.get_process(pid)
    return json.dumps(result, indent=2)


@mcp.tool()
async def kill_process(pid: int, signal: int = 15) -> str:
    result = subprocess_tools.kill_process(pid, signal)
    return json.dumps(result, indent=2)


@mcp.tool()
async def list_processes() -> str:
    result = subprocess_tools.list_processes()
    return json.dumps(result, indent=2)


@mcp.tool()
async def fetch_repo(
    repo_url: str,
    version: Optional[str] = None,
    target_dir: Optional[str] = None,
    shallow: bool = True
) -> str:
    if target_dir and not os.path.isabs(target_dir):
        target_dir = os.path.join(DEFAULT_WORKSPACE, target_dir)
    elif not target_dir:
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
    if cwd is None:
        cwd = DEFAULT_WORKSPACE
    result = python_tools.execute_code(code, cwd, timeout)
    return json.dumps(result, indent=2)


@mcp.tool()
async def solve(
    script: str,
    pid_timeout: float = 10.0
) -> str:
    try:
        os.makedirs(DEFAULT_WORKSPACE, exist_ok=True)
        script_path = os.path.join(DEFAULT_WORKSPACE, "solve.py")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script)

        python_exe = python_tools.get_python_executable()
        base_cmd = f"{python_exe} -u {shlex.quote(script_path)}"
        env = {"PYTHONUNBUFFERED": "1"}
        spawn = subprocess_tools.spawn_process(base_cmd, cwd=DEFAULT_WORKSPACE, env=env)
        if spawn.get("stdout_path"):
            pid_capture = subprocess_tools.wait_for_pid_marker(spawn["stdout_path"], timeout=pid_timeout)
            spawn["inner_pid_lookup"] = pid_capture
            if pid_capture.get("success") and "pid" in pid_capture:
                spawn["inner_pid"] = pid_capture["pid"]
        spawn["script_path"] = script_path
        spawn["command"] = base_cmd
        return json.dumps(spawn, indent=2)
    except Exception as e:
        return json.dumps({
            "success": False,
            "error": str(e)
        }, indent=2)


@mcp.tool()
async def install_python_packages(
    packages: str,
    upgrade: bool = False
) -> str:
    packages_list = packages.split()
    result = python_tools.install_packages(packages_list, upgrade)
    return json.dumps(result, indent=2)


@mcp.tool()
async def list_python_packages() -> str:
    result = python_tools.get_installed_packages()
    return json.dumps(result, indent=2)


@mcp.tool()
async def get_retdec_status() -> str:
    if not retdec_analyzer:
        return json.dumps({
            "status": "not_initialized",
            "message": "RetDec analyzer not initialized"
        }, indent=2)
    if not retdec_analyzer._initialized:
        logger.info("Performing lazy initialization of RetDec analyzer")
        await retdec_analyzer.initialize()
    status = retdec_analyzer.get_status()
    return json.dumps(status, indent=2)


@mcp.tool()
async def get_decompiled_code() -> str:
    if not retdec_analyzer:
        return json.dumps({
            "status": "error",
            "message": "RetDec analyzer not initialized"
        }, indent=2)
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
        status = retdec_analyzer.get_status()
        return json.dumps({
            "status": "unavailable",
            "reason": status.get("status"),
            "details": status
        }, indent=2)


def get_mcp_app() -> FastAPI:
    return mcp.streamable_http_app()
