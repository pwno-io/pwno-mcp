import os
import shlex
import time
from typing import Any, Dict, List, Optional, Tuple

from fastmcp import Context, FastMCP
from fastmcp.dependencies import CurrentContext

from pwnomcp.pwnpipe import PwnPipe
from pwnomcp.tools.common import (
    catch_errors,
    get_pwnpipe,
    get_services,
    resolve_binary_path,
    resolve_debug_session,
    resolve_pipe_session_id,
    require_session_registry,
    run_blocking,
)


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @catch_errors()
    async def pwncli(
        file: str,
        session_id: str,
        argument: str = "",
        wait_timeout: float = 3.0,
        binary_path: Optional[str] = None,
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Run a pwncli exploit script for a specific debug session.

        Behavior:
        - Writes the provided script content to a per-session runtime directory
        - Launches: uv run <session-script> debug <resolved binary> <argument>
        - Maintains one PwnPipe per debug session
        - Detects a single-line marker printed by pwncli after attach:
          "PWNCLI_ATTACH_RESULT:{...json...}" and exposes it as attachment.result
        - Waits up to wait_timeout seconds for attach/output/exit before returning
        - Stores inline script content in session runtime state; only create persistent
          /workspace scripts when the user explicitly requests it

        Args:
            file: Full contents of a pwncli-style Python script.
            argument: Additional pwncli arguments after "debug <binary>".
            wait_timeout: Max time (seconds) to wait for initial attach/output/exit signal.
            binary_path: Optional target binary path (resolved under /workspace). Use a
                container-visible path under /workspace; relative paths resolve under
                /workspace.
            session_id: Debug session id.

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
        services = get_services(ctx)
        session = resolve_debug_session(
            services, session_id=session_id, create_if_missing=False
        )
        resolved_binary = resolve_binary_path(binary_path, session, require_exists=True)

        runtime_dir = session.runtime_dir
        os.makedirs(runtime_dir, exist_ok=True)
        script_path = os.path.join(runtime_dir, f"exp_{int(time.time() * 1000)}.py")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(file)

        replaced = False
        driver_pid: Optional[int] = None
        old_pipe: Optional[PwnPipe] = None
        with services.pwnpipe_lock:
            old_pipe = services.pwnpipe_sessions.get(session.session_id)
            if old_pipe and old_pipe.is_alive():
                replaced = True
            services.pwnpipe_sessions.pop(session.session_id, None)

            cmd = (
                f"uv run {shlex.quote(script_path)} debug {shlex.quote(resolved_binary)} {argument}"
            ).strip()
            pipe = PwnPipe(
                command=cmd,
                cwd=os.path.dirname(resolved_binary),
                env={"PYTHONUNBUFFERED": "1"},
            )
            services.pwnpipe_sessions[session.session_id] = pipe
            driver_pid = pipe.get_pid()
            session.driver_pid = driver_pid

        if old_pipe and old_pipe.is_alive():
            old_pipe.kill()

        def _collect_startup() -> Tuple[Dict[str, Any], str, Any]:
            startup_result = pipe.wait_ready(timeout=wait_timeout)
            output_result = pipe.release()
            attach_result_value = pipe.get_attach_result()
            return startup_result, output_result, attach_result_value

        startup, output, attach_result = await run_blocking(_collect_startup)

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
        session_id: str,
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Send raw input to a session-scoped pwncli process stdin.

        Important:
            This call does not append a newline. If the target expects a line, include
            "\n" yourself.

        Args:
            data: Raw text to write to stdin.

        Returns:
            { "success": bool } indicating whether the input was written successfully.
        """
        services = get_services(ctx)
        resolved_session_id, pipe = get_pwnpipe(services, session_id=session_id)
        with services.pwnpipe_lock:
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
        session_id: str,
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Release and return accumulated output from a session PwnPipe.

        Returns:
            { "success": True, "output": str } on success, or a failure object when no
            pipe exists. The internal buffer is cleared by this call (subsequent calls only
            return new output).
        """
        services = get_services(ctx)
        resolved_session_id, pipe = get_pwnpipe(services, session_id=session_id)
        with services.pwnpipe_lock:
            out = pipe.release()
        return {"success": True, "session_id": resolved_session_id, "output": out}

    @mcp.tool()
    @catch_errors()
    async def checkevents(
        session_id: str,
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Release and return structured events from a session PwnPipe.

        Returns:
            {"success": True, "events": [...], "alive": bool, "exit_code": int|None}
        """
        services = get_services(ctx)
        resolved_session_id, pipe = get_pwnpipe(services, session_id=session_id)
        with services.pwnpipe_lock:
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
        session_id: str,
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Stop a pwncli driver session and clear its session pipe."""
        services = get_services(ctx)
        resolved_session_id = resolve_pipe_session_id(services, session_id=session_id)
        with services.pwnpipe_lock:
            pipe = services.pwnpipe_sessions.pop(resolved_session_id, None)
            if not pipe:
                return {
                    "success": False,
                    "session_id": resolved_session_id,
                    "error": "No active PwnPipe",
                }
            was_alive = pipe.is_alive()
            exit_code = pipe.get_exit_code()
            pipe.kill()
        session = require_session_registry(services).get_session(resolved_session_id)
        if session:
            session.driver_pid = None
        return {
            "success": True,
            "session_id": resolved_session_id,
            "was_alive": was_alive,
            "exit_code": exit_code,
        }

    @mcp.tool()
    @catch_errors()
    async def list_pwncli_sessions(
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """List all active pwncli driver sessions."""
        services = get_services(ctx)
        sessions: List[Dict[str, Any]] = []
        with services.pwnpipe_lock:
            for sid, pipe in services.pwnpipe_sessions.items():
                sessions.append(
                    {
                        "session_id": sid,
                        "driver_pid": pipe.get_pid(),
                        "alive": pipe.is_alive(),
                        "exit_code": pipe.get_exit_code(),
                    }
                )
        return {"success": True, "count": len(sessions), "sessions": sessions}
