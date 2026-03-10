from typing import Any, Dict, List, Optional, Tuple

from fastmcp import Context, FastMCP
from fastmcp.dependencies import CurrentContext

from pwnomcp.tools.common import (
    catch_errors,
    get_services,
    resolve_binary_path,
    resolve_debug_session,
    require_session_registry,
    run_session_action,
)


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @catch_errors()
    async def create_debug_session(
        session_id: Optional[str] = None,
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Create or return a debug session by id."""
        services = get_services(ctx)
        session = resolve_debug_session(
            services, session_id=session_id, create_if_missing=True
        )
        return {"success": True, "session": session.to_dict()}

    @mcp.tool()
    @catch_errors()
    async def list_debug_sessions(
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """List all active debug sessions and metadata."""
        services = get_services(ctx)
        sessions = require_session_registry(services).list_sessions()
        return {"success": True, "count": len(sessions), "sessions": sessions}

    @mcp.tool()
    @catch_errors()
    async def close_debug_session(
        session_id: str,
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Close an active debug session and stop any attached pwncli driver."""
        services = get_services(ctx)
        registry = require_session_registry(services)
        session = registry.get_session(session_id)
        resolved_session_id = session.session_id if session else session_id

        with services.pwnpipe_lock:
            pipe = services.pwnpipe_sessions.pop(resolved_session_id, None)
        if pipe:
            pipe.kill()

        return registry.close_session(session_id)

    @mcp.tool()
    @catch_errors()
    async def execute(
        command: str,
        session_id: str,
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Execute an arbitrary GDB/pwndbg command."""
        services = get_services(ctx)
        session = resolve_debug_session(
            services, session_id=session_id, create_if_missing=False
        )
        result = await run_session_action(
            session, lambda: session.tools.execute(command)
        )
        result["session_id"] = session.session_id
        return result

    @mcp.tool()
    @catch_errors()
    async def set_file(
        binary_path: str,
        session_id: str,
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Load an executable file into GDB/pwndbg for debugging.

        Use a container-visible path under /workspace (or a relative path, which
        resolves under /workspace). If your host file is ./workspace/chal, pass
        /workspace/chal here.
        """
        services = get_services(ctx)
        session = resolve_debug_session(
            services, session_id=session_id, create_if_missing=False
        )
        resolved_binary = resolve_binary_path(binary_path, session, require_exists=True)
        result = await run_session_action(
            session, lambda: session.tools.set_file(resolved_binary)
        )
        result["session_id"] = session.session_id
        result["binary_path"] = resolved_binary
        return result

    @mcp.tool()
    @catch_errors(tuple_on_error=True)
    async def attach(
        pid: int,
        session_id: str,
        ctx: Context = CurrentContext(),
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Attach to an existing process by PID using GDB/MI."""
        services = get_services(ctx)
        session = resolve_debug_session(
            services, session_id=session_id, create_if_missing=False
        )
        result, context = await run_session_action(
            session, lambda: session.tools.attach(pid)
        )
        result["session_id"] = session.session_id
        return result, context

    @mcp.tool()
    @catch_errors()
    async def run(
        session_id: str,
        args: str = "",
        start: bool = False,
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Run the loaded program under GDB control."""
        services = get_services(ctx)
        session = resolve_debug_session(
            services, session_id=session_id, create_if_missing=False
        )
        result = await run_session_action(
            session, lambda: session.tools.run(args, start)
        )
        result["session_id"] = session.session_id
        return result

    @mcp.tool()
    @catch_errors()
    async def step_control(
        command: str,
        session_id: str,
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Execute a stepping command (c, n, s, ni, si)."""
        services = get_services(ctx)
        session = resolve_debug_session(
            services, session_id=session_id, create_if_missing=False
        )
        result = await run_session_action(
            session, lambda: session.tools.step_control(command)
        )
        result["session_id"] = session.session_id
        return result

    @mcp.tool()
    @catch_errors()
    async def gdb_poll(
        session_id: str,
        timeout: float = 0.0,
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Drain pending async GDB notifications."""
        services = get_services(ctx)
        session = resolve_debug_session(
            services, session_id=session_id, create_if_missing=False
        )
        result = await run_session_action(
            session, lambda: session.tools.gdb_poll(timeout)
        )
        result["session_id"] = session.session_id
        return result

    @mcp.tool()
    @catch_errors()
    async def gdb_interrupt(
        session_id: str,
        timeout: float = 1.0,
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Interrupt the inferior and drain async notifications."""
        services = get_services(ctx)
        session = resolve_debug_session(
            services, session_id=session_id, create_if_missing=False
        )
        result = await run_session_action(
            session, lambda: session.tools.gdb_interrupt(timeout)
        )
        result["session_id"] = session.session_id
        return result

    @mcp.tool()
    @catch_errors()
    async def finish(
        session_id: str,
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Run until the current function returns (MI -exec-finish)."""
        services = get_services(ctx)
        session = resolve_debug_session(
            services, session_id=session_id, create_if_missing=False
        )
        result = await run_session_action(session, lambda: session.tools.finish())
        result["session_id"] = session.session_id
        return result

    @mcp.tool()
    @catch_errors()
    async def jump(
        locspec: str,
        session_id: str,
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Resume execution at a specified location (MI -exec-jump)."""
        services = get_services(ctx)
        session = resolve_debug_session(
            services, session_id=session_id, create_if_missing=False
        )
        result = await run_session_action(session, lambda: session.tools.jump(locspec))
        result["session_id"] = session.session_id
        return result

    @mcp.tool()
    @catch_errors()
    async def return_from_function(
        session_id: str,
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Force the current function to return immediately (MI -exec-return)."""
        services = get_services(ctx)
        session = resolve_debug_session(
            services, session_id=session_id, create_if_missing=False
        )
        result = await run_session_action(
            session, lambda: session.tools.return_from_function()
        )
        result["session_id"] = session.session_id
        return result

    @mcp.tool()
    @catch_errors()
    async def until(
        session_id: str,
        locspec: Optional[str] = None,
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Run until a specified location or next source line (MI -exec-until)."""
        services = get_services(ctx)
        session = resolve_debug_session(
            services, session_id=session_id, create_if_missing=False
        )
        result = await run_session_action(session, lambda: session.tools.until(locspec))
        result["session_id"] = session.session_id
        return result

    @mcp.tool()
    @catch_errors()
    async def set_breakpoint(
        location: str,
        session_id: str,
        condition: Optional[str] = None,
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Set a breakpoint using MI (-break-insert)."""
        services = get_services(ctx)
        session = resolve_debug_session(
            services, session_id=session_id, create_if_missing=False
        )
        result = await run_session_action(
            session, lambda: session.tools.set_breakpoint(location, condition)
        )
        result["session_id"] = session.session_id
        return result

    @mcp.tool()
    @catch_errors()
    async def get_session_info(
        session_id: str,
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Return current session info without issuing new GDB commands."""
        services = get_services(ctx)
        session = resolve_debug_session(
            services, session_id=session_id, create_if_missing=False
        )
        result = await run_session_action(
            session, lambda: session.tools.get_session_info()
        )
        result["session_id"] = session.session_id
        result["runtime_dir"] = session.runtime_dir
        return result
