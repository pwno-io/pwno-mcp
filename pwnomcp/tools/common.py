import asyncio
import logging
import os
from functools import wraps
from typing import Any, Callable, Dict, Optional, Tuple, TypeVar

from fastmcp import Context

from pwnomcp.pwnpipe import PwnPipe
from pwnomcp.services import AppServices
from pwnomcp.state import DebugSession, DebugSessionRegistry
from pwnomcp.utils.paths import DEFAULT_WORKSPACE, resolve_workspace_path

logger = logging.getLogger(__name__)
T = TypeVar("T")


def catch_errors(tuple_on_error: bool = False) -> Callable[[Callable[..., Any]], Any]:
    def decorator(fn: Callable[..., Any]) -> Any:
        @wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
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


def get_services(ctx: Context) -> AppServices:
    services = ctx.lifespan_context.get("services")
    if services is None:
        raise RuntimeError("Runtime services not initialized")
    return services


async def run_blocking(fn: Callable[[], T]) -> T:
    return await asyncio.to_thread(fn)


def require_session_registry(services: AppServices) -> DebugSessionRegistry:
    return services.session_registry


def resolve_debug_session(
    services: AppServices,
    session_id: Optional[str] = None,
    create_if_missing: bool = True,
) -> DebugSession:
    registry = require_session_registry(services)

    if session_id is not None:
        existing = registry.get_session(session_id)
        if existing:
            return existing
        if not create_if_missing:
            raise RuntimeError(f"Debug session '{session_id}' not found")
        return registry.create_session(session_id)

    if not create_if_missing:
        raise RuntimeError("session_id is required")
    return registry.ensure_session(services.default_session_id)


def sync_session_pid(session: DebugSession) -> None:
    pid = session.gdb.get_inferior_pid() or session.state.pid
    session.state.pid = pid


def run_session_locked(
    session: DebugSession,
    action: Callable[[], T],
    *,
    sync_pid: bool = True,
) -> T:
    with session.lock:
        result = action()
        if sync_pid:
            sync_session_pid(session)
        return result


async def run_session_action(
    session: DebugSession,
    action: Callable[[], T],
    *,
    sync_pid: bool = True,
) -> T:
    return await run_blocking(
        lambda: run_session_locked(session, action, sync_pid=sync_pid)
    )


def resolve_binary_path(
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


def resolve_pipe_session_id(services: AppServices, session_id: str) -> str:
    session = resolve_debug_session(
        services, session_id=session_id, create_if_missing=False
    )
    return session.session_id


def get_pwnpipe(services: AppServices, session_id: str) -> Tuple[str, PwnPipe]:
    resolved_session_id = resolve_pipe_session_id(services, session_id=session_id)
    with services.pwnpipe_lock:
        pipe = services.pwnpipe_sessions.get(resolved_session_id)
        if not pipe:
            raise RuntimeError(
                f"No active pwncli session for session_id='{resolved_session_id}'"
            )
        return resolved_session_id, pipe
