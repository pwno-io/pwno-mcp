import logging
import asyncio
from typing import List, Optional, Dict, Any, Tuple

from fastapi import FastAPI
from pydantic import BaseModel, Field

# Reuse the already-initialized runtime context from the MCP router
from pwnomcp.router import mcp as mcp_router
from pwnomcp.utils.paths import DEFAULT_WORKSPACE, resolve_workspace_path

logger = logging.getLogger(__name__)


class AttachRequest(BaseModel):
    """
    Request body for /attach

    - pre: list of GDB commands to execute before attaching
    - pid: target process id to attach
    - after: list of GDB commands to execute after successful attach
    - where: optional binary path to set as debug target before pre (can be skipped if pre-setted)
    - session_id: debug session identifier for parallel workflows
    """

    pre: Optional[List[str]] = Field(default=None)
    pid: int
    after: Optional[List[str]] = Field(default=None)
    where: Optional[str] = Field(default=None)
    session_id: str


class AttachResponse(BaseModel):
    """Response body for /attach"""

    successful: bool
    attach: Optional[Dict[str, Any]] = None
    result: Dict[str, Any]


app = FastAPI(title="pwno-mcp attach", version="0.1.0")


def _resolve_session(body: AttachRequest):
    """Resolve target debug session from session_id."""
    registry = mcp_router.session_registry
    if registry is not None:
        session = registry.get_session(body.session_id)
        if session is None:
            raise RuntimeError(f"Debug session '{body.session_id}' not found")
        return session

    tools = mcp_router.pwndbg_tools
    if tools is None:
        raise RuntimeError(
            "pwndbg_tools not initialized; ensure server set_runtime_context was called"
        )
    return None


@app.get("/")
async def root():
    return {"message": "Pwno MCP Attach"}


@app.post("/attach", response_model=AttachResponse)
async def attach_endpoint(body: AttachRequest) -> AttachResponse:
    """
    Attach to a running process and execute optional pre/after commands.

    Returns:
    - successful: whether attaching to the pid succeeded
    - result: mapping {command: command_result_dict} for all executed commands
    """
    try:
        session = _resolve_session(body)
    except Exception as exc:
        logger.exception("Failed to resolve debug session for attach request")
        return AttachResponse(
            successful=False,
            attach={
                "success": False,
                "error": str(exc),
                "pid": body.pid,
                "session_id": body.session_id,
            },
            result={},
        )

    tools = session.tools if session is not None else mcp_router.pwndbg_tools
    assert tools is not None
    command_results: Dict[str, Any] = {}

    def _run_attach_sequence() -> Tuple[bool, Optional[Dict[str, Any]], Dict[str, Any]]:
        # Optionally set the binary file prior to pre-commands
        if body.where:
            try:
                resolved_binary = resolve_workspace_path(
                    body.where,
                    workspace_root=DEFAULT_WORKSPACE,
                    require_exists=False,
                    kind="where",
                )
                logger.info("[attach] set-file: %s", resolved_binary)
                set_res = tools.set_file(resolved_binary)
                command_results["set-file"] = set_res
            except Exception as e:
                logger.exception("Error setting file: %s", body.where)
                command_results["set-file"] = {"success": False, "error": str(e)}

        # Execute pre-attachment commands
        for cmd in body.pre or []:
            try:
                logger.info("[attach] pre: %s", cmd)
                res = tools.execute(cmd)
                logger.info("[attach] pre command result: %s", res)
                command_results[cmd] = res
            except Exception as e:
                logger.exception("Error executing pre command: %s", cmd)
                command_results[cmd] = {"success": False, "error": str(e)}

        # Perform attach
        attach_info: Optional[Dict[str, Any]] = None
        try:
            logger.info("[attach] attaching to pid=%s", body.pid)
            attach_result, _ = tools.attach(body.pid)
            logger.info("[attach] attach result: %s", attach_result)
            attach_success = bool(attach_result.get("success"))
            if attach_success and session is not None:
                session.state.pid = body.pid
            # Selectively expose key fields only
            attach_info = {
                "command": attach_result.get("command"),
                "success": attach_success,
                "state": attach_result.get("state"),
                "pid": attach_result.get("pid"),
                "session_id": session.session_id if session is not None else None,
            }
        except Exception:
            logger.exception("Error attaching to pid %s", body.pid)
            attach_success = False
            attach_info = {
                "success": False,
                "error": f"failed to attach to pid {body.pid}",
            }

        # Execute after-attachment commands only if attach succeeded
        if attach_success:
            for cmd in body.after or []:
                try:
                    logger.info("[attach] after: %s", cmd)
                    res = tools.execute(cmd)
                    logger.info("[attach] after command result: %s", res)
                    command_results[cmd] = res
                except Exception as e:
                    logger.exception("Error executing after command: %s", cmd)
                    command_results[cmd] = {"success": False, "error": str(e)}

        return attach_success, attach_info, command_results

    def _run_with_optional_session_lock() -> (
        Tuple[bool, Optional[Dict[str, Any]], Dict[str, Any]]
    ):
        if session is None:
            return _run_attach_sequence()
        with session.lock:
            return _run_attach_sequence()

    attach_success, attach_info, command_results = await asyncio.to_thread(
        _run_with_optional_session_lock
    )

    return AttachResponse(
        successful=attach_success, attach=attach_info, result=command_results
    )


def get_attach_app() -> FastAPI:
    """Expose the attach FastAPI app for mounting/serving under loopback."""
    return app
