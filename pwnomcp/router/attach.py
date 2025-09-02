import logging
from typing import List, Optional, Dict, Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

# Reuse the already-initialized runtime context from the MCP router
from pwnomcp.router import mcp as mcp_router


logger = logging.getLogger(__name__)


class AttachRequest(BaseModel):
    """
    Request body for /attach

    - pre: list of GDB commands to execute before attaching
    - pid: target process id to attach
    - after: list of GDB commands to execute after successful attach
    - where: optional binary path to set as debug target before pre (can be skipped if pre-setted)
    """
    pre: Optional[List[str]] = Field(default=None)
    pid: int
    after: Optional[List[str]] = Field(default=None)
    where: Optional[str] = Field(default=None)

class AttachResponse(BaseModel):
    """Response body for /attach"""
    successful: bool
    attach: Optional[Dict[str, Any]] = None
    result: Dict[str, Any]


app = FastAPI(title="pwno-mcp attach", version="0.1.0")

def _get_tools():
    """Obtain the shared PwndbgTools instance from the MCP router."""
    tools = mcp_router.pwndbg_tools
    if tools is None:
        raise RuntimeError("pwndbg_tools not initialized; ensure server set_runtime_context was called")
    return tools

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

    tools = _get_tools()
    command_results: Dict[str, Any] = {}

    # Optionally set the binary file prior to pre-commands
    if body.where:
        try:
            logger.info("[attach] set-file: %s", body.where)
            set_res = tools.set_file(body.where)
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
        # Selectively expose key fields only
        attach_info = {
            "command": attach_result.get("command"),
            "success": attach_success,
            "state": attach_result.get("state"),
            "pid": attach_result.get("pid"),
        }
    except Exception:
        logger.exception("Error attaching to pid %s", body.pid)
        attach_success = False
        attach_info = {"success": False, "error": f"failed to attach to pid {body.pid}"}

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

    return AttachResponse(successful=attach_success, attach=attach_info, result=command_results)


def get_attach_app() -> FastAPI:
    """Expose the attach FastAPI app for mounting/serving under loopback."""
    return app