from fastapi import APIRouter
import os

from pwnomcp.router.mcp import (
    DEFAULT_WORKSPACE,
    auth_provider,
    gdb_controller,
    subprocess_tools,
)

router = APIRouter()


@router.get("/")
async def root():
    return {"message": "Pwno MCP Server"}


@router.get("/health")
async def health_check():
    health_status = {
        "status": "healthy",
        "server": "pwno-mcp",
        "version": "1.0.0",
        "workspace": {
            "path": DEFAULT_WORKSPACE,
            "exists": os.path.exists(DEFAULT_WORKSPACE),
        },
        "authentication": {"enabled": auth_provider.is_auth_enabled},
        "components": {},
    }

    if gdb_controller:
        try:
            health_status["components"]["gdb_initialized"] = gdb_controller._initialized
            health_status["components"]["gdb_state"] = gdb_controller.get_state()
        except Exception as e:
            health_status["components"]["gdb_error"] = str(e)
            health_status["status"] = "degraded"

    if subprocess_tools:
        try:
            active_processes = len(subprocess_tools.background_processes)
            health_status["active_processes"] = active_processes
        except Exception:
            health_status["active_processes"] = 0

    return health_status
