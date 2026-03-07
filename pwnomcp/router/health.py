import os

from fastapi import APIRouter

from pwnomcp.router import mcp as mcp_router

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
            "path": mcp_router.DEFAULT_WORKSPACE,
            "exists": os.path.exists(mcp_router.DEFAULT_WORKSPACE),
        },
        "authentication": {"enabled": mcp_router.auth_provider.is_auth_enabled},
        "components": {},
    }

    if mcp_router.gdb_controller:
        try:
            health_status["components"][
                "gdb_initialized"
            ] = mcp_router.gdb_controller._initialized
            health_status["components"][
                "gdb_state"
            ] = mcp_router.gdb_controller.get_state()
        except Exception as e:
            health_status["components"]["gdb_error"] = str(e)
            health_status["status"] = "degraded"

    if mcp_router.session_registry:
        try:
            health_status["components"]["debug_sessions"] = len(
                mcp_router.session_registry.sessions
            )
        except Exception:
            health_status["components"]["debug_sessions"] = 0

    if mcp_router.subprocess_tools:
        try:
            active_processes = len(mcp_router.subprocess_tools.background_processes)
            health_status["active_processes"] = active_processes
        except Exception:
            health_status["active_processes"] = 0

    return health_status
