import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI
import uvicorn

from pwnomcp.gdb import GdbController
from pwnomcp.state import SessionState
from pwnomcp.tools import PwndbgTools, SubprocessTools, GitTools, PythonTools
from pwnomcp.retdec.retdec import RetDecAnalyzer

from pwnomcp.router import health as health_router
from pwnomcp.router import mcp as mcp_router


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


DEFAULT_WORKSPACE = "/workspace"


gdb_controller: Optional[GdbController] = None
session_state: Optional[SessionState] = None
pwndbg_tools: Optional[PwndbgTools] = None
subprocess_tools: Optional[SubprocessTools] = None
git_tools: Optional[GitTools] = None
python_tools: Optional[PythonTools] = None
retdec_analyzer: Optional[RetDecAnalyzer] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global gdb_controller, session_state, pwndbg_tools, subprocess_tools, git_tools, python_tools, retdec_analyzer

    logger.info("Initializing Pwno MCP server...")

    if not os.path.exists(DEFAULT_WORKSPACE):
        try:
            os.makedirs(DEFAULT_WORKSPACE, exist_ok=True)
            logger.info(f"Created default workspace directory: {DEFAULT_WORKSPACE}")
        except OSError as e:
            logger.warning(f"Could not create workspace directory {DEFAULT_WORKSPACE}: {e}")
            logger.info("Continuing without default workspace directory")

    gdb_controller      = GdbController()
    session_state       = SessionState()
    pwndbg_tools        = PwndbgTools(gdb_controller, session_state)
    subprocess_tools    = SubprocessTools()
    git_tools           = GitTools()
    python_tools        = PythonTools()
    retdec_analyzer     = RetDecAnalyzer()

    init_result = gdb_controller.initialize()
    logger.info(f"GDB initialization: {init_result['status']}")
    logger.info("RetDec analyzer created (lazy initialization)")

    # Provide the runtime context to the MCP tools module
    mcp_router.set_runtime_context(
        gdb_controller,
        session_state,
        pwndbg_tools,
        subprocess_tools,
        git_tools,
        python_tools,
        retdec_analyzer,
    )

    # Run the MCP session manager lifecycle
    async with mcp_router.mcp.session_manager.run():
        yield

    logger.info("Shutting down Pwno MCP server...")
    if gdb_controller:
        gdb_controller.close()


def build_app() -> FastAPI:
    app = FastAPI(lifespan=lifespan)

    @app.get("/")
    async def root():
        return {"message": "Pwno MCP Server"}

    app.mount("/", mcp_router.get_mcp_app())

    return app


def run_server():
    app = build_app()
    uvicorn.run(app, host="0.0.0.0", port=5500)


app = build_app()