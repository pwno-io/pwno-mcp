import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

import uvicorn
from fastapi import FastAPI

from pwnomcp.gdb import GdbController
from pwnomcp.retdec.retdec import RetDecAnalyzer
from pwnomcp.router import attach as attach_router
from pwnomcp.router import mcp as mcp_router
from pwnomcp.state import SessionState
from pwnomcp.tools import GitTools, PwndbgTools, PythonTools, SubprocessTools


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
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


def _initialize_components() -> None:
    """
    Initialize all MCP components and set up the runtime context.

    This helper is shared between HTTP mode (FastAPI lifespan) and stdio mode so
    both transports share identical initialization semantics.
    """
    global gdb_controller, session_state, pwndbg_tools, subprocess_tools, git_tools, python_tools, retdec_analyzer

    if not os.path.exists(DEFAULT_WORKSPACE):
        try:
            os.makedirs(DEFAULT_WORKSPACE, exist_ok=True)
            logger.info("Created default workspace directory: %s", DEFAULT_WORKSPACE)
        except OSError as exc:
            logger.warning("Could not create workspace directory %s: %s", DEFAULT_WORKSPACE, exc)
            logger.info("Continuing without default workspace directory")

    gdb_controller = GdbController()
    session_state = SessionState()
    pwndbg_tools = PwndbgTools(gdb_controller, session_state)
    subprocess_tools = SubprocessTools()
    git_tools = GitTools()
    python_tools = PythonTools()
    retdec_analyzer = RetDecAnalyzer()

    init_result = gdb_controller.initialize()
    logger.info("GDB initialization: %s", init_result["status"])
    logger.info("RetDec analyzer created (lazy initialization)")

    mcp_router.set_runtime_context(
        gdb_controller,
        session_state,
        pwndbg_tools,
        subprocess_tools,
        git_tools,
        python_tools,
        retdec_analyzer,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing Pwno MCP server (HTTP mode)...")

    _initialize_components()

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


def run_stdio() -> None:
    """
    Run Pwno MCP in stdio mode for MCP clients (Claude Desktop, etc.).

    This path keeps the initialization consistent with HTTP mode but swaps the
    transport for a stdio driver expected by MCP-aware desktop agents.
    """
    logger.info("Initializing Pwno MCP server (stdio mode)...")
    _initialize_components()
    logger.info("Starting MCP server in stdio mode...")
    mcp_router.mcp.run()


def run_server(
    host: str = "0.0.0.0",
    port: int = 5500,
    attach_host: str = "127.0.0.1",
    attach_port: int = 5501,
) -> None:
    """
    Run the Pwno MCP FastAPI server and the attach API concurrently.

    :param host: Host address for the HTTP MCP server.
    :param port: Port for the HTTP MCP server.
    :param attach_host: Host address for the attach API server.
    :param attach_port: Port for the attach API server.
    """
    main_app = build_app()
    attach_app = attach_router.get_attach_app()

    main_config = uvicorn.Config(main_app, host=host, port=port, log_level="info")
    attach_config = uvicorn.Config(attach_app, host=attach_host, port=attach_port, log_level="info")

    main_server = uvicorn.Server(main_config)
    attach_server = uvicorn.Server(attach_config)

    async def _serve_both():
        logger.info(
            "Starting MCP server on %s:%s and attach server on %s:%s",
            host,
            port,
            attach_host,
            attach_port,
        )
        await asyncio.gather(
            main_server.serve(),
            attach_server.serve(),
        )

    asyncio.run(_serve_both())


app = build_app()
