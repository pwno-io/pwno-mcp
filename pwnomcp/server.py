import logging
import os
import asyncio
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
from pwnomcp.router import attach as attach_router


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


def _initialize_components():
    """
    Initialize all MCP components and set up the runtime context.

    This function is shared between HTTP mode (lifespan) and stdio mode (run_stdio)
    to ensure consistent initialization across different transport modes.
    """
    global gdb_controller, session_state, pwndbg_tools, subprocess_tools, git_tools, python_tools, retdec_analyzer

    # Ensure workspace directory exists
    if not os.path.exists(DEFAULT_WORKSPACE):
        try:
            os.makedirs(DEFAULT_WORKSPACE, exist_ok=True)
            logger.info(f"Created default workspace directory: {DEFAULT_WORKSPACE}")
        except OSError as e:
            logger.warning(f"Could not create workspace directory {DEFAULT_WORKSPACE}: {e}")
            logger.info("Continuing without default workspace directory")

    # Initialize all components
    gdb_controller   = GdbController()
    session_state    = SessionState()
    pwndbg_tools     = PwndbgTools(gdb_controller, session_state)
    subprocess_tools = SubprocessTools()
    git_tools        = GitTools()
    python_tools     = PythonTools()
    retdec_analyzer  = RetDecAnalyzer()

    # Initialize GDB
    init_result = gdb_controller.initialize()
    logger.info(f"GDB initialization: {init_result['status']}")
    logger.info("RetDec analyzer created (lazy initialization)")

    # Set runtime context for MCP router
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

    # Initialize all components
    _initialize_components()

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


def run_stdio():
    """
    Run MCP server in stdio mode for MCP clients (Claude Desktop, etc.)

    This mode uses standard input/output for communication, making it suitable
    for integration with MCP clients like Claude Desktop or other stdio-based tools.
    """
    logger.info("Initializing Pwno MCP server (stdio mode)...")

    # Initialize all components (shared with HTTP mode)
    _initialize_components()

    # Start MCP server in stdio mode
    logger.info("Starting MCP server in stdio mode...")
    mcp_router.mcp.run()


def run_server():
    """
    - Main MCP app on 0.0.0.0:5500
    - Attach API on 127.0.0.1:5501
    """
    Run the Pwno MCP server.

    Args:
        host: Host address for the main MCP server (default: 0.0.0.0)
        port: Port for the main MCP server (default: 5500)
        attach_host: Host address for the attach API server (default: 127.0.0.1)
        attach_port: Port for the attach API server (default: 5501)
    """
    main_app = build_app()
    attach_app = attach_router.get_attach_app()

    main_config = uvicorn.Config(main_app, host=host, port=port, log_level="info")
    attach_config = uvicorn.Config(attach_app, host=attach_host, port=attach_port, log_level="info")

    main_server = uvicorn.Server(main_config)
    attach_server = uvicorn.Server(attach_config)

    async def _serve_both():
        logger.info(f"Starting MCP server on {host}:{port} and attach server on {attach_host}:{attach_port}")
        await asyncio.gather(
            main_server.serve(),
            attach_server.serve(),
        )

    asyncio.run(_serve_both())


app = build_app()