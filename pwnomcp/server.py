import logging
import os
import threading
from dataclasses import dataclass
from typing import Optional

import uvicorn

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


@dataclass
class AttachServerHandle:
    """Track the background attach FastAPI server."""

    server: uvicorn.Server
    thread: threading.Thread


def _initialize_components() -> None:
    """
    Initialize all MCP components and set up the runtime context.

    This helper is shared between HTTP mode and stdio mode so both transports
    share identical initialization semantics.
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


def _shutdown_components() -> None:
    """Tear down global components created during initialization."""
    global gdb_controller, session_state, pwndbg_tools, subprocess_tools, git_tools, python_tools, retdec_analyzer

    logger.info("Shutting down Pwno MCP server components...")
    if gdb_controller:
        gdb_controller.close()

    gdb_controller = None
    session_state = None
    pwndbg_tools = None
    subprocess_tools = None
    git_tools = None
    python_tools = None
    retdec_analyzer = None


def _configure_fastmcp(host: str, port: int, streamable_http_path: str) -> None:
    """Ensure the FastMCP instance listens on the requested interface."""
    mcp_router.mcp.settings.host = host
    mcp_router.mcp.settings.port = port
    if streamable_http_path:
        mcp_router.mcp.settings.streamable_http_path = streamable_http_path


def _start_attach_server(host: Optional[str], port: Optional[int]) -> Optional[AttachServerHandle]:
    """Start the attach FastAPI server in a background daemon thread."""
    if not host or not port:
        logger.info("Attach server disabled (host or port missing)")
        return None

    attach_app = attach_router.get_attach_app()
    attach_config = uvicorn.Config(attach_app, host=host, port=port, log_level="info")
    attach_server = uvicorn.Server(attach_config)

    def _serve_attach() -> None:
        try:
            logger.info("Attach server listening on %s:%s", host, port)
            attach_server.run()
        except Exception:
            logger.exception("Attach server crashed")

    thread = threading.Thread(target=_serve_attach, name="pwno-mcp-attach-server", daemon=True)
    thread.start()

    return AttachServerHandle(server=attach_server, thread=thread)


def _stop_attach_server(handle: Optional[AttachServerHandle]) -> None:
    """Signal the attach server to stop and wait briefly for the thread."""
    if not handle:
        return

    logger.info("Stopping attach server...")
    handle.server.should_exit = True
    handle.server.force_exit = True
    if handle.thread.is_alive():
        handle.thread.join(timeout=5)


def run_stdio() -> None:
    """
    Run Pwno MCP in stdio mode for MCP clients (Claude Desktop, etc.).

    This path keeps the initialization consistent with HTTP mode but swaps the
    transport for a stdio driver expected by MCP-aware desktop agents.
    """
    logger.info("Initializing Pwno MCP server (stdio mode)...")
    _initialize_components()
    try:
        logger.info("Starting MCP server in stdio mode via FastMCP.run()...")
        mcp_router.mcp.run(transport="stdio")
    finally:
        _shutdown_components()


def run_server(
    host: str = "0.0.0.0",
    port: int = 5500,
    attach_host: str = "127.0.0.1",
    attach_port: int = 5501,
    streamable_http_path: str = "/debug",
) -> None:
    """
    Run the Pwno MCP StreamableHTTP server via FastMCP.run() plus the attach API.

    :param host: Host address for the HTTP MCP server.
    :param port: Port for the HTTP MCP server.
    :param attach_host: Host address for the attach API server.
    :param attach_port: Port for the attach API server.
    :param streamable_http_path: URL prefix for the Streamable HTTP transport.
    """
    logger.info(
        "Starting MCP server on %s:%s (stream path %s) and attach server on %s:%s",
        host,
        port,
        streamable_http_path,
        attach_host,
        attach_port,
    )
    _configure_fastmcp(host, port, streamable_http_path)
    _initialize_components()
    attach_handle = _start_attach_server(attach_host, attach_port)

    try:
        logger.info("Launching FastMCP server via mcp.run(transport='streamable-http')...")
        mcp_router.mcp.run(transport="streamable-http")
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down Pwno MCP server")
    finally:
        _stop_attach_server(attach_handle)
        _shutdown_components()
