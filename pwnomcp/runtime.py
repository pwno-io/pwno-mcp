import logging
import threading
from dataclasses import dataclass
from typing import Optional

import uvicorn

from pwnomcp.http.attach import create_attach_app
from pwnomcp.server import create_mcp
from pwnomcp.services import close_services, create_services

logger = logging.getLogger(__name__)


@dataclass
class AttachServerHandle:
    server: uvicorn.Server
    thread: threading.Thread


def _start_attach_server(
    host: Optional[str], port: Optional[int], attach_app
) -> Optional[AttachServerHandle]:
    if not host or not port:
        logger.info("Attach server disabled (host or port missing)")
        return None

    attach_config = uvicorn.Config(attach_app, host=host, port=port, log_level="info")
    attach_server = uvicorn.Server(attach_config)

    def _serve_attach() -> None:
        try:
            logger.info("Attach server listening on %s:%s", host, port)
            attach_server.run()
        except Exception:
            logger.exception("Attach server crashed")

    thread = threading.Thread(
        target=_serve_attach, name="pwno-mcp-attach-server", daemon=True
    )
    thread.start()

    return AttachServerHandle(server=attach_server, thread=thread)


def _stop_attach_server(handle: Optional[AttachServerHandle]) -> None:
    if not handle:
        return

    logger.info("Stopping attach server...")
    handle.server.should_exit = True
    handle.server.force_exit = True
    if handle.thread.is_alive():
        handle.thread.join(timeout=5)


def run_stdio() -> None:
    logger.info("Initializing Pwno MCP server (stdio mode)...")
    services = create_services()
    mcp = create_mcp(services=services)
    try:
        logger.info("Starting MCP server in stdio mode...")
        mcp.run(transport="stdio")
    finally:
        close_services(services)


def run_http(
    host: str = "0.0.0.0",
    port: int = 5500,
    attach_host: str = "127.0.0.1",
    attach_port: int = 5501,
    http_path: str = "/mcp",
) -> None:
    logger.info(
        "Starting MCP server on %s:%s (path %s) and attach server on %s:%s",
        host,
        port,
        http_path,
        attach_host,
        attach_port,
    )

    services = create_services()
    mcp = create_mcp(services=services)
    attach_app = create_attach_app(services)
    attach_handle = _start_attach_server(attach_host, attach_port, attach_app)

    try:
        logger.info("Launching FastMCP server via mcp.run(transport='http')...")
        mcp.run(transport="http", host=host, port=port, path=http_path)
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down Pwno MCP server")
    finally:
        _stop_attach_server(attach_handle)
        close_services(services)
