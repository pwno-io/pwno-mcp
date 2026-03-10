import logging
from typing import Optional

from fastmcp import FastMCP

from pwnomcp.lifespan import create_lifespan
from pwnomcp.services import AppServices
from pwnomcp.tools import register_all_tools

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)


def create_mcp(services: Optional[AppServices] = None) -> FastMCP:
    mcp = FastMCP(
        name="pwno-mcp",
        lifespan=create_lifespan(services=services),
    )
    register_all_tools(mcp)
    return mcp


mcp = create_mcp()
