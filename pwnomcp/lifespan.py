from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Callable, Optional

from fastmcp import FastMCP

from pwnomcp.services import AppServices, close_services, create_services


def create_lifespan(
    services: Optional[AppServices] = None,
) -> Callable[[FastMCP], Any]:
    @asynccontextmanager
    async def _lifespan(_server: FastMCP) -> AsyncIterator[dict[str, Any]]:
        managed_services = services
        owns_services = managed_services is None
        if managed_services is None:
            managed_services = create_services()

        try:
            yield {"services": managed_services}
        finally:
            if owns_services:
                close_services(managed_services)

    return _lifespan
