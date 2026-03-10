from typing import Any, Dict

from fastmcp import Context, FastMCP
from fastmcp.dependencies import CurrentContext

from pwnomcp.tools.common import (
    catch_errors,
    get_services,
    resolve_debug_session,
    run_session_action,
)


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @catch_errors()
    async def get_context(
        session_id: str,
        context_type: str = "all",
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Get the current debugging context."""
        services = get_services(ctx)
        session = resolve_debug_session(
            services, session_id=session_id, create_if_missing=False
        )
        result = await run_session_action(
            session, lambda: session.tools.get_context(context_type)
        )
        result["session_id"] = session.session_id
        return result

    @mcp.tool()
    @catch_errors()
    async def get_memory(
        address: str,
        session_id: str,
        size: int = 64,
        format: str = "hex",
        ctx: Context = CurrentContext(),
    ) -> Dict[str, Any]:
        """Read memory at the specified address."""
        services = get_services(ctx)
        session = resolve_debug_session(
            services, session_id=session_id, create_if_missing=False
        )
        result = await run_session_action(
            session, lambda: session.tools.get_memory(address, size, format)
        )
        result["session_id"] = session.session_id
        return result
