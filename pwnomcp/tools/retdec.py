import json

from fastmcp import Context, FastMCP
from fastmcp.dependencies import CurrentContext

from pwnomcp.tools.common import get_services


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def get_retdec_status(ctx: Context = CurrentContext()) -> str:
        """Get the current RetDec decompilation status, lazily initializing as needed."""
        services = get_services(ctx)
        analyzer = services.retdec_analyzer
        if not analyzer._initialized:
            await analyzer.initialize()
        status = analyzer.get_status()
        return json.dumps(status, indent=2)

    @mcp.tool()
    async def get_decompiled_code(ctx: Context = CurrentContext()) -> str:
        """Return RetDec decompiled C code if available."""
        services = get_services(ctx)
        analyzer = services.retdec_analyzer
        if not analyzer._initialized:
            await analyzer.initialize()
        code = analyzer.get_decompiled_code()
        if code:
            return json.dumps({"status": "success", "decompiled_code": code}, indent=2)

        status = analyzer.get_status()
        return json.dumps(
            {
                "status": "unavailable",
                "reason": status.get("status"),
                "details": status,
            },
            indent=2,
        )
