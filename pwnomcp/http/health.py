from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse


def register_health_routes(mcp: FastMCP) -> None:
    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(_request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok"})
