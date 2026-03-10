from pwnomcp.server import mcp

app = mcp.http_app(path="/mcp")
