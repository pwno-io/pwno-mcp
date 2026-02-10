import pytest

from pwnomcp.router import attach as attach_router
from pwnomcp.router import mcp as mcp_router


class FakePwndbgTools:
    def __init__(self, attach_success: bool = True):
        self.attach_success = attach_success
        self.calls = []

    def set_file(self, path: str):
        self.calls.append(("set_file", path))
        return {"success": True, "command": f"set-file {path}"}

    def execute(self, command: str):
        self.calls.append(("execute", command))
        return {"success": True, "command": command}

    def attach(self, pid: int):
        self.calls.append(("attach", pid))
        result = {
            "success": self.attach_success,
            "command": "attach",
            "state": "stopped",
            "pid": pid,
        }
        return result, []


@pytest.mark.asyncio
async def test_attach_endpoint_runs_pre_and_after():
    tools = FakePwndbgTools(attach_success=True)
    original = mcp_router.pwndbg_tools
    mcp_router.pwndbg_tools = tools
    try:
        body = attach_router.AttachRequest(
            pre=["info registers"],
            pid=1337,
            after=["bt"],
            where="/bin/ls",
            script_pid=42,
        )
        response = await attach_router.attach_endpoint(body)
    finally:
        mcp_router.pwndbg_tools = original

    assert response.successful is True
    assert response.attach["pid"] == 1337
    assert response.attach["script_pid"] == 42
    assert response.result["set-file"]["success"] is True
    assert "info registers" in response.result
    assert "bt" in response.result
    assert tools.calls == [
        ("set_file", "/bin/ls"),
        ("execute", "info registers"),
        ("attach", 1337),
        ("execute", "bt"),
    ]


@pytest.mark.asyncio
async def test_attach_endpoint_skips_after_when_attach_fails():
    tools = FakePwndbgTools(attach_success=False)
    original = mcp_router.pwndbg_tools
    mcp_router.pwndbg_tools = tools
    try:
        body = attach_router.AttachRequest(
            pre=["info registers"],
            pid=9001,
            after=["should_not_run"],
        )
        response = await attach_router.attach_endpoint(body)
    finally:
        mcp_router.pwndbg_tools = original

    assert response.successful is False
    assert "should_not_run" not in response.result
