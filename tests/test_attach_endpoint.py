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


class FakeRegistry:
    def __init__(self, session=None):
        self.session = session

    def get_session(self, _session_id):
        return self.session

    def create_session(self, _session_id):
        return self.session

    def get_session_for_pid(self, _pid):
        return self.session

    def ensure_session(self, _default_session_id):
        return self.session


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
            where="target",
            script_pid=42,
        )
        response = await attach_router.attach_endpoint(body)
    finally:
        mcp_router.pwndbg_tools = original

    assert response.successful is True
    assert response.attach is not None
    assert response.attach["pid"] == 1337
    assert response.attach["script_pid"] == 42
    assert response.result["set-file"]["success"] is True
    assert "info registers" in response.result
    assert "bt" in response.result
    assert tools.calls == [
        ("set_file", "/workspace/target"),
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


@pytest.mark.asyncio
async def test_attach_endpoint_errors_on_missing_script_pid_mapping():
    original_registry = mcp_router.session_registry
    original_default_session_id = mcp_router.default_session_id

    mcp_router.session_registry = FakeRegistry(session=None)
    mcp_router.default_session_id = "default"

    try:
        body = attach_router.AttachRequest(pid=1337, script_pid=4242)
        response = await attach_router.attach_endpoint(body)
    finally:
        mcp_router.session_registry = original_registry
        mcp_router.default_session_id = original_default_session_id

    assert response.successful is False
    assert response.attach is not None
    assert "script_pid=4242" in response.attach["error"]
