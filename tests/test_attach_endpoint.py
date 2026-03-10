import threading

import pytest

from pwnomcp.http.attach import run_attach_request
from pwnomcp.http.models import AttachRequest


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


class FakeSession:
    def __init__(self, session_id: str, tools: FakePwndbgTools):
        self.session_id = session_id
        self.tools = tools
        self.lock = threading.RLock()
        self.state = type("State", (), {"pid": None})()


class FakeRegistry:
    def __init__(self, session=None):
        self.session = session

    def get_session(self, _session_id):
        return self.session

    def create_session(self, _session_id):
        return self.session


class FakeServices:
    def __init__(self, registry):
        self.session_registry = registry
        self.default_session_id = "default"


@pytest.mark.asyncio
async def test_attach_endpoint_runs_pre_and_after():
    tools = FakePwndbgTools(attach_success=True)
    session = FakeSession("chal-a", tools)
    services = FakeServices(FakeRegistry(session=session))

    body = AttachRequest(
        pre=["info registers"],
        pid=1337,
        after=["bt"],
        where="target",
        session_id="chal-a",
    )
    response = await run_attach_request(body, services)

    assert response.successful is True
    assert response.attach is not None
    assert response.attach["pid"] == 1337
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
    session = FakeSession("chal-a", tools)
    services = FakeServices(FakeRegistry(session=session))

    body = AttachRequest(
        pre=["info registers"],
        pid=9001,
        after=["should_not_run"],
        session_id="chal-a",
    )
    response = await run_attach_request(body, services)

    assert response.successful is False
    assert "should_not_run" not in response.result


@pytest.mark.asyncio
async def test_attach_endpoint_errors_on_missing_session_mapping():
    services = FakeServices(FakeRegistry(session=None))

    body = AttachRequest(pid=1337, session_id="missing")
    response = await run_attach_request(body, services)

    assert response.successful is False
    assert response.attach is not None
    assert "missing" in response.attach["error"]
