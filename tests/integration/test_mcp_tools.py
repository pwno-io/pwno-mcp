"""
Integration tests for MCP tools

These tests require a running MCP server instance.
"""

import asyncio
import json
import os
import tempfile
from pathlib import Path

import httpx
import pytest


@pytest.fixture
def mcp_url():
    """Get MCP server URL from environment or use default"""
    return os.environ.get("MCP_URL", "http://localhost:5500")


@pytest.fixture
def mcp_nonce():
    """Get MCP nonce from environment if authentication is enabled"""
    return os.environ.get("MCP_NONCE")


@pytest.fixture
async def mcp_client(mcp_url, mcp_nonce):
    """Create an MCP client for testing"""
    headers = {"Content-Type": "application/json"}
    if mcp_nonce:
        headers["X-Nonce"] = mcp_nonce

    class MCPClient:
        def __init__(self):
            self.base_url = mcp_url
            self.headers = headers

        async def call_tool(self, tool_name: str, params: dict):
            """Call an MCP tool and return the result"""
            payload = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": params},
                "id": 1,
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.base_url}/sse", headers=self.headers, json=payload
                )
                response.raise_for_status()

                # Parse SSE response
                for line in response.text.split("\n"):
                    if line.startswith("data: "):
                        data = json.loads(line[6:])
                        if "result" in data:
                            return data["result"]["content"][0]["text"]

            raise Exception("No result in response")

    return MCPClient()


@pytest.mark.asyncio
class TestMCPTools:
    """Test MCP tool functionality"""

    async def test_health_endpoint(self, mcp_url):
        """Test that the health endpoint is accessible"""
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{mcp_url}/health")
            assert response.status_code == 200
            data = response.json()
            assert data["status"] in ["healthy", "degraded"]
            assert "components" in data

    async def test_execute_command(self, mcp_client):
        """Test executing GDB commands"""
        result = await mcp_client.call_tool("execute", {"command": "help"})
        assert "List of classes of commands" in result

    async def test_run_system_command(self, mcp_client):
        """Test running system commands"""
        result = await mcp_client.call_tool(
            "run_command", {"command": "echo 'Integration test'", "cwd": "/tmp"}
        )
        data = json.loads(result)
        assert data["success"] is True
        assert "Integration test" in data["stdout"]

    async def test_spawn_and_kill_process(self, mcp_client):
        """Test spawning and killing background processes"""
        # Spawn a process
        spawn_result = await mcp_client.call_tool(
            "spawn_process", {"command": "sleep 30", "cwd": "/tmp"}
        )
        spawn_data = json.loads(spawn_result)
        assert spawn_data["success"] is True
        pid = spawn_data["pid"]

        # Check process status
        status_result = await mcp_client.call_tool("get_process", {"pid": pid})
        status_data = json.loads(status_result)
        assert status_data["status"] == "running"

        # Kill the process
        kill_result = await mcp_client.call_tool("kill_process", {"pid": pid})
        kill_data = json.loads(kill_result)
        assert kill_data["success"] is True

    async def test_python_script_execution(self, mcp_client):
        """Test Python script execution"""
        # Create a test script
        script_content = """
import json
data = {"test": "success", "value": 42}
print(json.dumps(data))
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            f.write(script_content)
            script_path = f.name

        try:
            result = await mcp_client.call_tool(
                "execute_python_script", {"script_path": script_path}
            )
            data = json.loads(result)
            assert data["success"] is True
            output = json.loads(data["stdout"].strip())
            assert output["test"] == "success"
            assert output["value"] == 42
        finally:
            os.unlink(script_path)

    async def test_python_code_execution(self, mcp_client):
        """Test direct Python code execution"""
        code = """
import sys
import platform
print(f"Python {sys.version}")
print(f"Platform: {platform.platform()}")
print("Test completed successfully")
"""
        result = await mcp_client.call_tool("execute_python_code", {"code": code})
        data = json.loads(result)
        assert data["success"] is True
        assert "Test completed successfully" in data["stdout"]

    async def test_gdb_binary_loading(self, mcp_client):
        """Test loading a binary in GDB"""
        # Create a test binary
        c_code = """
#include <stdio.h>
int main() {
    int x = 42;
    printf("Value: %d\\n", x);
    return 0;
}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
            f.write(c_code)
            c_path = f.name

        binary_path = "/tmp/test_binary"

        try:
            # Compile the binary
            compile_result = await mcp_client.call_tool(
                "run_command",
                {"command": f"gcc -g -o {binary_path} {c_path}", "cwd": "/tmp"},
            )
            compile_data = json.loads(compile_result)
            assert compile_data["success"] is True

            # Load the binary in GDB
            load_result = await mcp_client.call_tool(
                "set_file", {"binary_path": binary_path}
            )
            assert "Binary loaded successfully" in load_result

            # Set a breakpoint
            bp_result = await mcp_client.call_tool(
                "set_breakpoint", {"location": "main"}
            )
            assert "Breakpoint" in bp_result

        finally:
            os.unlink(c_path)
            if os.path.exists(binary_path):
                os.unlink(binary_path)

    async def test_session_info(self, mcp_client):
        """Test getting session information"""
        result = await mcp_client.call_tool("get_session_info", {})
        data = json.loads(result)
        assert "session" in data
        assert "gdb_state" in data
        session = data["session"]
        assert "state" in session
        assert "breakpoints" in session

    async def test_git_repository_fetch(self, mcp_client):
        """Test fetching a git repository"""
        result = await mcp_client.call_tool(
            "fetch_repo",
            {
                "repo_url": "https://github.com/octocat/Hello-World.git",
                "target_dir": "/tmp/test-hello-world",
                "shallow": True,
            },
        )
        data = json.loads(result)
        assert data["success"] is True
        assert data["path"] == "/tmp/test-hello-world"

        # Clean up
        import shutil

        if os.path.exists("/tmp/test-hello-world"):
            shutil.rmtree("/tmp/test-hello-world")

    async def test_install_python_package(self, mcp_client):
        """Test installing Python packages"""
        result = await mcp_client.call_tool(
            "install_python_packages", {"packages": "cowsay", "upgrade": False}
        )
        data = json.loads(result)
        assert data["success"] is True

        # Verify installation
        list_result = await mcp_client.call_tool("list_python_packages", {})
        list_data = json.loads(list_result)
        assert "cowsay" in list_data["packages"]

    async def test_retdec_status(self, mcp_client):
        """Test RetDec analyzer status"""
        result = await mcp_client.call_tool("get_retdec_status", {})
        data = json.loads(result)
        assert "status" in data
        # Status can be "not_analyzed", "skipped", "success", or "failed"
        assert data["status"] in [
            "not_analyzed",
            "skipped",
            "success",
            "failed",
        ]
