#!/usr/bin/env python3
"""
MCP Client Test Harness for Pwno MCP Server

This script tests the MCP server by acting as an MCP client,
calling various tools and validating responses.
"""

import asyncio
import json
import os
import sys
from typing import Any, Dict, Optional

import httpx


class MCPTestClient:
    """Test client for MCP server interaction"""

    def __init__(self, base_url: str = "http://localhost:5500", nonce: Optional[str] = None):
        """
        Initialize MCP test client.
        
        :param base_url: Base URL of the MCP server
        :param nonce: Optional authentication nonce
        """
        self.base_url = base_url.rstrip("/")
        self.headers = {"Content-Type": "application/json"}
        if nonce:
            self.headers["X-Nonce"] = nonce

    async def health_check(self) -> Dict[str, Any]:
        """Check server health status"""
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{self.base_url}/health")
            response.raise_for_status()
            return response.json()

    async def call_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Call an MCP tool.
        
        :param tool_name: Name of the tool to call
        :param params: Parameters for the tool
        :returns: Tool response
        """
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
            content = response.text
            for line in content.split("\n"):
                if line.startswith("data: "):
                    data = json.loads(line[6:])
                    if "result" in data:
                        return data["result"]
                    elif "error" in data:
                        raise Exception(f"Tool error: {data['error']}")

            raise Exception("No result in response")

    async def list_tools(self) -> Dict[str, Any]:
        """List available MCP tools"""
        payload = {"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 1}

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/sse", headers=self.headers, json=payload
            )
            response.raise_for_status()

            # Parse SSE response
            content = response.text
            for line in content.split("\n"):
                if line.startswith("data: "):
                    data = json.loads(line[6:])
                    if "result" in data:
                        return data["result"]

            raise Exception("No result in response")


class TestSuite:
    """Test suite for MCP server"""

    def __init__(self, client: MCPTestClient):
        self.client = client
        self.passed = 0
        self.failed = 0
        self.results = []

    async def run_test(self, name: str, test_func):
        """Run a single test"""
        try:
            print(f"Running: {name}...", end=" ")
            await test_func()
            print("✅ PASSED")
            self.passed += 1
            self.results.append({"test": name, "status": "passed"})
        except Exception as e:
            print(f"❌ FAILED: {e}")
            self.failed += 1
            self.results.append({"test": name, "status": "failed", "error": str(e)})

    async def test_health_check(self):
        """Test health endpoint"""
        health = await self.client.health_check()
        assert health["status"] in ["healthy", "degraded"]
        assert "components" in health

    async def test_list_tools(self):
        """Test listing available tools"""
        tools = await self.client.list_tools()
        assert "tools" in tools
        assert len(tools["tools"]) > 0

        # Check for expected tools
        tool_names = [tool["name"] for tool in tools["tools"]]
        expected_tools = [
            "execute",
            "set_file",
            "run",
            "get_context",
            "set_breakpoint",
            "run_command",
            "spawn_process",
        ]
        for expected in expected_tools:
            assert expected in tool_names, f"Missing tool: {expected}"

    async def test_run_command(self):
        """Test running a system command"""
        result = await self.client.call_tool(
            "run_command", {"command": "echo 'Hello from MCP test'", "cwd": "/tmp"}
        )
        result_data = json.loads(result["content"][0]["text"])
        assert result_data["success"] is True
        assert "Hello from MCP test" in result_data["stdout"]

    async def test_spawn_process(self):
        """Test spawning a background process"""
        # Spawn a sleep process
        result = await self.client.call_tool(
            "spawn_process", {"command": "sleep 5", "cwd": "/tmp"}
        )
        result_data = json.loads(result["content"][0]["text"])
        assert result_data["success"] is True
        assert "pid" in result_data

        # Get process status
        pid = result_data["pid"]
        status_result = await self.client.call_tool("get_process", {"pid": pid})
        status_data = json.loads(status_result["content"][0]["text"])
        assert status_data["success"] is True
        assert status_data["status"] == "running"

        # Kill the process
        kill_result = await self.client.call_tool("kill_process", {"pid": pid})
        kill_data = json.loads(kill_result["content"][0]["text"])
        assert kill_data["success"] is True

    async def test_python_execution(self):
        """Test Python code execution"""
        code = """
import sys
print("Python version:", sys.version)
print("Test successful!")
"""
        result = await self.client.call_tool(
            "execute_python_code", {"code": code, "cwd": "/tmp"}
        )
        result_data = json.loads(result["content"][0]["text"])
        assert result_data["success"] is True
        assert "Test successful!" in result_data["stdout"]

    async def test_gdb_initialization(self):
        """Test GDB initialization and basic commands"""
        # Create a simple test binary
        c_code = """
#include <stdio.h>
int main() {
    printf("Test program\\n");
    return 0;
}
"""
        # Write C file
        with open("/tmp/test.c", "w") as f:
            f.write(c_code)

        # Compile
        compile_result = await self.client.call_tool(
            "run_command",
            {"command": "gcc -g -o /tmp/test_binary /tmp/test.c", "cwd": "/tmp"},
        )
        compile_data = json.loads(compile_result["content"][0]["text"])
        assert compile_data["success"] is True

        # Load binary in GDB
        load_result = await self.client.call_tool(
            "set_file", {"binary_path": "/tmp/test_binary"}
        )
        assert "Binary loaded successfully" in load_result["content"][0]["text"]

        # Set a breakpoint
        bp_result = await self.client.call_tool("set_breakpoint", {"location": "main"})
        assert "Breakpoint" in bp_result["content"][0]["text"]

    async def test_git_operations(self):
        """Test git repository fetching"""
        # Fetch a small test repository
        result = await self.client.call_tool(
            "fetch_repo",
            {
                "repo_url": "https://github.com/octocat/Hello-World.git",
                "target_dir": "/tmp/test-repo",
                "shallow": True,
            },
        )
        result_data = json.loads(result["content"][0]["text"])
        assert result_data["success"] is True
        assert "path" in result_data

    async def test_session_info(self):
        """Test getting session information"""
        result = await self.client.call_tool("get_session_info", {})
        session_data = json.loads(result["content"][0]["text"])
        assert "session" in session_data
        assert "gdb_state" in session_data

    async def test_retdec_status(self):
        """Test RetDec analyzer status"""
        result = await self.client.call_tool("get_retdec_status", {})
        status_data = json.loads(result["content"][0]["text"])
        assert "status" in status_data

    async def run_all_tests(self):
        """Run all tests in the suite"""
        print("\n" + "=" * 60)
        print("MCP SERVER TEST SUITE")
        print("=" * 60 + "\n")

        # Run tests
        await self.run_test("Health Check", self.test_health_check)
        await self.run_test("List Tools", self.test_list_tools)
        await self.run_test("Run Command", self.test_run_command)
        await self.run_test("Spawn Process", self.test_spawn_process)
        await self.run_test("Python Execution", self.test_python_execution)
        await self.run_test("GDB Initialization", self.test_gdb_initialization)
        await self.run_test("Git Operations", self.test_git_operations)
        await self.run_test("Session Info", self.test_session_info)
        await self.run_test("RetDec Status", self.test_retdec_status)

        # Print summary
        print("\n" + "=" * 60)
        print(f"RESULTS: {self.passed} passed, {self.failed} failed")
        print("=" * 60)

        # Write results to file
        with open("test-results.json", "w") as f:
            json.dump(
                {
                    "passed": self.passed,
                    "failed": self.failed,
                    "total": self.passed + self.failed,
                    "results": self.results,
                },
                f,
                indent=2,
            )

        return self.failed == 0


async def main():
    """Main test runner"""
    # Get server URL and nonce from environment
    server_url = os.environ.get("MCP_SERVER_URL", "http://localhost:5500")
    nonce = os.environ.get("MCP_NONCE")

    # Create client and test suite
    client = MCPTestClient(server_url, nonce)
    suite = TestSuite(client)

    # Run tests
    success = await suite.run_all_tests()

    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    asyncio.run(main())
