"""
End-to-End test scenarios for Pwno MCP Server

These tests simulate real-world usage scenarios.
"""

import asyncio
import json
import os
import tempfile
from pathlib import Path

import httpx
import pytest


@pytest.fixture
async def mcp_client():
    """Create MCP client for E2E testing"""
    base_url = os.environ.get("MCP_URL", "http://localhost:5500")
    nonce = os.environ.get("MCP_NONCE")
    
    headers = {"Content-Type": "application/json"}
    if nonce:
        headers["X-Nonce"] = nonce

    class E2EClient:
        def __init__(self):
            self.base_url = base_url
            self.headers = headers

        async def call_tool(self, tool_name: str, params: dict):
            """Call an MCP tool"""
            payload = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": params},
                "id": 1,
            }

            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{self.base_url}/sse", headers=self.headers, json=payload
                )
                response.raise_for_status()

                for line in response.text.split("\n"):
                    if line.startswith("data: "):
                        data = json.loads(line[6:])
                        if "result" in data:
                            return data["result"]["content"][0]["text"]

            raise Exception("No result in response")

    return E2EClient()


@pytest.mark.asyncio
class TestE2EScenarios:
    """End-to-end test scenarios"""

    async def test_buffer_overflow_analysis(self, mcp_client):
        """Test analyzing a buffer overflow vulnerability"""
        # Create vulnerable C program
        vuln_code = """
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Vulnerable to buffer overflow
    printf("You entered: %s\\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <input>\\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}
"""
        # Write and compile the vulnerable program
        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
            f.write(vuln_code)
            c_path = f.name

        binary_path = "/tmp/vulnerable_binary"

        try:
            # Compile with debug symbols and no stack protector
            compile_result = await mcp_client.call_tool(
                "run_command",
                {
                    "command": f"gcc -g -fno-stack-protector -z execstack -o {binary_path} {c_path}",
                    "cwd": "/tmp",
                },
            )
            compile_data = json.loads(compile_result)
            assert compile_data["success"] is True

            # Load binary in GDB
            load_result = await mcp_client.call_tool(
                "set_file", {"binary_path": binary_path}
            )
            assert "Binary loaded successfully" in load_result

            # Set breakpoint at vulnerable function
            bp_result = await mcp_client.call_tool(
                "set_breakpoint", {"location": "vulnerable_function"}
            )
            assert "Breakpoint" in bp_result

            # Run with safe input
            run_result = await mcp_client.call_tool(
                "run", {"args": "SafeInput", "interrupt_after": 2}
            )
            assert "State: stopped" in run_result or "State: exited" in run_result

            # Get context to analyze
            context_result = await mcp_client.call_tool(
                "get_context", {"context_type": "stack"}
            )
            # Context should show stack information

        finally:
            os.unlink(c_path)
            if os.path.exists(binary_path):
                os.unlink(binary_path)

    async def test_reverse_engineering_workflow(self, mcp_client):
        """Test a reverse engineering workflow"""
        # Create a simple crackme program
        crackme_code = """
#include <stdio.h>
#include <string.h>

int check_password(const char *input) {
    const char *correct = "s3cr3t_p4ss";
    return strcmp(input, correct) == 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <password>\\n", argv[0]);
        return 1;
    }
    
    if (check_password(argv[1])) {
        printf("Correct! Access granted.\\n");
        return 0;
    } else {
        printf("Wrong password!\\n");
        return 1;
    }
}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
            f.write(crackme_code)
            c_path = f.name

        binary_path = "/tmp/crackme"

        try:
            # Compile the crackme
            compile_result = await mcp_client.call_tool(
                "run_command",
                {"command": f"gcc -o {binary_path} {c_path}", "cwd": "/tmp"},
            )
            compile_data = json.loads(compile_result)
            assert compile_data["success"] is True

            # Load in GDB for analysis
            load_result = await mcp_client.call_tool(
                "set_file", {"binary_path": binary_path}
            )
            assert "Binary loaded successfully" in load_result

            # Disassemble main function
            disasm_result = await mcp_client.call_tool(
                "execute", {"command": "disassemble main"}
            )
            assert "push" in disasm_result or "mov" in disasm_result

            # Set breakpoint at check_password
            bp_result = await mcp_client.call_tool(
                "set_breakpoint", {"location": "check_password"}
            )
            assert "Breakpoint" in bp_result

            # Run with test password
            run_result = await mcp_client.call_tool(
                "run", {"args": "test123", "interrupt_after": 2}
            )
            
            # Check session info
            session_result = await mcp_client.call_tool("get_session_info", {})
            session_data = json.loads(session_result)
            assert session_data["session"]["breakpoints"]

        finally:
            os.unlink(c_path)
            if os.path.exists(binary_path):
                os.unlink(binary_path)

    async def test_exploit_development_scenario(self, mcp_client):
        """Test exploit development workflow"""
        # Create exploit script using pwntools
        exploit_code = """
from pwn import *
import sys

# Simple test to verify pwntools is working
context.arch = 'amd64'
context.os = 'linux'

# Generate a cyclic pattern
pattern = cyclic(100)
print(f"Generated pattern: {pattern[:50].decode()}...")

# Find offset
offset = cyclic_find(b'kaaa')
print(f"Offset of 'kaaa': {offset}")

# Create a simple ROP chain (example)
rop = ROP(ELF('/bin/ls', checksec=False))
print(f"ROP gadgets found: {len(rop.gadgets)}")

print("Exploit development environment working!")
"""
        
        # Execute the exploit development script
        result = await mcp_client.call_tool(
            "execute_python_code", {"code": exploit_code, "cwd": "/tmp"}
        )
        data = json.loads(result)
        assert data["success"] is True
        assert "Exploit development environment working!" in data["stdout"]
        assert "Generated pattern:" in data["stdout"]

    async def test_multi_tool_debugging_session(self, mcp_client):
        """Test a complex debugging session using multiple tools"""
        # Create a program with multiple functions
        complex_code = """
#include <stdio.h>
#include <stdlib.h>

int calculate(int a, int b) {
    return a * b + 10;
}

void process_data(int *data, int size) {
    for (int i = 0; i < size; i++) {
        data[i] = calculate(data[i], 2);
    }
}

int main() {
    int data[] = {1, 2, 3, 4, 5};
    int size = sizeof(data) / sizeof(data[0]);
    
    printf("Before processing:\\n");
    for (int i = 0; i < size; i++) {
        printf("%d ", data[i]);
    }
    printf("\\n");
    
    process_data(data, size);
    
    printf("After processing:\\n");
    for (int i = 0; i < size; i++) {
        printf("%d ", data[i]);
    }
    printf("\\n");
    
    return 0;
}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
            f.write(complex_code)
            c_path = f.name

        binary_path = "/tmp/complex_program"

        try:
            # Compile with debug symbols
            compile_result = await mcp_client.call_tool(
                "run_command",
                {"command": f"gcc -g -O0 -o {binary_path} {c_path}", "cwd": "/tmp"},
            )
            compile_data = json.loads(compile_result)
            assert compile_data["success"] is True

            # Load binary
            await mcp_client.call_tool("set_file", {"binary_path": binary_path})

            # Set multiple breakpoints
            await mcp_client.call_tool("set_breakpoint", {"location": "main"})
            await mcp_client.call_tool("set_breakpoint", {"location": "calculate"})
            await mcp_client.call_tool("set_breakpoint", {"location": "process_data"})

            # Run the program
            run_result = await mcp_client.call_tool("run", {"args": ""})
            
            # Step through execution
            for _ in range(3):
                step_result = await mcp_client.call_tool(
                    "step_control", {"command": "continue"}
                )
                if "exited" in step_result:
                    break

            # Get final session info
            session_result = await mcp_client.call_tool("get_session_info", {})
            session_data = json.loads(session_result)
            
            # Verify multiple breakpoints were set
            assert len(session_data["session"]["breakpoints"]) >= 2

        finally:
            os.unlink(c_path)
            if os.path.exists(binary_path):
                os.unlink(binary_path)

    async def test_concurrent_process_management(self, mcp_client):
        """Test managing multiple concurrent processes"""
        processes = []
        
        try:
            # Spawn multiple background processes
            for i in range(3):
                result = await mcp_client.call_tool(
                    "spawn_process",
                    {"command": f"sleep {30 + i}", "cwd": "/tmp"},
                )
                data = json.loads(result)
                assert data["success"] is True
                processes.append(data["pid"])

            # List all processes
            list_result = await mcp_client.call_tool("list_processes", {})
            list_data = json.loads(list_result)
            assert list_data["count"] >= 3

            # Check each process status
            for pid in processes:
                status_result = await mcp_client.call_tool(
                    "get_process", {"pid": pid}
                )
                status_data = json.loads(status_result)
                assert status_data["status"] == "running"

        finally:
            # Clean up all processes
            for pid in processes:
                try:
                    await mcp_client.call_tool("kill_process", {"pid": pid})
                except:
                    pass
