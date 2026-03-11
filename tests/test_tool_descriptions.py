import pytest

from pwnomcp.server import create_mcp


@pytest.mark.asyncio
async def test_python_execution_tool_guidance_in_descriptions():
    mcp = create_mcp()
    tools = await mcp.list_tools(run_middleware=False)
    descriptions = {tool.name: (tool.description or "").lower() for tool in tools}

    assert "info registers" in descriptions["execute"]
    assert "current gdb state" in descriptions["execute"]

    assert "python code dynamically" in descriptions["execute_python_code"]
    assert (
        "only persist files in /workspace when the user explicitly asks"
        in descriptions["execute_python_code"]
    )

    assert "script_path" in descriptions["execute_python_script"]
    assert (
        "timeout: seconds to wait before termination"
        in descriptions["execute_python_script"]
    )

    assert "do not use this to run the target binary" in descriptions["run_command"]
    assert "stdout/stderr/exit code" in descriptions["run_command"]
    assert "under /workspace" in descriptions["run_command"]
    assert "execute_python_code" in descriptions["run_command"]
    assert "pwncli" in descriptions["run_command"]
    assert "use this for build and helper commands" in descriptions["run_command"]

    assert "under /workspace" in descriptions["spawn_process"]
    assert "do not use this to run the target binary" in descriptions["spawn_process"]
    assert "set_file + run" in descriptions["spawn_process"]
    assert "under /workspace" in descriptions["set_file"]
    assert "under /workspace" in descriptions["execute_python_script"]
    assert "under /workspace" in descriptions["fetch_repo"]
    assert "branch/tag/commit" in descriptions["fetch_repo"]
    assert "equivalent to --start" in descriptions["run"]
    assert "does not append a newline" in descriptions["sendinput"]
    assert "0xdeadbeef" in descriptions["get_memory"]

    assert "pwncli_attach_result" in descriptions["pwncli"]
    assert "persistent" in descriptions["pwncli"]
    assert "/workspace scripts" in descriptions["pwncli"]
    assert "binary_path" in descriptions["pwncli"]
