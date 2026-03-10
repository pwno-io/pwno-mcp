import pytest

from pwnomcp.server import create_mcp


@pytest.mark.asyncio
async def test_python_execution_tool_guidance_in_descriptions():
    mcp = create_mcp()
    tools = await mcp.list_tools(run_middleware=False)
    descriptions = {tool.name: (tool.description or "").lower() for tool in tools}

    assert "ad-hoc python code" in descriptions["execute_python_code"]
    assert (
        "only persist files in /workspace when the user explicitly asks"
        in descriptions["execute_python_code"]
    )

    assert "a .py file already exists" in descriptions["execute_python_script"]
    assert "execute_python_code" in descriptions["execute_python_script"]

    assert "non-python shell commands" in descriptions["run_command"]
    assert "execute_python_code" in descriptions["run_command"]
    assert "execute_python_script" in descriptions["run_command"]
    assert "under /workspace" in descriptions["run_command"]

    assert "under /workspace" in descriptions["spawn_process"]
    assert "under /workspace" in descriptions["set_file"]
    assert "under /workspace" in descriptions["execute_python_script"]
    assert "under /workspace" in descriptions["fetch_repo"]

    assert "transient pwncli exploit driver" in descriptions["pwncli"]
    assert "only create persistent /workspace scripts" in descriptions["pwncli"]
    assert "binary_path" in descriptions["pwncli"]
