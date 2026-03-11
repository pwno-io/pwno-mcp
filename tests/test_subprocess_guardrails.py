from pwnomcp.tools.backends import subproc as subproc_module
from pwnomcp.tools.backends.subproc import SubprocessTools


def test_run_command_blocks_inline_python_c():
    tools = SubprocessTools()

    result = tools.run_command('python3 -c "print(1)"')

    assert result["success"] is False
    assert result["type"] == "ToolUsageError"
    assert result["recommended_tool"] == "execute_python_code"
    assert "python -c" in result["error"].lower()


def test_run_command_blocks_shell_wrapped_inline_python_c():
    tools = SubprocessTools()

    result = tools.run_command("sh -lc 'python3 -c \"print(1)\"'")

    assert result["success"] is False
    assert result["type"] == "ToolUsageError"
    assert result["recommended_tool"] == "execute_python_code"


def test_run_command_blocks_workspace_elf_execution(tmp_path, monkeypatch):
    monkeypatch.setattr(subproc_module, "DEFAULT_WORKSPACE", str(tmp_path))
    target = tmp_path / "chal"
    target.write_bytes(b"\x7fELF" + b"\x00" * 16)
    target.chmod(0o755)
    tools = SubprocessTools()

    result = tools.run_command(str(target), cwd=str(tmp_path))

    assert result["success"] is False
    assert result["type"] == "ToolUsageError"
    assert result["recommended_tool"] == "set_file+run"
    assert "under /workspace" in result["error"].lower()


def test_spawn_process_blocks_workspace_elf_execution(tmp_path, monkeypatch):
    monkeypatch.setattr(subproc_module, "DEFAULT_WORKSPACE", str(tmp_path))
    target = tmp_path / "chal"
    target.write_bytes(b"\x7fELF" + b"\x00" * 16)
    target.chmod(0o755)
    tools = SubprocessTools()

    result = tools.spawn_process(str(target), cwd=str(tmp_path))

    assert result["success"] is False
    assert result["type"] == "ToolUsageError"
    assert result["recommended_tool"] == "set_file+run"
