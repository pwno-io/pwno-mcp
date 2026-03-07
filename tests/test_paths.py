import os

import pytest

from pwnomcp.utils.paths import build_runtime_paths, resolve_workspace_path


def test_resolve_workspace_path_from_relative():
    assert (
        resolve_workspace_path("chall", workspace_root="/workspace")
        == "/workspace/chall"
    )


def test_resolve_workspace_path_from_host_mounted_workspace_path():
    host_style = "/home/user/project/workspace/bin/chall"
    assert (
        resolve_workspace_path(host_style, workspace_root="/workspace")
        == "/workspace/bin/chall"
    )


def test_resolve_workspace_path_rejects_outside_workspace_absolute_path():
    with pytest.raises(ValueError):
        resolve_workspace_path("/bin/ls", workspace_root="/workspace")


def test_build_runtime_paths_creates_isolated_directories(tmp_path):
    workspace_root = str(tmp_path / "workspace")
    runtime_root = str(tmp_path / "runtime")
    paths = build_runtime_paths(
        workspace_root=workspace_root, runtime_root=runtime_root
    )

    assert paths.workspace_root == workspace_root
    assert paths.runtime_root == runtime_root
    assert os.path.isdir(paths.sessions_dir)
    assert os.path.isdir(paths.processes_dir)
    assert os.path.isdir(paths.python_dir)
    assert os.path.isdir(paths.repos_dir)
