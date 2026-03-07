"""Path and runtime directory helpers for Pwno MCP."""

from __future__ import annotations

from dataclasses import dataclass
import os
import re
import tempfile
from typing import Optional

DEFAULT_WORKSPACE = "/workspace"
DEFAULT_RUNTIME_ROOT = os.environ.get(
    "PWNO_RUNTIME_ROOT", os.path.join(tempfile.gettempdir(), "pwno")
)


@dataclass
class RuntimePaths:
    """Filesystem layout used by server-managed runtime artifacts."""

    workspace_root: str
    runtime_root: str
    sessions_dir: str
    processes_dir: str
    python_dir: str
    repos_dir: str


def build_runtime_paths(
    workspace_root: str = DEFAULT_WORKSPACE,
    runtime_root: str = DEFAULT_RUNTIME_ROOT,
) -> RuntimePaths:
    """Build and ensure runtime directories exist."""
    resolved_workspace = os.path.normpath(workspace_root)
    resolved_runtime = os.path.normpath(runtime_root)
    paths = RuntimePaths(
        workspace_root=resolved_workspace,
        runtime_root=resolved_runtime,
        sessions_dir=os.path.join(resolved_runtime, "sessions"),
        processes_dir=os.path.join(resolved_runtime, "processes"),
        python_dir=os.path.join(resolved_runtime, "python"),
        repos_dir=os.path.join(resolved_runtime, "repos"),
    )
    for path in [
        paths.workspace_root,
        paths.runtime_root,
        paths.sessions_dir,
        paths.processes_dir,
        paths.python_dir,
        paths.repos_dir,
    ]:
        os.makedirs(path, exist_ok=True)
    return paths


def sanitize_session_id(value: Optional[str]) -> str:
    """Return a filesystem-safe session identifier."""
    if value is None:
        return "session"
    sanitized = re.sub(r"[^A-Za-z0-9_.-]", "_", value).strip("._")
    return sanitized or "session"


def _within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def _map_host_workspace_path(path: str, workspace_root: str) -> Optional[str]:
    marker = f"{os.sep}workspace"
    normalized = path.rstrip(os.sep)
    if normalized.endswith(marker):
        return workspace_root
    marker_with_sep = marker + os.sep
    idx = normalized.find(marker_with_sep)
    if idx == -1:
        return None
    suffix = normalized[idx + len(marker) :]
    return os.path.normpath(workspace_root + suffix)


def resolve_workspace_path(
    raw_path: str,
    workspace_root: str = DEFAULT_WORKSPACE,
    require_exists: bool = False,
    kind: str = "path",
) -> str:
    """Resolve user-provided paths into the server workspace namespace.

    Accepts:
    - absolute paths already under /workspace
    - relative paths (resolved under /workspace)
    - host absolute paths containing '/workspace/...', remapped to container path
    """
    if not raw_path or not raw_path.strip():
        raise ValueError(f"{kind} cannot be empty")

    workspace_root = os.path.normpath(workspace_root)
    candidate = raw_path.strip()

    if os.path.isabs(candidate):
        candidate = os.path.normpath(candidate)
        if not _within(candidate, workspace_root):
            mapped = _map_host_workspace_path(candidate, workspace_root)
            if mapped and _within(mapped, workspace_root):
                candidate = mapped
            else:
                raise ValueError(
                    f"{kind} must be in {workspace_root}. "
                    f"Got '{raw_path}'. Use a container path like '{workspace_root}/<name>'."
                )
    else:
        normalized_rel = candidate
        if normalized_rel.startswith(f"workspace{os.sep}"):
            normalized_rel = normalized_rel[len("workspace") + 1 :]
        elif normalized_rel == "workspace":
            normalized_rel = ""
        candidate = os.path.normpath(os.path.join(workspace_root, normalized_rel))
        if not _within(candidate, workspace_root):
            raise ValueError(
                f"{kind} escapes {workspace_root}: '{raw_path}'. "
                f"Use a safe path under {workspace_root}."
            )

    if require_exists and not os.path.exists(candidate):
        raise FileNotFoundError(
            f"{kind} not found: '{candidate}'. Ensure the file exists in {workspace_root}."
        )

    return candidate


def resolve_workspace_cwd(
    cwd: Optional[str], workspace_root: str = DEFAULT_WORKSPACE
) -> str:
    """Resolve an optional working directory to a workspace directory."""
    if cwd is None:
        return os.path.normpath(workspace_root)
    resolved = resolve_workspace_path(
        cwd, workspace_root=workspace_root, require_exists=False, kind="cwd"
    )
    os.makedirs(resolved, exist_ok=True)
    return resolved
