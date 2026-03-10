import json
import os
from typing import Optional

from fastmcp import Context, FastMCP
from fastmcp.dependencies import CurrentContext

from pwnomcp.tools.common import get_services, run_blocking
from pwnomcp.utils.paths import DEFAULT_WORKSPACE, resolve_workspace_path


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def fetch_repo(
        repo_url: str,
        version: Optional[str] = None,
        target_dir: Optional[str] = None,
        shallow: bool = True,
        ctx: Context = CurrentContext(),
    ) -> str:
        """Fetch a git repository into /workspace.

        Args:
            repo_url: Repository URL (https or ssh).
            version: Branch/tag/commit to checkout (None = default branch).
            target_dir: Optional specific directory; defaults to a name derived from
                the URL. When provided, it must be inside the container under
                /workspace; relative paths resolve under /workspace.
            shallow: Whether to clone shallowly.
        """
        services = get_services(ctx)
        tools = services.git_tools
        if target_dir:
            target_dir = resolve_workspace_path(
                target_dir,
                workspace_root=DEFAULT_WORKSPACE,
                require_exists=False,
                kind="target_dir",
            )
        else:
            repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
            target_dir = os.path.join(DEFAULT_WORKSPACE, repo_name)
        result = await run_blocking(
            lambda: tools.fetch_repo(repo_url, version, target_dir, shallow)
        )
        return json.dumps(result, indent=2)
