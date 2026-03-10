import json
from typing import Optional

from fastmcp import Context, FastMCP
from fastmcp.dependencies import CurrentContext

from pwnomcp.tools.common import get_services, run_blocking
from pwnomcp.utils.paths import (
    DEFAULT_WORKSPACE,
    resolve_workspace_cwd,
    resolve_workspace_path,
)


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def execute_python_script(
        script_path: str,
        args: Optional[str] = None,
        cwd: Optional[str] = None,
        timeout: float = 300.0,
        ctx: Context = CurrentContext(),
    ) -> str:
        """Execute an existing Python script within the shared environment.

        Args:
            script_path: Path to the script. Use a container-visible path under
                /workspace; relative paths resolve under /workspace.
            args: Space-separated args for the script.
            cwd: Working directory (default /workspace). Use a container-visible path
                under /workspace; relative paths resolve under /workspace.
            timeout: Seconds to wait before termination.
        """
        services = get_services(ctx)
        tools = services.python_tools
        resolved_script_path = resolve_workspace_path(
            script_path,
            workspace_root=DEFAULT_WORKSPACE,
            require_exists=True,
            kind="script_path",
        )
        cwd = resolve_workspace_cwd(cwd, workspace_root=DEFAULT_WORKSPACE)
        args_list = args.split() if args else None
        result = await run_blocking(
            lambda: tools.execute_script(resolved_script_path, args_list, cwd, timeout)
        )
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def execute_python_code(
        code: str,
        cwd: Optional[str] = None,
        timeout: float = 300.0,
        ctx: Context = CurrentContext(),
    ) -> str:
        """Execute Python code dynamically in the shared environment.

        Args:
            code: Python source code to run.
            cwd: Working directory (default /workspace). If provided, use a
                container-visible path under /workspace; relative paths resolve under
                /workspace.
            timeout: Seconds to wait before termination.

        Prefer this for quick probes and analysis, and only persist files in /workspace when the user explicitly asks.
        """
        services = get_services(ctx)
        tools = services.python_tools
        cwd = resolve_workspace_cwd(cwd, workspace_root=DEFAULT_WORKSPACE)
        result = await run_blocking(lambda: tools.execute_code(code, cwd, timeout))
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def install_python_packages(
        packages: str,
        upgrade: bool = False,
        ctx: Context = CurrentContext(),
    ) -> str:
        """Install additional Python packages using the shared package manager (uv).

        Args:
            packages: Space-separated package list.
            upgrade: If True, perform upgrades when applicable.
        """
        services = get_services(ctx)
        tools = services.python_tools
        packages_list = packages.split()
        result = await run_blocking(
            lambda: tools.install_packages(packages_list, upgrade)
        )
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def list_python_packages(ctx: Context = CurrentContext()) -> str:
        """List all packages installed in the shared Python environment."""
        services = get_services(ctx)
        result = await run_blocking(services.python_tools.get_installed_packages)
        return json.dumps(result, indent=2)
