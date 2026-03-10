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
        """Execute an existing Python script in the shared environment.

        Use this when a .py file already exists; for one-off snippets, prefer
        execute_python_code. `script_path` and `cwd` should point inside the
        container under /workspace.
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
        """Execute ad-hoc Python code using a temporary runtime script.

        Prefer this for quick probes and analysis, and only persist files in /workspace when the user explicitly asks.
        If provided, `cwd` is resolved inside the container under /workspace.
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
        """Install additional Python packages using uv."""
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
