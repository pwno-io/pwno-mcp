import json
from typing import Optional

from fastmcp import Context, FastMCP
from fastmcp.dependencies import CurrentContext

from pwnomcp.tools.common import get_services, run_blocking
from pwnomcp.utils.paths import DEFAULT_WORKSPACE, resolve_workspace_cwd


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def run_command(
        command: str,
        cwd: Optional[str] = None,
        timeout: float = 30.0,
        ctx: Context = CurrentContext(),
    ) -> str:
        """Execute a system command and wait for completion.

        Note:
            Do not use this to run the target binary under analysis; use the dedicated
            tools instead.

        Args:
            command: Shell command to run.
            cwd: Working directory (defaults to /workspace). Use a container-visible path
                under /workspace; relative paths resolve under /workspace.
            timeout: Timeout in seconds.

        Returns:
            JSON string with stdout/stderr/exit code.
        """
        services = get_services(ctx)
        tools = services.subprocess_tools
        cwd = resolve_workspace_cwd(cwd, workspace_root=DEFAULT_WORKSPACE)
        result = await run_blocking(
            lambda: tools.run_command(command, cwd=cwd, timeout=timeout)
        )
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def spawn_process(
        command: str,
        cwd: Optional[str] = None,
        ctx: Context = CurrentContext(),
    ) -> str:
        """Spawn a long-running background process and return its PID and log paths.

        Args:
            command: Shell command to spawn.
            cwd: Working directory (defaults to /workspace). Use a container-visible path
                under /workspace; relative paths resolve under /workspace.
        """
        services = get_services(ctx)
        tools = services.subprocess_tools
        cwd = resolve_workspace_cwd(cwd, workspace_root=DEFAULT_WORKSPACE)
        result = await run_blocking(lambda: tools.spawn_process(command, cwd=cwd))
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def get_process(pid: int, ctx: Context = CurrentContext()) -> str:
        """Get information about a tracked background process by PID."""
        services = get_services(ctx)
        result = await run_blocking(lambda: services.subprocess_tools.get_process(pid))
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def kill_process(
        pid: int,
        signal: int = 15,
        ctx: Context = CurrentContext(),
    ) -> str:
        """Send a signal to a tracked background process (default SIGTERM=15)."""
        services = get_services(ctx)
        result = await run_blocking(
            lambda: services.subprocess_tools.kill_process(pid, signal)
        )
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def list_processes(ctx: Context = CurrentContext()) -> str:
        """List all tracked background processes and their metadata (PID, command, log paths)."""
        services = get_services(ctx)
        result = await run_blocking(services.subprocess_tools.list_processes)
        return json.dumps(result, indent=2)
