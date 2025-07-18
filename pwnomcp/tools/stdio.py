"""
STDIO tools for checking GDB and inferior output
"""

from typing import Optional
from pwnomcp.mcp_server import mcp
from pwnomcp.gdb_controller import gdb_controller
from pwnomcp.tools.pwndbg import ensure_gdb_initialized


@mcp.tool()
async def pwnodbg_stdio(
    stream: str = "all",
    clear: bool = False,
    tail: Optional[int] = None
) -> str:
    """
    Get buffered output from GDB and inferior process
    
    Args:
        stream: Which stream to get (stdout, stderr, console, all)
        clear: Whether to clear the buffer after reading
        tail: Only return last N lines (optional)
    """
    await ensure_gdb_initialized()
    
    valid_streams = ["stdout", "stderr", "console", "all"]
    if stream not in valid_streams:
        return f"Invalid stream. Valid streams: {', '.join(valid_streams)}"
    
    output = []
    
    if stream == "all" or stream == "stdout":
        stdout = gdb_controller.get_stdout(clear=clear and stream != "all")
        if stdout:
            if tail:
                lines = stdout.splitlines()
                stdout = "\n".join(lines[-tail:])
            output.append(f"=== STDOUT ===\n{stdout}")
            
    if stream == "all" or stream == "stderr":
        stderr = gdb_controller.get_stderr(clear=clear and stream != "all")
        if stderr:
            if tail:
                lines = stderr.splitlines()
                stderr = "\n".join(lines[-tail:])
            output.append(f"=== STDERR ===\n{stderr}")
            
    if stream == "all" or stream == "console":
        console = gdb_controller.get_console(clear=clear and stream != "all")
        if console:
            if tail:
                lines = console.splitlines()
                console = "\n".join(lines[-tail:])
            output.append(f"=== CONSOLE ===\n{console}")
    
    # Clear all if requested and showing all
    if clear and stream == "all":
        gdb_controller.clear_buffers()
    
    if not output:
        return f"No output in {stream} buffer(s)"
        
    return "\n\n".join(output)


@mcp.tool()
async def pwnodbg_clear_stdio() -> str:
    """Clear all stdio buffers"""
    await ensure_gdb_initialized()
    
    gdb_controller.clear_buffers()
    return "All stdio buffers cleared"


@mcp.tool()
async def pwnodbg_wait_for_output(
    pattern: Optional[str] = None,
    timeout: float = 5.0,
    stream: str = "console"
) -> str:
    """
    Wait for specific output or any output to appear
    
    Args:
        pattern: Pattern to wait for (substring match)
        timeout: Maximum time to wait in seconds
        stream: Which stream to monitor (stdout, stderr, console)
    """
    await ensure_gdb_initialized()
    
    import asyncio
    import time
    
    valid_streams = ["stdout", "stderr", "console"]
    if stream not in valid_streams:
        return f"Invalid stream. Valid streams: {', '.join(valid_streams)}"
    
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        # Get current buffer content
        if stream == "stdout":
            content = gdb_controller.get_stdout(clear=False)
        elif stream == "stderr":
            content = gdb_controller.get_stderr(clear=False)
        else:
            content = gdb_controller.get_console(clear=False)
            
        # Check for pattern or any content
        if pattern:
            if pattern in content:
                return f"Found pattern '{pattern}' in {stream}"
        elif content:
            return f"Output detected in {stream}"
            
        # Small delay before next check
        await asyncio.sleep(0.1)
    
    if pattern:
        return f"Timeout waiting for pattern '{pattern}' in {stream}"
    else:
        return f"Timeout waiting for output in {stream}"