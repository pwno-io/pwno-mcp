"""
MCP tools for pwndbg integration
Provides execution and control flow tools for debugging
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List
from pathlib import Path

from pwnomcp.mcp_server import mcp
from pwnomcp.gdb_controller import gdb_controller, ResponseToken, InferiorState

logger = logging.getLogger(__name__)


async def ensure_gdb_initialized():
    """Ensure GDB controller is initialized"""
    if not gdb_controller.controller:
        if not gdb_controller.initialize():
            raise RuntimeError("Failed to initialize GDB controller")


@mcp.tool()
async def pwnodbg_execute(command: str) -> str:
    """
    Execute any GDB command and return output
    
    Args:
        command: The GDB command to execute
    """
    await ensure_gdb_initialized()
    
    # Execute and get result
    result = gdb_controller.execute_and_wait(command)
    
    # Following pwndbg-gui: update contexts after user command
    from pwnomcp.context import context_manager
    await context_manager.on_command_executed(command)
    
    return result if result else f"Command executed: {command} (no output)"


# @mcp.tool()
# async def pwnodbg_try_free(address: str) -> str:
#     """
#     Attempt to free a memory chunk at the given address
    
#     Args:
#         address: The address of the chunk to free (hex or decimal)
#     """
#     await ensure_gdb_initialized()
    
#     gdb_controller.execute(f"try_free {address}")
#     return f"Executing try_free on {address}"


@mcp.tool()
async def pwnodbg_launch(
    binary: Optional[str] = None,
    pid: Optional[int] = None,
    args: Optional[List[str]] = None,
    env: Optional[Dict[str, str]] = None
) -> str:
    """
    Launch a binary or attach to a process
    
    Args:
        binary: Path to the binary to debug
        pid: PID to attach to (alternative to binary)
        args: Arguments to pass to the binary
        env: Environment variables to set
    """
    await ensure_gdb_initialized()
    
    output = []
    
    # Handle attachment to PID
    if pid is not None:
        gdb_controller.execute(f"attach {pid}")
        output.append(f"Attaching to process {pid}")
        
    # Handle binary loading
    elif binary is not None:
        # Verify binary exists
        if not Path(binary).exists():
            return f"Binary not found: {binary}"
        
        # Load the binary
        gdb_controller.execute(f"file {binary}")
        output.append(f"Loading binary: {binary}")
        
        # Set environment variables if provided
        if env:
            for key, value in env.items():
                gdb_controller.execute(f"set environment {key}={value}")
            output.append(f"Set {len(env)} environment variables")
        
        # Set arguments if provided
        if args:
            args_str = " ".join(args)
            gdb_controller.execute(f"set args {args_str}")
            output.append(f"Set arguments: {args_str}")
            
        gdb_controller.inferior_state = InferiorState.LOADED
        
    else:
        return "Must provide either 'binary' or 'pid' parameter"
        
    return "\n".join(output)


@mcp.tool()
async def pwnodbg_run(until: Optional[str] = None) -> str:
    """
    Run the loaded binary from the beginning
    
    Args:
        until: Run until this address/symbol (optional)
    """
    await ensure_gdb_initialized()
    
    if gdb_controller.inferior_state == InferiorState.NONE:
        return "No binary loaded. Use pwnodbg_launch first."
        
    command = "run"
    if until:
        command = f"run {until}"
        
    # Send run command
    gdb_controller.execute(command, ResponseToken.USER)
    
    # Update contexts after run (if it stops at a breakpoint)
    from pwnomcp.context import context_manager
    await context_manager.on_command_executed(command)
    
    return f"Executing: {command}"


@mcp.tool()
async def pwnodbg_continue() -> str:
    """Continue execution from current position"""
    await ensure_gdb_initialized()
    
    if not gdb_controller.is_stopped():
        return "Process is not stopped. Cannot continue."
        
    gdb_controller.execute("continue", ResponseToken.USER)
    
    # Update contexts after continue (if it stops at a breakpoint)
    from pwnomcp.context import context_manager
    await context_manager.on_command_executed("continue")
    
    return "Continuing execution..."


@mcp.tool()
async def pwnodbg_step(type: str = "step", count: int = 1) -> str:
    """
    Single-step debugging commands
    
    Args:
        type: Type of step operation (step, next, stepi, nexti)
        count: Number of steps to execute
    """
    await ensure_gdb_initialized()
    
    if not gdb_controller.is_stopped():
        return "Process is not stopped. Cannot step."
        
    if type not in ["step", "next", "stepi", "nexti"]:
        return "Invalid step type. Use: step, next, stepi, or nexti"
        
    # Execute step command
    command = f"{type} {count}" if count > 1 else type
    gdb_controller.execute(command, ResponseToken.USER)
    
    # Update contexts after step command
    from pwnomcp.context import context_manager
    await context_manager.on_command_executed(command)
    
    return f"Executing: {command} (context will be updated)"


@mcp.tool()
async def pwnodbg_context(sections: Optional[List[str]] = None, refresh: bool = False) -> str:
    """
    Display debugging context information from cache
    
    Args:
        sections: Context sections to display (regs, stack, code, disasm, backtrace, heap, all)
                 Default is ["all"]
        refresh: Force refresh context before returning (default: False)
    """
    await ensure_gdb_initialized()
    
    if sections is None:
        sections = ["all"]
        
    valid_sections = ["regs", "stack", "code", "disasm", "backtrace", "heap", "all"]
    
    # Validate sections
    for section in sections:
        if section not in valid_sections:
            return f"Invalid section: {section}. Valid sections: {', '.join(valid_sections)}"
    
    # Import context manager
    from pwnomcp.context import context_manager
    
    # Force refresh if requested
    if refresh:
        await context_manager.update_contexts(force=True)
        # Wait a bit for context to be populated
        await asyncio.sleep(0.5)
    
    # Get cached context
    cached = context_manager.get_cached_context()
    
    # Check if we have any cached data
    if not cached.get("timestamp"):
        # No cache, trigger update
        await context_manager.update_contexts()
        await asyncio.sleep(0.5)
        cached = context_manager.get_cached_context()
        
        if not cached.get("timestamp"):
            return "No context available. Is the process stopped?"
    
    output = []
    
    if "all" in sections:
        # Return all cached sections
        section_map = {
            "registers": "REGISTERS",
            "stack": "STACK",
            "code": "CODE",
            "disasm": "DISASSEMBLY",
            "backtrace": "BACKTRACE",
            "heap": "HEAP"
        }
        
        for key, title in section_map.items():
            if cached.get(key):
                output.append(f"=== {title} ===\n{cached[key]}")
    else:
        # Return specific sections
        section_key_map = {
            "regs": "registers",
            "stack": "stack",
            "code": "code",
            "disasm": "disasm",
            "backtrace": "backtrace",
            "heap": "heap"
        }
        
        for section in sections:
            key = section_key_map.get(section, section)
            if cached.get(key):
                output.append(f"=== {section.upper()} ===\n{cached[key]}")
            else:
                output.append(f"=== {section.upper()} ===\n(No data available)")
                
    if not output:
        return "No context data available"
        
    return "\n\n".join(output)