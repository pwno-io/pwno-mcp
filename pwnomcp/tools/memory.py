"""
Memory analysis tools for PwnoMCP
"""

from typing import Optional, List
from pwnomcp.mcp_server import mcp
from pwnomcp.gdb_controller import gdb_controller
from pwnomcp.tools.pwndbg import ensure_gdb_initialized


@mcp.tool()
async def pwnodbg_heap(command: str = "chunks", address: Optional[str] = None) -> str:
    """
    Analyze heap state and chunks
    
    Args:
        command: Heap command to execute (chunks, bins, arenas, tcache, top, info)
        address: Address for heap operations (optional)
    """
    await ensure_gdb_initialized()
    
    valid_commands = ["chunks", "bins", "arenas", "tcache", "top", "info"]
    if command not in valid_commands:
        return f"Invalid heap command. Valid commands: {', '.join(valid_commands)}"
    
    # Build heap command
    if command == "chunks":
        cmd = "heap chunks" + (f" {address}" if address else "")
    elif command == "bins":
        cmd = "heap bins"
    elif command == "arenas":
        cmd = "heap arenas"
    elif command == "tcache":
        cmd = "heap tcache"
    elif command == "top":
        cmd = "heap top"
    else:
        cmd = "heap"
        
    # Memory analysis commands don't change state, return output directly
    result = gdb_controller.execute_and_wait(cmd)
    return result if result else f"No output from: {cmd}"


@mcp.tool()
async def pwnodbg_vmmap(address: Optional[str] = None, name: Optional[str] = None) -> str:
    """
    Show process memory mappings
    
    Args:
        address: Filter mappings containing this address
        name: Filter mappings by name pattern
    """
    await ensure_gdb_initialized()
    
    cmd = "vmmap"
    
    if address:
        cmd += f" {address}"
    elif name:
        cmd += f" {name}"
        
    # Memory analysis commands don't change state, return output directly
    result = gdb_controller.execute_and_wait(cmd)
    return result if result else f"No output from: {cmd}"


@mcp.tool()
async def pwnodbg_search(
    pattern: str,
    type: str = "string",
    writable: bool = False
) -> str:
    """
    Search process memory for patterns
    
    Args:
        pattern: Pattern to search (string or hex bytes)
        type: Type of search (string, bytes, pointer, dword, qword)
        writable: Only search writable memory
    """
    await ensure_gdb_initialized()
    
    valid_types = ["string", "bytes", "pointer", "dword", "qword"]
    if type not in valid_types:
        return f"Invalid search type. Valid types: {', '.join(valid_types)}"
    
    # Build search command based on type
    if type == "string":
        cmd = f"search -s '{pattern}'"
    elif type == "bytes":
        cmd = f"search -x '{pattern}'"
    elif type == "pointer":
        cmd = f"search -p {pattern}"
    elif type == "dword":
        cmd = f"search -d {pattern}"
    elif type == "qword":
        cmd = f"search -q {pattern}"
        
    if writable:
        cmd += " -w"
        
    # Memory analysis commands don't change state, return output directly
    result = gdb_controller.execute_and_wait(cmd)
    return result if result else f"No output from: {cmd}"


@mcp.tool()
async def pwnodbg_telescope(address: Optional[str] = None, count: int = 10) -> str:
    """
    Recursively dereference memory pointers
    
    Args:
        address: Starting address (default: stack pointer)
        count: Number of lines to display
    """
    await ensure_gdb_initialized()
    
    cmd = "telescope"
    
    if address:
        cmd += f" {address}"
        
    cmd += f" {count}"
        
    # Memory analysis commands don't change state, return output directly
    result = gdb_controller.execute_and_wait(cmd)
    return result if result else f"No output from: {cmd}"


@mcp.tool()
async def pwnodbg_rop(
    command: str = "gadgets",
    filter: Optional[str] = None,
    address: Optional[str] = None
) -> str:
    """
    Find and analyze ROP gadgets
    
    Args:
        command: ROP command type (gadgets, chain, dump)
        filter: Filter gadgets by instruction pattern
        address: Address for ROP operations
    """
    await ensure_gdb_initialized()
    
    valid_commands = ["gadgets", "chain", "dump"]
    if command not in valid_commands:
        return f"Invalid ROP command. Valid commands: {', '.join(valid_commands)}"
    
    if command == "gadgets":
        cmd = "rop"
        if filter:
            cmd += f" --grep '{filter}'"
    elif command == "chain":
        cmd = "ropchain"
    elif command == "dump":
        cmd = f"rop --dump {address or '$rsp'}"
        
    # Memory analysis commands don't change state, return output directly
    result = gdb_controller.execute_and_wait(cmd)
    return result if result else f"No output from: {cmd}"