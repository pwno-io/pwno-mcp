"""
Breakpoint and watchpoint management tools for PwnoMCP
"""

import re
from typing import Optional, List
from pwnomcp.mcp_server import mcp
from pwnomcp.gdb_controller import gdb_controller
from pwnomcp.tools.pwndbg import ensure_gdb_initialized


@mcp.tool()
async def pwnodbg_breakpoint(
    action: str = "set",
    location: Optional[str] = None,
    number: Optional[int] = None,
    condition: Optional[str] = None,
    commands: Optional[List[str]] = None
) -> str:
    """
    Set and manage breakpoints
    
    Args:
        action: Breakpoint action (set, list, delete, disable, enable)
        location: Address or symbol for breakpoint
        number: Breakpoint number (for delete/disable/enable)
        condition: Conditional expression for breakpoint
        commands: Commands to execute when breakpoint hits
    """
    await ensure_gdb_initialized()
    
    valid_actions = ["set", "list", "delete", "disable", "enable"]
    if action not in valid_actions:
        return f"Invalid action. Valid actions: {', '.join(valid_actions)}"
    
    if action == "set":
        if not location:
            return "Location required for setting breakpoint"
            
        cmd = f"break {location}"
        
        # Add condition if specified
        if condition:
            cmd += f" if {condition}"
            
        # Execute and get result
        result = gdb_controller.execute_and_wait(cmd)
        
        # Set commands if specified and breakpoint was created
        if commands and result:
            import re
            match = re.search(r"Breakpoint (\d+)", result)
            if match:
                bp_num = match.group(1)
                commands_str = "\n".join(commands)
                gdb_controller.execute_and_wait(f"commands {bp_num}\n{commands_str}\nend")
                
        # Update contexts after state change
        from pwnomcp.context import context_manager
        await context_manager.on_command_executed(cmd)
        
        return result if result else f"Breakpoint set at {location}"
                
    elif action == "list":
        # List is a query, return output directly
        result = gdb_controller.execute_and_wait("info breakpoints")
        return result if result else "No breakpoints set"
        
    elif action == "delete":
        if number is not None:
            cmd = f"delete {number}"
        else:
            cmd = "delete"  # Delete all
        
        result = gdb_controller.execute_and_wait(cmd)
        
        # Update contexts after state change
        from pwnomcp.context import context_manager
        await context_manager.on_command_executed(cmd)
        
        return result if result else f"Breakpoint(s) deleted"
        
    elif action in ["disable", "enable"]:
        if number is None:
            return f"Breakpoint number required for {action}"
        cmd = f"{action} {number}"
        
        result = gdb_controller.execute_and_wait(cmd)
        
        # Update contexts after state change
        from pwnomcp.context import context_manager
        await context_manager.on_command_executed(cmd)
        
        return result if result else f"Breakpoint {number} {action}d"


@mcp.tool()
async def pwnodbg_watchpoint(
    address: str,
    type: str = "write",
    size: int = 8
) -> str:
    """
    Set memory watchpoints
    
    Args:
        address: Memory address to watch
        type: Type of watchpoint (write, read, access)
        size: Size in bytes to watch
    """
    await ensure_gdb_initialized()
    
    valid_types = ["write", "read", "access"]
    if type not in valid_types:
        return f"Invalid watchpoint type. Valid types: {', '.join(valid_types)}"
    
    # Build watchpoint command
    if type == "write":
        cmd = f"watch *(void*){address}"
    elif type == "read":
        cmd = f"rwatch *(void*){address}"
    elif type == "access":
        cmd = f"awatch *(void*){address}"
        
    # Adjust for size if not default
    if size != 8:
        type_map = {1: "char", 2: "short", 4: "int", 8: "long"}
        if size in type_map:
            cmd = cmd.replace("void*", type_map[size] + "*")
        else:
            return f"Unsupported size: {size}. Use 1, 2, 4, or 8 bytes."
            
    # State-changing command, execute and update contexts
    result = gdb_controller.execute_and_wait(cmd)
    
    # Update contexts after state change
    from pwnomcp.context import context_manager
    await context_manager.on_command_executed(cmd)
    
    return result if result else f"Command executed: {cmd}"


@mcp.tool()
async def pwnodbg_catch(event: str, name: Optional[str] = None) -> str:
    """
    Set catchpoints for system calls and signals
    
    Args:
        event: Event type to catch (syscall, signal, exec, fork, vfork)
        name: Specific syscall or signal name
    """
    await ensure_gdb_initialized()
    
    valid_events = ["syscall", "signal", "exec", "fork", "vfork"]
    if event not in valid_events:
        return f"Invalid event type. Valid events: {', '.join(valid_events)}"
    
    if event == "syscall":
        if name:
            cmd = f"catch syscall {name}"
        else:
            cmd = "catch syscall"
    elif event == "signal":
        if name:
            cmd = f"catch signal {name}"
        else:
            cmd = "catch signal"
    else:
        cmd = f"catch {event}"
        
    # State-changing command, execute and update contexts
    result = gdb_controller.execute_and_wait(cmd)
    
    # Update contexts after state change
    from pwnomcp.context import context_manager
    await context_manager.on_command_executed(cmd)
    
    return result if result else f"Command executed: {cmd}"