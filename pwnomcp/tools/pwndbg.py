"""
Pwndbg tools for MCP server

Provides MCP tool implementations for GDB/pwndbg commands.
Each tool returns immediate results suitable for LLM interaction.
"""

import logging
from typing import Dict, Any, Optional
from pwnomcp.gdb import GdbController
from pwnomcp.state import SessionState

logger = logging.getLogger(__name__)


class PwndbgTools:
    """MCP tools for pwndbg interaction"""
    
    def __init__(self, gdb_controller: GdbController, session_state: SessionState):
        """
        Initialize pwndbg tools
        
        Args:
            gdb_controller: GDB controller instance
            session_state: Session state manager
        """
        self.gdb = gdb_controller
        self.session = session_state
        
    def execute(self, command: str) -> Dict[str, Any]:
        """
        Execute arbitrary GDB/pwndbg command
        
        This is the general-purpose tool for running any GDB command.
        
        Args:
            command: GDB command to execute
            
        Returns:
            Dictionary containing:
                - command: The executed command
                - output: Console output from command
                - error: Any error messages
                - state: Current inferior state after command
        """
        logger.info(f"Execute tool: {command}")
        
        # Execute the command
        result = self.gdb.execute_command(command)
        
        # Update session state
        self.session.update_state(result["state"])
        self.session.record_command(command, result)
        
        return result
        
    def set_file(self, binary_path: str) -> Dict[str, Any]:
        """
        Set the file to debug
        
        Args:
            binary_path: Path to binary to debug
            
        Returns:
            Dictionary with file loading status
        """
        logger.info(f"Set file: {binary_path}")
        
        # Load the binary using GDB controller
        result = self.gdb.set_file(binary_path)
        
        # Update session state if successful
        if not result.get("error"):
            self.session.binary_path = binary_path
            self.session.binary_loaded = True
            
        return {
            "success": not result.get("error"),
            "output": result["output"],
            "error": result.get("error"),
            "state": result["state"]
        }
        
    def run(self, args: str = "", interrupt_after: Optional[float] = None, start: bool = False) -> Dict[str, Any]:
        """
        Run the loaded binary
        
        Args:
            args: Arguments to pass to the binary
            interrupt_after: Send interrupt signal after specified seconds
            start: If True, stop at program entry (GDB --start)
            
        Returns:
            Dictionary with execution results
        """
        logger.info(f"Run with args: '{args}', interrupt_after: {interrupt_after}")
        
        # Check if binary is loaded
        if not self.session.binary_loaded:
            return {
                "success": False,
                "error": "No binary loaded. Use set_file first."
            }
            
        # Run the program
        result = self.gdb.run(args, start=start)
        
        # If interrupt_after is specified and program is running, schedule interrupt
        if interrupt_after and result.get("state") == "running":
            import threading
            
            def interrupt_program():
                logger.info(f"Interrupting program after {interrupt_after} seconds")
                # Send interrupt signal
                interrupt_result = self.gdb.interrupt()
                logger.info(f"Interrupt result: {interrupt_result}")
                
            # Schedule interrupt
            timer = threading.Timer(interrupt_after, interrupt_program)
            timer.daemon = True
            timer.start()
            
            # Note in the output
            if result.get("output"):
                result["output"] += f"\n[Note: Interrupt scheduled after {interrupt_after} seconds]"
            else:
                result["output"] = f"[Note: Interrupt scheduled after {interrupt_after} seconds]"
        
        # Update session state
        self.session.update_state(result["state"])
        self.session.record_command(result.get("command", f"run {args}"), result)
        
        # Get context if stopped
        context = None
        if result["state"] == "stopped":
            context = self._get_full_context()
            
        return {
            "success": not result.get("error"),
            "output": result["output"],
            "error": result.get("error"),
            "state": result["state"],
            "context": context
        }

    def finish(self) -> Dict[str, Any]:
        """Run until current function finishes (-exec-finish)"""
        logger.info("Finish current function")
        result = self.gdb.finish()
        self.session.update_state(result["state"])
        self.session.record_command(result.get("command", "finish"), result)

        context = None
        if result["state"] == "stopped":
            context = self._get_full_context()

        return {
            "success": not result.get("error"),
            "command": "finish",
            "output": result.get("output"),
            "error": result.get("error"),
            "state": result["state"],
            "context": context
        }

    def interrupt_execution(self, all_threads: bool = False, thread_group: Optional[str] = None) -> Dict[str, Any]:
        """Interrupt the target using MI (-exec-interrupt)"""
        logger.info("Interrupt execution via MI")
        result = self.gdb.interrupt_execution(all_threads=all_threads, thread_group=thread_group)
        self.session.update_state(result["state"])
        self.session.record_command(result.get("command", "interrupt"), result)

        context = None
        if result["state"] == "stopped":
            context = self._get_full_context()

        return {
            "success": not result.get("error"),
            "command": "interrupt",
            "output": result.get("output"),
            "error": result.get("error"),
            "state": result["state"],
            "context": context
        }

    def jump(self, locspec: str) -> Dict[str, Any]:
        """Jump to a specific location (-exec-jump)"""
        logger.info(f"Jump to {locspec}")
        result = self.gdb.jump(locspec)
        self.session.update_state(result["state"])
        self.session.record_command(result.get("command", f"jump {locspec}"), result)

        context = None
        if result["state"] == "stopped":
            context = self._get_full_context()

        return {
            "success": not result.get("error"),
            "command": "jump",
            "output": result.get("output"),
            "error": result.get("error"),
            "state": result["state"],
            "context": context
        }

    def return_from_function(self) -> Dict[str, Any]:
        """Force return from current function (-exec-return)"""
        logger.info("Force return from current function")
        result = self.gdb.return_from_function()
        self.session.update_state(result["state"])
        self.session.record_command(result.get("command", "return"), result)

        context = None
        if result["state"] == "stopped":
            context = self._get_full_context()

        return {
            "success": not result.get("error"),
            "command": "return",
            "output": result.get("output"),
            "error": result.get("error"),
            "state": result["state"],
            "context": context
        }

    def until(self, locspec: Optional[str] = None) -> Dict[str, Any]:
        """Run until a location or next source line (-exec-until)"""
        logger.info(f"Until {locspec if locspec else '[next line]'}")
        result = self.gdb.until(locspec)
        self.session.update_state(result["state"])
        self.session.record_command(result.get("command", "until"), result)

        context = None
        if result["state"] == "stopped":
            context = self._get_full_context()

        return {
            "success": not result.get("error"),
            "command": "until",
            "output": result.get("output"),
            "error": result.get("error"),
            "state": result["state"],
            "context": context
        }
        
    def step_control(self, command: str) -> Dict[str, Any]:
        """
        Execute stepping commands (c, n, s, ni, si)
        
        This provides proper support for program flow control.
        
        Args:
            command: Stepping command (continue, next, step, nexti, stepi)
            
        Returns:
            Dictionary with execution results and new state
        """
        logger.info(f"Step control: {command}")
        
        # Map command aliases
        command_map = {
            "c": "continue",
            "n": "next", 
            "s": "step",
            "ni": "nexti",
            "si": "stepi"
        }
        
        actual_command = command_map.get(command, command)
        
        # Check if we can execute the command
        current_state = self.gdb.get_state()
        
        if actual_command == "continue" and current_state == "stopped":
            result = self.gdb.continue_execution()
        elif actual_command in ["next", "step", "nexti", "stepi"] and current_state == "stopped":
            # Use the appropriate method
            method = getattr(self.gdb, actual_command.replace("i", "i" if "i" in actual_command else ""))
            result = method()
        else:
            return {
                "success": False,
                "error": f"Cannot execute '{command}' in state '{current_state}'",
                "state": current_state
            }
            
        # Update session state
        self.session.update_state(result["state"])
        self.session.record_command(result.get("command", actual_command), result)
        
        # Get context if stopped
        context = None
        if result["state"] == "stopped":
            context = self._get_full_context()
            
        return {
            "success": not result.get("error"),
            "command": actual_command,
            "output": result["output"],
            "error": result.get("error"),
            "state": result["state"],
            "context": context
        }
        
    def get_context(self, context_type: str = "all") -> Dict[str, Any]:
        """
        Get debugging context (registers, stack, disassembly, etc.)
        
        Args:
            context_type: Type of context or "all" for complete context
            
        Returns:
            Dictionary with requested context information
        """
        logger.info(f"Get context: {context_type}")
        
        if self.gdb.get_state() != "stopped":
            return {
                "success": False,
                "error": f"Cannot get context while inferior is {self.gdb.get_state()}"
            }
            
        if context_type == "all":
            return {
                "success": True,
                "context": self._get_full_context()
            }
        else:
            result = self.gdb.get_context(context_type)
            return {
                "success": not result.get("error"),
                "context_type": context_type,
                "data": result.get("data"),
                "error": result.get("error")
            }
            
    def set_breakpoint(self, location: str, condition: Optional[str] = None) -> Dict[str, Any]:
        """
        Set a breakpoint
        
        Args:
            location: Address or symbol for breakpoint
            condition: Optional breakpoint condition
            
        Returns:
            Dictionary with breakpoint information
        """
        logger.info(f"Set breakpoint at {location}")
        
        # Use GDB controller's MI-based breakpoint method
        result = self.gdb.set_breakpoint(location, condition)
        
        # Extract breakpoint info from structured payload
        if not result.get("error") and result.get("payload"):
            bkpt_info = result["payload"].get("bkpt", {})
            bp_num = bkpt_info.get("number")
            if bp_num:
                # Store as int
                bp_num = int(bp_num)
                # Use actual address from response if available
                addr = bkpt_info.get("addr", location)
                self.session.add_breakpoint(bp_num, addr, condition)
                
        return {
            "success": not result.get("error"),
            "output": result["output"],
            "error": result.get("error"),
            "breakpoint_info": result.get("payload", {}).get("bkpt") if result.get("payload") else None
        }
        
    def list_breakpoints(self) -> Dict[str, Any]:
        """
        List all breakpoints
        
        Returns:
            Dictionary with breakpoint list
        """
        logger.info("List breakpoints")
        
        result = self.gdb.list_breakpoints()
        
        # Format breakpoint information
        breakpoints = []
        if result.get("breakpoints"):
            for bp in result["breakpoints"]:
                bp_info = {
                    "number": int(bp.get("number", 0)),
                    "type": bp.get("type", "breakpoint"),
                    "enabled": bp.get("enabled", "y") == "y",
                    "address": bp.get("addr", ""),
                    "function": bp.get("func", ""),
                    "file": bp.get("file", ""),
                    "line": bp.get("line", ""),
                    "condition": bp.get("cond", ""),
                    "hit_count": int(bp.get("times", 0))
                }
                breakpoints.append(bp_info)
                
        return {
            "success": not result.get("error"),
            "breakpoints": breakpoints,
            "error": result.get("error")
        }
        
    def delete_breakpoint(self, number: int) -> Dict[str, Any]:
        """
        Delete a breakpoint
        
        Args:
            number: Breakpoint number to delete
            
        Returns:
            Dictionary with deletion status
        """
        logger.info(f"Delete breakpoint #{number}")
        
        result = self.gdb.delete_breakpoint(number)
        
        # Update session state
        if not result.get("error"):
            self.session.remove_breakpoint(number)
            
        return {
            "success": not result.get("error"),
            "output": result["output"],
            "error": result.get("error")
        }
        
    def toggle_breakpoint(self, number: int, enable: bool) -> Dict[str, Any]:
        """
        Enable or disable a breakpoint
        
        Args:
            number: Breakpoint number
            enable: True to enable, False to disable
            
        Returns:
            Dictionary with toggle status
        """
        action = "enable" if enable else "disable"
        logger.info(f"{action} breakpoint #{number}")
        
        if enable:
            result = self.gdb.enable_breakpoint(number)
        else:
            result = self.gdb.disable_breakpoint(number)
            
        # Update session state
        if not result.get("error"):
            self.session.toggle_breakpoint(number)
            
        return {
            "success": not result.get("error"),
            "output": result["output"],
            "error": result.get("error")
        }
        
    def _get_full_context(self) -> Dict[str, Any]:
        """Get complete debugging context"""
        contexts = {}
        for ctx_type in ["regs", "stack", "disasm", "code", "backtrace"]:
            ctx_result = self.gdb.get_context(ctx_type)
            if not ctx_result.get("error"):
                contexts[ctx_type] = ctx_result["data"]
                
        return contexts
        
    def get_memory(self, address: str, size: int = 64, format: str = "hex") -> Dict[str, Any]:
        """
        Read memory at specified address
        
        Args:
            address: Memory address to read
            size: Number of bytes to read
            format: Output format (hex, string, int)
            
        Returns:
            Dictionary with memory contents
        """
        logger.info(f"Read memory at {address}, {size} bytes as {format}")
        
        # Use appropriate pwndbg command based on format
        if format == "hex":
            cmd = f"hexdump {address} {size}"
        elif format == "string":
            cmd = f"x/s {address}"
        else:
            cmd = f"x/{size}b {address}"
            
        result = self.gdb.execute_command(cmd)
        
        return {
            "success": not result.get("error"),
            "address": address,
            "size": size,
            "format": format,
            "data": result["output"],
            "error": result.get("error")
        }
        
    def get_session_info(self) -> Dict[str, Any]:
        """Get current session information"""
        # Sync breakpoints with GDB
        bp_result = self.gdb.list_breakpoints()
        if bp_result.get("breakpoints"):
            # Clear and rebuild breakpoint list from GDB
            self.session.breakpoints.clear()
            for bp in bp_result["breakpoints"]:
                self.session.add_breakpoint(
                    int(bp.get("number", 0)),
                    bp.get("addr", ""),
                    bp.get("cond", "")
                )
                
        return {
            "session": self.session.to_dict(),
            "gdb_state": self.gdb.get_state()
        } 