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
        """Execute arbitrary GDB/pwndbg command and return raw responses"""
        logger.info(f"Execute tool: {command}")
        result = self.gdb.execute_command(command)
        self.session.update_state(result["state"])
        self.session.record_command(command, result)
        return result
        
    def set_file(self, binary_path: str) -> Dict[str, Any]:
        """Set the file to debug; return raw responses"""
        logger.info(f"Set file: {binary_path}")
        result = self.gdb.set_file(binary_path)
        if result.get("success"):
            self.session.binary_path = binary_path
            self.session.binary_loaded = True
        self.session.update_state(result["state"])
        self.session.record_command(result.get("command", f"-file-exec-and-symbols {binary_path}"), result)
        return result

    def attach(self, pid: int) -> Dict[str, Any]:
        """Attach to an existing process; return raw responses"""
        logger.info(f"Attach to pid: {pid}")
        result = self.gdb.attach(pid)
        if result.get("success"):
            self.session.pid = pid
        self.session.update_state(result["state"])
        self.session.record_command(result.get("command", f"-target-attach {pid}"), result)
        return result
        
    def run(self, args: str = "", start: bool = False) -> Dict[str, Any]:
        """Run the loaded binary; return raw responses"""
        logger.info(f"Run with args: '{args}'")
        if not self.session.binary_loaded:
            return {"command": "-exec-run", "responses": [], "success": False, "state": self.gdb.get_state(), "error": "No binary loaded. Use set_file first."}
        result = self.gdb.run(args, start=start)
        self.session.update_state(result["state"])
        self.session.record_command(result.get("command", "-exec-run"), result)
        return result

    def finish(self) -> Dict[str, Any]:
        """Run until current function finishes; return raw responses"""
        logger.info("Finish current function")
        result = self.gdb.finish()
        self.session.update_state(result["state"])
        self.session.record_command(result.get("command", "-exec-finish"), result)
        return result

    

    def jump(self, locspec: str) -> Dict[str, Any]:
        """Jump to a specific location; return raw responses"""
        logger.info(f"Jump to {locspec}")
        result = self.gdb.jump(locspec)
        self.session.update_state(result["state"])
        self.session.record_command(result.get("command", f"-exec-jump {locspec}"), result)
        return result

    def return_from_function(self) -> Dict[str, Any]:
        """Force return from current function; return raw responses"""
        logger.info("Force return from current function")
        result = self.gdb.return_from_function()
        self.session.update_state(result["state"])
        self.session.record_command(result.get("command", "-exec-return"), result)
        return result

    def until(self, locspec: Optional[str] = None) -> Dict[str, Any]:
        """Run until a location or next source line; return raw responses"""
        logger.info(f"Until {locspec if locspec else '[next line]'}")
        result = self.gdb.until(locspec)
        self.session.update_state(result["state"])
        self.session.record_command(result.get("command", "-exec-until"), result)
        return result
        
    def step_control(self, command: str) -> Dict[str, Any]:
        """Execute stepping commands (c, n, s, ni, si); return raw responses"""
        logger.info(f"Step control: {command}")
        command_map = {
            "c": "continue",
            "n": "next",
            "s": "step",
            "ni": "nexti",
            "si": "stepi",
        }
        actual = command_map.get(command, command)
        current_state = self.gdb.get_state()
        if current_state != "stopped":
            return {"command": actual, "responses": [], "success": False, "state": current_state, "error": f"Cannot execute '{command}' in state '{current_state}'"}
        if actual == "continue":
            result = self.gdb.continue_execution()
        elif actual == "next":
            result = self.gdb.next()
        elif actual == "step":
            result = self.gdb.step()
        elif actual == "nexti":
            result = self.gdb.nexti()
        elif actual == "stepi":
            result = self.gdb.stepi()
        else:
            return {"command": actual, "responses": [], "success": False, "state": current_state, "error": f"Unknown step command '{command}'"}
        self.session.update_state(result["state"])
        self.session.record_command(result.get("command", actual), result)
        return result
        
    def get_context(self, context_type: str = "all") -> Dict[str, Any]:
        """Get debugging context (registers, stack, disassembly, etc.)"""
        logger.info(f"Get context: {context_type}")
        if self.gdb.get_state() != "stopped":
            return {"command": f"context {context_type}", "responses": [], "success": False, "state": self.gdb.get_state(), "error": f"Cannot get context while inferior is {self.gdb.get_state()}"}
        if context_type == "all":
            # Aggregate raw responses of each context call
            aggregated = {"success": True, "state": self.gdb.get_state(), "contexts": {}}
            for ctx_type in ["regs", "stack", "disasm", "code", "backtrace"]:
                aggregated["contexts"][ctx_type] = self.gdb.get_context(ctx_type)
            self.session.record_command("context all", aggregated)
            return aggregated
        else:
            result = self.gdb.get_context(context_type)
            self.session.record_command(f"context {context_type}", result)
            return result
            
    def set_breakpoint(self, location: str, condition: Optional[str] = None) -> Dict[str, Any]:
        """Set a breakpoint; return raw responses"""
        logger.info(f"Set breakpoint at {location}")
        result = self.gdb.set_breakpoint(location, condition)
        self.session.record_command(result.get("command", "-break-insert"), result)
        return result
        
    def list_breakpoints(self) -> Dict[str, Any]:
        """List all breakpoints; return raw responses"""
        logger.info("List breakpoints")
        result = self.gdb.list_breakpoints()
        self.session.record_command(result.get("command", "-break-list"), result)
        return result
        
    def delete_breakpoint(self, number: int) -> Dict[str, Any]:
        """Delete a breakpoint; return raw responses"""
        logger.info(f"Delete breakpoint #{number}")
        result = self.gdb.delete_breakpoint(number)
        self.session.record_command(result.get("command", f"-break-delete {number}"), result)
        return result
        
    def toggle_breakpoint(self, number: int, enable: bool) -> Dict[str, Any]:
        """Enable or disable a breakpoint; return raw responses"""
        action = "enable" if enable else "disable"
        logger.info(f"{action} breakpoint #{number}")
        result = self.gdb.enable_breakpoint(number) if enable else self.gdb.disable_breakpoint(number)
        self.session.record_command(result.get("command", f"-break-{action} {number}"), result)
        return result
        
    def _get_full_context(self) -> Dict[str, Any]:
        """Get complete debugging context (raw responses per context)"""
        contexts = {}
        for ctx_type in ["regs", "stack", "disasm", "code", "backtrace"]:
            contexts[ctx_type] = self.gdb.get_context(ctx_type)
        return contexts
        
    def get_memory(self, address: str, size: int = 64, format: str = "hex") -> Dict[str, Any]:
        """Read memory at specified address; return raw responses"""
        logger.info(f"Read memory at {address}, {size} bytes as {format}")
        if format == "hex":
            cmd = f"hexdump {address} {size}"
        elif format == "string":
            cmd = f"x/s {address}"
        else:
            cmd = f"x/{size}b {address}"
        result = self.gdb.execute_command(cmd)
        self.session.record_command(cmd, result)
        return result
        
    def get_session_info(self) -> Dict[str, Any]:
        """Get current session information (no GDB sync/parsing)"""
        return {
            "session": self.session.to_dict(),
            "gdb_state": self.gdb.get_state()
        }