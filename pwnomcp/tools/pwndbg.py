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
        
    def launch(self, binary_path: str, args: str = "", mode: str = "run") -> Dict[str, Any]:
        """
        Launch binary for debugging with proper support for execution control
        
        This tool handles the complexity of launching and controlling binary execution,
        learning from pwndbg-gui's inferior handler design.
        
        Args:
            binary_path: Path to binary to debug
            args: Arguments to pass to the binary
            mode: Launch mode - "run" (start fresh) or "start" (break at entry)
            
        Returns:
            Dictionary with launch results and initial state
        """
        logger.info(f"Launch tool: {binary_path} with args '{args}' in mode '{mode}'")
        
        results = {}
        
        # Load the binary
        load_result = self.gdb.set_file(binary_path)
        results["load"] = load_result
        
        if load_result["error"]:
            return {
                "success": False,
                "error": f"Failed to load binary: {load_result['error']}",
                "results": results
            }
            
        # Update session state
        self.session.binary_path = binary_path
        self.session.binary_loaded = True
        
        # Get entry point
        entry_result = self.gdb.execute_command("info target")
        results["entry_info"] = entry_result
        
        # Launch based on mode
        if mode == "run":
            # Run directly
            launch_result = self.gdb.run(args)
        elif mode == "start":
            # Break at entry and run
            self.gdb.execute_command("break _start")
            launch_result = self.gdb.run(args)
        else:
            return {
                "success": False,
                "error": f"Unknown launch mode: {mode}",
                "results": results
            }
            
        results["launch"] = launch_result
        
        # Get initial context if stopped
        if self.gdb.get_state() == "stopped":
            results["context"] = self._get_full_context()
            
        return {
            "success": not launch_result.get("error"),
            "state": self.gdb.get_state(),
            "results": results
        }
        
    def step_control(self, command: str) -> Dict[str, Any]:
        """
        Execute stepping commands (run, c, n, s, ni, si)
        
        This provides proper support for program flow control.
        
        Args:
            command: Stepping command (run, continue, next, step, nexti, stepi)
            
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
        
        if actual_command == "run":
            # Run can be executed from any state
            result = self.gdb.run()
        elif actual_command == "continue" and current_state == "stopped":
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
        self.session.record_command(actual_command, result)
        
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
        
        # Build break command
        cmd = f"break {location}"
        if condition:
            cmd += f" if {condition}"
            
        result = self.gdb.execute_command(cmd)
        
        # Parse breakpoint number from output if successful
        if not result.get("error") and "Breakpoint" in result["output"]:
            # Extract breakpoint number
            import re
            match = re.search(r"Breakpoint (\d+)", result["output"])
            if match:
                bp_num = int(match.group(1))
                self.session.add_breakpoint(bp_num, location, condition)
                
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
        return {
            "session": self.session.to_dict(),
            "gdb_state": self.gdb.get_state()
        } 