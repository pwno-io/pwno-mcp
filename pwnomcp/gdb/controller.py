"""
GDB Controller for Pwno MCP Server

This module provides a synchronous interface to GDB/pwndbg via pygdbmi.
Unlike pwndbg-gui, this is designed for discrete tool invocations with
immediate responses suitable for LLM interaction.
"""

import logging
from typing import List, Dict, Optional, Any
from pathlib import Path
from pygdbmi import gdbcontroller

logger = logging.getLogger(__name__)


class GdbController:
    """Manages GDB instance and command execution via Machine Interface"""
    
    def __init__(self, pwnodbg: str = "pwndbg"):
        """
        Initialize GDB controller
        
        Args:
            gdb_path: Path to GDB executable (default: "gdb")
        """
        self.controller = gdbcontroller.GdbController(
            command=[pwnodbg, "--interpreter=mi3", "--quiet"]
        )
        self._initialized = False
        self._inferior_pid = None
        self._state = "idle"  # idle, running, stopped, exited
        
    def initialize(self) -> Dict[str, Any]:
        """
        Initialize GDB with pwndbg from ~/.gdbinit
        
        Returns:
            Dictionary with initialization status and messages
        """
        if self._initialized:
            return {"status": "already_initialized", "messages": []}
            
        results = []
        
        # Load .gdbinit if it exists
        # gdbinit = Path.home() / ".gdbinit"
        # if gdbinit.exists():
        #     logger.info(f"Loading .gdbinit from {gdbinit}")
        #     response = self.execute_command(f"source {gdbinit}")
        #     results.append(response)
        # else:
        #     logger.warning("No .gdbinit found")
            
        # Verify pwndbg is loaded
        pwndbg_check = self.execute_command("pwndbg")
        results.append(pwndbg_check)
        
        self._initialized = True
        return {
            "status": "initialized",
            "messages": results
        }
        
    def execute_command(self, command: str, timeout_sec: float = 10.0) -> Dict[str, Any]:
        """
        Execute a GDB command and return the complete response
        
        Args:
            command: GDB command to execute
            timeout_sec: Timeout for command execution
            
        Returns:
            Dictionary containing:
                - command: The executed command
                - output: Console output from command
                - error: Any error messages
                - state: Current inferior state after command
        """
        logger.debug(f"Executing command: {command}")
        
        # Write command without reading response
        self.controller.write(command, read_response=False)
        
        # Collect all responses until we get a result
        output_lines = []
        error_lines = []
        logs = []
        
        while True:
            responses = self.controller.get_gdb_response(
                timeout_sec=timeout_sec,
                raise_error_on_timeout=False
            )
            
            if not responses:
                break
                
            for response in responses:
                msg_type = response.get("type", "")
                payload = response.get("payload", "")
                
                if msg_type == "console":
                    # Console output from GDB/pwndbg
                    if payload:
                        output_lines.append(payload)
                        
                elif msg_type == "output":
                    # Output from inferior process
                    if payload:
                        output_lines.append(f"[INFERIOR] {payload}")
                        
                elif msg_type == "log":
                    # Log messages
                    if payload:
                        logs.append(payload)
                        
                elif msg_type == "result":
                    # Command completed
                    message = response.get("message", "")
                    if message == "error":
                        error_payload = response.get("payload", {})
                        error_msg = error_payload.get("msg", "Unknown error")
                        error_lines.append(error_msg)
                    
                    # This indicates command completion
                    return {
                        "command": command,
                        "output": "".join(output_lines),
                        "error": "\n".join(error_lines) if error_lines else None,
                        "logs": logs,
                        "state": self._state
                    }
                    
                elif msg_type == "notify":
                    # State change notifications
                    self._handle_notify(response)
                    
        # If we exit the loop without a result, return what we have
        return {
            "command": command,
            "output": "".join(output_lines),
            "error": "\n".join(error_lines) if error_lines else None,
            "logs": logs,
            "state": self._state
        }
        
    def _handle_notify(self, response: Dict[str, Any]):
        """Handle GDB notification messages to track state"""
        message = response.get("message", "")
        
        if message == "running":
            self._state = "running"
            logger.debug("Inferior state: RUNNING")
            
        elif message == "stopped":
            self._state = "stopped"
            payload = response.get("payload", {})
            # Extract stop reason if available
            reason = payload.get("reason", "unknown")
            logger.debug(f"Inferior state: STOPPED (reason: {reason})")
            
        elif message == "thread-group-exited":
            self._state = "exited"
            logger.debug("Inferior state: EXITED")
            
        elif message == "thread-group-started":
            # This happens when attaching to a process
            payload = response.get("payload", {})
            self._inferior_pid = payload.get("pid")
            logger.debug(f"Thread group started, PID: {self._inferior_pid}")
            
    def get_context(self, context_type: str) -> Dict[str, Any]:
        """
        Get a specific pwndbg context
        
        Args:
            context_type: Type of context (regs, stack, disasm, code, backtrace)
            
        Returns:
            Dictionary with context data
        """
        if self._state != "stopped":
            return {
                "error": f"Cannot get context while inferior is {self._state}",
                "context_type": context_type
            }
            
        response = self.execute_command(f"context {context_type}")
        return {
            "context_type": context_type,
            "data": response["output"],
            "error": response["error"]
        }
        
    def set_file(self, filepath: str) -> Dict[str, Any]:
        """Load an executable file for debugging"""
        response = self.execute_command(f"file {filepath}")
        if not response["error"]:
            self._state = "stopped"  # File loaded, ready to run
        return response
        
    def run(self, args: str = "") -> Dict[str, Any]:
        """Run the loaded program"""
        return self.execute_command(f"run {args}")
        
    def continue_execution(self) -> Dict[str, Any]:
        """Continue execution (c command)"""
        return self.execute_command("continue")
        
    def next(self) -> Dict[str, Any]:
        """Step over (n command)"""
        return self.execute_command("next")
        
    def step(self) -> Dict[str, Any]:
        """Step into (s command)"""
        return self.execute_command("step")
        
    def nexti(self) -> Dict[str, Any]:
        """Step one instruction (ni command)"""
        return self.execute_command("nexti")
        
    def stepi(self) -> Dict[str, Any]:
        """Step into one instruction (si command)"""
        return self.execute_command("stepi")
        
    def get_state(self) -> str:
        """Get current inferior state"""
        return self._state
        
    def close(self):
        """Clean up GDB controller"""
        if hasattr(self, 'controller'):
            self.controller.exit() 