"""
GDB Controller for Pwno MCP Server

This module provides a synchronous interface to GDB/pwndbg via pygdbmi.
Unlike pwndbg-gui, this is designed for discrete tool invocations with
immediate responses suitable for LLM interaction.
"""

import logging
from typing import List, Dict, Optional, Any, Tuple
from pathlib import Path
from pygdbmi import gdbcontroller
import os

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
            
        # Enable MI asynchronous mode so that execution commands are non-blocking
        mi_async_set = self.execute_mi_command("set mi-async on")
        results.append(mi_async_set)
        
        pwndbg_check = self.execute_command("pwndbg")
        results.append(pwndbg_check)
        
        self._initialized = True
        return {
            "status": "initialized",
            "messages": results
        }
        
    def execute_mi_command(self, command: str, timeout_sec: float = 10.0) -> Dict[str, Any]:
        """
        Execute a GDB/MI command and return raw MI responses.

        Args:
            command: GDB/MI command to execute (should start with -)
            timeout_sec: Timeout for command execution

        Returns:
            Dictionary with raw MI responses, success flag, and current state.
        """
        logger.debug(f"Executing MI command: {command}")

        responses = self.controller.write(command, timeout_sec=timeout_sec)

        # Update internal state from notify messages
        success = False
        error_found = False
        for response in responses:
            if response.get("type") == "notify":
                self._handle_notify(response)
            elif response.get("type") == "result":
                msg = response.get("message")
                if msg == "error":
                    error_found = True
                if msg in ("done", "running"):
                    success = True

        if error_found:
            success = False

        return {
            "command": command,
            "responses": responses,
            "success": success,
            "state": self._state,
        }
        
    def execute_command(self, command: str, timeout_sec: float = 10.0) -> Dict[str, Any]:
        """
        Execute a classic GDB command (non-MI) and return raw responses.

        Args:
            command: GDB command to execute
            timeout_sec: Timeout for command execution

        Returns:
            Dictionary with raw responses, success flag, and current state.
        """
        logger.debug(f"Executing command: {command}")

        # Send command and manually collect responses
        self.controller.write(command, read_response=False)

        collected: list[dict] = []
        while True:
            responses = self.controller.get_gdb_response(
                timeout_sec=timeout_sec,
                raise_error_on_timeout=False
            )
            if not responses:
                break
            for response in responses:
                collected.append(response)
                if response.get("type") == "notify":
                    self._handle_notify(response)

        # Determine success: no explicit error result messages
        success = True
        for r in collected:
            if r.get("type") == "result" and r.get("message") == "error":
                success = False
                break

        return {
            "command": command,
            "responses": collected,
            "success": success,
            "state": self._state,
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
        """Get a specific pwndbg context; return raw responses"""
        if self._state != "stopped":
            return {
                "command": f"context {context_type}",
                "responses": [],
                "success": False,
                "state": self._state,
                "error": f"Cannot get context while inferior is {self._state}",
            }
        return self.execute_command(f"context {context_type}")
        
    def set_file(self, filepath: str) -> Dict[str, Any]:
        """Load an executable file for debugging using MI command"""
        result = self.execute_mi_command(f"-file-exec-and-symbols {filepath}")
        # Change working directory for relative paths during debugging
        self.execute_mi_command(f"-environment-cd {os.path.dirname(filepath)}")
        if result["success"]:
            self._state = "stopped"
        # Ensure returned state reflects any updates
        result["state"] = self._state
        return result
    
    def attach(self, pid: int) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Attach to an existing process using MI command (-target-attach)"""
        self.execute_command("set pagination off")
        self.execute_command("set confirm off")
        self.execute_command("set detach-on-fork off")
        self.execute_command("set follow-fork-mode parent")
        self.execute_command("set follow-exec-mode same")
        
        result = self.execute_mi_command(f"-target-attach {pid}")
        if result["success"]:
            self._inferior_pid = pid
            self._state = "stopped"
        result["state"] = self._state
        result["pid"] = self._inferior_pid

        context = []
        context.append(self.get_context("backtrace"))
        context.append(self.get_context("heap"))
        
        return result, context
        
    def run(self, args: str = "", start: bool = False) -> Dict[str, Any]:
        """Run the loaded program using MI command"""
        if args:
            set_args_result = self.execute_mi_command(f"-exec-arguments {args}")
            if not set_args_result["success"]:
                return set_args_result

        run_command = "-exec-run --start" if start else "-exec-run"
        result = self.execute_mi_command(run_command)
        return result
        
    def continue_execution(self) -> Dict[str, Any]:
        """Continue execution using MI command"""
        return self.execute_mi_command("-exec-continue")

    def finish(self) -> Dict[str, Any]:
        """Finish current function using MI command (-exec-finish)"""
        return self.execute_mi_command("-exec-finish")
        
    def next(self) -> Dict[str, Any]:
        """Step over using MI command"""
        return self.execute_mi_command("-exec-next")
        
    def step(self) -> Dict[str, Any]:
        """Step into using MI command"""
        return self.execute_mi_command("-exec-step")
        
    def nexti(self) -> Dict[str, Any]:
        """Step one instruction using MI command"""
        return self.execute_mi_command("-exec-next-instruction")
        
    def stepi(self) -> Dict[str, Any]:
        """Step into one instruction using MI command"""
        return self.execute_mi_command("-exec-step-instruction")

    def jump(self, locspec: str) -> Dict[str, Any]:
        """Jump to a specific location using MI command (-exec-jump)"""
        return self.execute_mi_command(f"-exec-jump {locspec}")

    def return_from_function(self) -> Dict[str, Any]:
        """Force return from current function using MI command (-exec-return)"""
        return self.execute_mi_command("-exec-return")

    def until(self, locspec: Optional[str] = None) -> Dict[str, Any]:
        """Run until a specific location or next line using MI command (-exec-until)"""
        mi_cmd = "-exec-until" if not locspec else f"-exec-until {locspec}"
        return self.execute_mi_command(mi_cmd)
        
    def set_breakpoint(self, location: str, condition: Optional[str] = None) -> Dict[str, Any]:
        """Set a breakpoint using MI command"""
        mi_command = f"-break-insert {location}"
        if condition:
            mi_command = f"-break-insert -c \"{condition}\" {location}"
        return self.execute_mi_command(mi_command)
        
    def evaluate_expression(self, expression: str) -> Dict[str, Any]:
        """Evaluate an expression using MI command"""
        return self.execute_mi_command(f"-data-evaluate-expression \"{expression}\"")
        
    def read_memory_mi(self, address: str, word_format: str, word_size: int, nr_rows: int, nr_cols: int) -> Dict[str, Any]:
        """Read memory using MI command"""
        mi_command = f"-data-read-memory {address} {word_format} {word_size} {nr_rows} {nr_cols}"
        return self.execute_mi_command(mi_command)
        
    def list_breakpoints(self) -> Dict[str, Any]:
        """List all breakpoints using MI command"""
        return self.execute_mi_command("-break-list")
        
    def delete_breakpoint(self, number: int) -> Dict[str, Any]:
        """Delete a breakpoint using MI command"""
        return self.execute_mi_command(f"-break-delete {number}")
        
    def enable_breakpoint(self, number: int) -> Dict[str, Any]:
        """Enable a breakpoint using MI command"""
        return self.execute_mi_command(f"-break-enable {number}")
        
    def disable_breakpoint(self, number: int) -> Dict[str, Any]:
        """Disable a breakpoint using MI command"""
        return self.execute_mi_command(f"-break-disable {number}")
        
    
        
    def get_state(self) -> str:
        """Get current inferior state"""
        return self._state
        
    def close(self):
        """Clean up GDB controller"""
        if hasattr(self, 'controller'):
            self.controller.exit() 