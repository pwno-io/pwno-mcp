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
        
        # Verify pwndbg is loaded
        pwndbg_check = self.execute_command("pwndbg")
        results.append(pwndbg_check)
        
        self._initialized = True
        return {
            "status": "initialized",
            "messages": results
        }
        
    def execute_mi_command(self, command: str, timeout_sec: float = 10.0) -> Dict[str, Any]:
        """
        Execute a GDB/MI command and return structured response
        
        Args:
            command: GDB/MI command to execute (should start with -)
            timeout_sec: Timeout for command execution
            
        Returns:
            Dictionary containing parsed MI response
        """
        logger.debug(f"Executing MI command: {command}")
        
        # Write command and get response
        responses = self.controller.write(command, timeout_sec=timeout_sec)
        
        # Process responses
        result = {
            "command": command,
            "success": False,
            "message": None,
            "payload": None,
            "output": [],
            "error": None,
            "state": self._state
        }
        
        for response in responses:
            msg_type = response.get("type", "")
            
            if msg_type == "result":
                result["message"] = response.get("message", "")
                result["payload"] = response.get("payload", {})
                result["success"] = result["message"] in ["done", "running"]
                
                if result["message"] == "error":
                    error_msg = result["payload"].get("msg", "Unknown error")
                    result["error"] = error_msg
                    
            elif msg_type == "console":
                if response.get("payload"):
                    result["output"].append(response["payload"])
                    
            elif msg_type == "notify":
                self._handle_notify(response)
                
        result["state"] = self._state
        return result
        
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
        """Load an executable file for debugging using MI command"""
        # Use MI command for better structured response
        result = self.execute_mi_command(f"-file-exec-and-symbols {filepath}")
        self.execute_mi_command(f"-environment-cd {os.path.dirname(filepath)}")

        if result["success"]:
            self._state = "stopped"  # File loaded, ready to run
            
        # Convert MI response to our format
        return {
            "command": f"-file-exec-and-symbols {filepath}",
            "output": "\n".join(result["output"]) if result["output"] else f"Reading symbols from {filepath}...",
            "error": result["error"],
            "state": self._state
        }

    def attach(self, pid: int) -> Dict[str, Any]:
        """Attach to an existing process using MI command (-target-attach)"""
        result = self.execute_mi_command(f"-target-attach {pid}")

        if result["success"]:
            self._inferior_pid = pid
            self._state = "stopped"

        return {
            "command": f"-target-attach {pid}",
            "output": "\n".join(result["output"]) if result["output"] else "",
            "error": result["error"],
            "state": self._state,
            "pid": self._inferior_pid
        }
        
    def run(self, args: str = "", start: bool = False) -> Dict[str, Any]:
        """Run the loaded program using MI command

        :param args: Program arguments to set prior to run
        :param start: If True, stop at program entry (equivalent to --start)
        :returns: Structured run result
        """
        # If arguments were provided, set them for the next run using MI per GDB/MI spec
        # Reference: -exec-arguments (GDB/MI Program Context)
        if args:
            set_args_result = self.execute_mi_command(f"-exec-arguments {args}")
            if not set_args_result["success"]:
                return {
                    "command": f"-exec-arguments {args}",
                    "output": "\n".join(set_args_result["output"]) if set_args_result["output"] else "",
                    "error": set_args_result["error"] or "Failed to set program arguments",
                    "state": self._state
                }

        # Start execution from the beginning
        run_command = "-exec-run --start" if start else "-exec-run"
        result = self.execute_mi_command(run_command)
        
        # Convert MI response to our format
        return {
            "command": (f"-exec-arguments {args}, {run_command}" if args else run_command),
            "output": "\n".join(result["output"]) if result["output"] else "",
            "error": result["error"],
            "state": self._state
        }
        
    def continue_execution(self) -> Dict[str, Any]:
        """Continue execution using MI command"""
        result = self.execute_mi_command("-exec-continue")
        
        return {
            "command": "-exec-continue",
            "output": "\n".join(result["output"]) if result["output"] else "",
            "error": result["error"],
            "state": self._state
        }

    def finish(self) -> Dict[str, Any]:
        """Finish current function using MI command (-exec-finish)"""
        result = self.execute_mi_command("-exec-finish")

        return {
            "command": "-exec-finish",
            "output": "\n".join(result["output"]) if result["output"] else "",
            "error": result["error"],
            "state": self._state,
            "payload": result.get("payload")
        }
        
    def next(self) -> Dict[str, Any]:
        """Step over using MI command"""
        result = self.execute_mi_command("-exec-next")
        
        return {
            "command": "-exec-next",
            "output": "\n".join(result["output"]) if result["output"] else "",
            "error": result["error"],
            "state": self._state
        }
        
    def step(self) -> Dict[str, Any]:
        """Step into using MI command"""
        result = self.execute_mi_command("-exec-step")
        
        return {
            "command": "-exec-step",
            "output": "\n".join(result["output"]) if result["output"] else "",
            "error": result["error"],
            "state": self._state
        }
        
    def nexti(self) -> Dict[str, Any]:
        """Step one instruction using MI command"""
        result = self.execute_mi_command("-exec-next-instruction")
        
        return {
            "command": "-exec-next-instruction",
            "output": "\n".join(result["output"]) if result["output"] else "",
            "error": result["error"],
            "state": self._state
        }
        
    def stepi(self) -> Dict[str, Any]:
        """Step into one instruction using MI command"""
        result = self.execute_mi_command("-exec-step-instruction")
        
        return {
            "command": "-exec-step-instruction",
            "output": "\n".join(result["output"]) if result["output"] else "",
            "error": result["error"],
            "state": self._state
        }

    def jump(self, locspec: str) -> Dict[str, Any]:
        """Jump to a specific location using MI command (-exec-jump)"""
        result = self.execute_mi_command(f"-exec-jump {locspec}")

        return {
            "command": f"-exec-jump {locspec}",
            "output": "\n".join(result["output"]) if result["output"] else "",
            "error": result["error"],
            "state": self._state
        }

    def return_from_function(self) -> Dict[str, Any]:
        """Force return from current function using MI command (-exec-return)"""
        result = self.execute_mi_command("-exec-return")

        return {
            "command": "-exec-return",
            "output": "\n".join(result["output"]) if result["output"] else "",
            "error": result["error"],
            "state": self._state,
            "payload": result.get("payload")
        }

    def until(self, locspec: Optional[str] = None) -> Dict[str, Any]:
        """Run until a specific location or next line using MI command (-exec-until)"""
        mi_cmd = "-exec-until" if not locspec else f"-exec-until {locspec}"
        result = self.execute_mi_command(mi_cmd)

        return {
            "command": mi_cmd,
            "output": "\n".join(result["output"]) if result["output"] else "",
            "error": result["error"],
            "state": self._state
        }
        
    def set_breakpoint(self, location: str, condition: Optional[str] = None) -> Dict[str, Any]:
        """Set a breakpoint using MI command"""
        # Build MI break command
        mi_command = f"-break-insert {location}"
        if condition:
            mi_command = f"-break-insert -c \"{condition}\" {location}"
            
        result = self.execute_mi_command(mi_command)
        
        # Parse breakpoint info from payload
        output = ""
        if result["success"] and result["payload"]:
            bkpt = result["payload"].get("bkpt", {})
            number = bkpt.get("number", "?")
            addr = bkpt.get("addr", "?")
            func = bkpt.get("func", "")
            file = bkpt.get("file", "")
            line = bkpt.get("line", "")
            
            output = f"Breakpoint {number} at {addr}"
            if func:
                output += f": {func}"
            if file and line:
                output += f" ({file}:{line})"
                
        return {
            "command": mi_command,
            "output": output or "\n".join(result["output"]),
            "error": result["error"],
            "state": self._state,
            "payload": result["payload"]  # Include structured data
        }
        
    def evaluate_expression(self, expression: str) -> Dict[str, Any]:
        """Evaluate an expression using MI command"""
        result = self.execute_mi_command(f"-data-evaluate-expression \"{expression}\"")
        
        value = None
        if result["success"] and result["payload"]:
            value = result["payload"].get("value")
            
        return {
            "command": f"-data-evaluate-expression \"{expression}\"",
            "output": value if value else "\n".join(result["output"]),
            "error": result["error"],
            "state": self._state,
            "value": value
        }
        
    def read_memory_mi(self, address: str, word_format: str, word_size: int, nr_rows: int, nr_cols: int) -> Dict[str, Any]:
        """
        Read memory using MI command
        
        Args:
            address: Starting address
            word_format: Format (x=hex, d=decimal, o=octal, t=binary)
            word_size: Size of each word in bytes
            nr_rows: Number of rows
            nr_cols: Number of columns per row
            
        Returns:
            Structured memory data
        """
        mi_command = f"-data-read-memory {address} {word_format} {word_size} {nr_rows} {nr_cols}"
        result = self.execute_mi_command(mi_command)
        
        return {
            "command": mi_command,
            "output": "\n".join(result["output"]) if result["output"] else "",
            "error": result["error"],
            "state": self._state,
            "memory": result["payload"]  # Structured memory data
        }
        
    def list_breakpoints(self) -> Dict[str, Any]:
        """List all breakpoints using MI command"""
        result = self.execute_mi_command("-break-list")
        
        return {
            "command": "-break-list",
            "output": "\n".join(result["output"]) if result["output"] else "",
            "error": result["error"],
            "state": self._state,
            "breakpoints": result["payload"].get("BreakpointTable", {}).get("body", []) if result["payload"] else []
        }
        
    def delete_breakpoint(self, number: int) -> Dict[str, Any]:
        """Delete a breakpoint using MI command"""
        result = self.execute_mi_command(f"-break-delete {number}")
        
        return {
            "command": f"-break-delete {number}",
            "output": "\n".join(result["output"]) if result["output"] else f"Deleted breakpoint {number}",
            "error": result["error"],
            "state": self._state
        }
        
    def enable_breakpoint(self, number: int) -> Dict[str, Any]:
        """Enable a breakpoint using MI command"""
        result = self.execute_mi_command(f"-break-enable {number}")
        
        return {
            "command": f"-break-enable {number}",
            "output": "\n".join(result["output"]) if result["output"] else f"Enabled breakpoint {number}",
            "error": result["error"],
            "state": self._state
        }
        
    def disable_breakpoint(self, number: int) -> Dict[str, Any]:
        """Disable a breakpoint using MI command"""
        result = self.execute_mi_command(f"-break-disable {number}")
        
        return {
            "command": f"-break-disable {number}",
            "output": "\n".join(result["output"]) if result["output"] else f"Disabled breakpoint {number}",
            "error": result["error"],
            "state": self._state
        }
        
    def interrupt(self) -> Dict[str, Any]:
        """Send interrupt signal to the running program"""
        logger.info("Sending interrupt signal to GDB")
        
        # Use pygdbmi's interrupt_gdb method
        try:
            self.controller.interrupt_gdb()
            # Give it a moment to process
            import time
            time.sleep(0.1)
            
            # Check for any output
            responses = self.controller.get_gdb_response(timeout_sec=1.0, raise_error_on_timeout=False)
            output_lines = []
            
            for response in responses:
                if response.get("type") == "console" and response.get("payload"):
                    output_lines.append(response["payload"])
                elif response.get("type") == "notify":
                    self._handle_notify(response)
                    
            return {
                "success": True,
                "output": "".join(output_lines),
                "state": self._state
            }
        except Exception as e:
            logger.error(f"Failed to interrupt: {e}")
            return {
                "success": False,
                "error": str(e),
                "state": self._state
            }

    def interrupt_execution(self, all_threads: bool = False, thread_group: Optional[str] = None) -> Dict[str, Any]:
        """Interrupt target using MI command (-exec-interrupt)

        :param all_threads: If True, interrupt all threads (non-stop mode)
        :param thread_group: Optional thread group identifier to interrupt
        :returns: Structured interrupt result
        """
        mi_cmd = "-exec-interrupt"
        if all_threads:
            mi_cmd += " --all"
        elif thread_group:
            mi_cmd += f" --thread-group {thread_group}"

        result = self.execute_mi_command(mi_cmd)

        return {
            "command": mi_cmd,
            "output": "\n".join(result["output"]) if result["output"] else "",
            "error": result["error"],
            "state": self._state
        }
        
    def get_state(self) -> str:
        """Get current inferior state"""
        return self._state
        
    def close(self):
        """Clean up GDB controller"""
        if hasattr(self, 'controller'):
            self.controller.exit() 