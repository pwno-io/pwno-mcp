"""
GDB Controller wrapper for PwnoMCP
Handles pygdbmi integration with proper state management and response handling
Following pwndbg-gui's synchronous design pattern
"""

import logging
from enum import Enum, auto
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from pygdbmi import gdbcontroller
import threading
import time

logger = logging.getLogger(__name__)


class InferiorState(Enum):
    """State of the debugged process"""
    NONE = auto()
    LOADED = auto()
    RUNNING = auto()
    STOPPED = auto()
    EXITED = auto()


class ResponseToken(Enum):
    """Token types for multiplexing GDB responses"""
    # Command execution tokens
    EXECUTE = 1
    RUN = 2
    CONTINUE = 3
    NEXT = 4
    STEP = 5
    NEXTI = 6
    STEPI = 7
    
    # Context-specific tokens (pre-determined destinations)
    CONTEXT_FULL = 8      # Full context output
    CONTEXT_REGS = 9      # → registers component
    CONTEXT_STACK = 10    # → stack component
    CONTEXT_CODE = 11     # → code component
    CONTEXT_DISASM = 12   # → disasm component
    CONTEXT_BACKTRACE = 13 # → backtrace component
    
    # Memory/Heap tokens
    HEAP_CHUNKS = 20      # → heap component
    HEAP_BINS = 21        # → heap component
    HEAP_TCACHE = 22      # → heap component
    MEMORY_DUMP = 25      # → memory component
    VMMAP = 26            # → memory component
    
    # Info tokens
    INFO_BREAKPOINTS = 30 # → breakpoint component
    INFO_REGISTERS = 31   # → registers component
    
    # General tokens
    USER = 100           # User command → console
    INTERNAL = 200       # Internal command → discard


@dataclass
class GDBResponse:
    """Parsed GDB response"""
    token: Optional[ResponseToken]
    type: str
    message: str
    payload: Any
    raw: Dict[str, Any]


class GDBController:
    """
    Thread-safe wrapper around pygdbmi GdbController
    Implements synchronous patterns from pwndbg-gui
    """
    
    def __init__(self):
        self.controller: Optional[gdbcontroller.GdbController] = None
        self.inferior_state = InferiorState.NONE
        self.reader_thread: Optional[threading.Thread] = None
        self.running = False
        self._token_counter = 1000
        self._gdbinit_loaded = False
        
        # Response handling (synchronous, like pwndbg-gui)
        self.result: List[str] = []
        self.logs: List[str] = []
        
        # Stdio buffers
        self._stdout_buffer: List[str] = []
        self._stderr_buffer: List[str] = []
        self._console_buffer: List[str] = []
        self._max_buffer_size = 10000  # Max lines to keep in buffers
        
        # Token-based response buffers
        self._response_buffers: Dict[int, List[str]] = {}
        
        # Thread synchronization
        self._response_lock = threading.Lock()
        self._command_lock = threading.Lock()
        
    def initialize(self) -> bool:
        """Initialize GDB controller and start reader thread"""
        try:
            self.controller = gdbcontroller.GdbController()
            self.running = True
            
            # Start reader thread (following pwndbg-gui pattern)
            self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
            self.reader_thread.start()
            
            # Load .gdbinit if it exists
            self._load_gdbinit()
            
            logger.info("GDB controller initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize GDB controller: {e}")
            return False
            
    def shutdown(self):
        """Shutdown GDB controller and reader thread"""
        self.running = False
        
        if self.reader_thread:
            self.reader_thread.join(timeout=1.0)
            
        if self.controller:
            try:
                self.controller.exit()
            except:
                pass
            self.controller = None
                
    def _load_gdbinit(self):
        """Load .gdbinit file manually (GDB MI doesn't load it automatically)"""
        gdbinit_path = Path.home() / ".gdbinit"
        if gdbinit_path.exists():
            self.execute("source " + str(gdbinit_path), ResponseToken.INTERNAL)
            self._gdbinit_loaded = True
            
    def _reader_loop(self):
        """Continuously read responses from GDB (following pwndbg-gui pattern)"""
        while self.running:
            try:
                if not self.controller:
                    break
                    
                # Get response with timeout (like pwndbg-gui)
                response = self.controller.get_gdb_response(
                    timeout_sec=0.1,
                    raise_error_on_timeout=False
                )
                
                if response:
                    self._parse_response(response)
                    
            except Exception as e:
                if "closed file" in str(e).lower():
                    logger.info("GDB process closed, stopping reader")
                    self.running = False
                    break
                else:
                    logger.error(f"Error in reader loop: {e}")
                    
    def _parse_response(self, gdbmi_response: List[Dict[str, Any]]):
        """Parse response from GDB MI (following pwndbg-gui logic)"""
        for response in gdbmi_response:
            with self._response_lock:
                # Extract token if present
                token = None
                token_value = response.get("token")
                if token_value is not None:
                    try:
                        token = int(token_value)
                    except:
                        pass
                
                # Handle different response types (following pwndbg-gui pattern)
                resp_type = response.get("type", "")
                payload = response.get("payload", "")
                
                if resp_type == "console" and payload:
                    # Console output goes to result buffer
                    self.result.append(payload)
                    self._add_to_buffer(self._console_buffer, payload)
                    
                    # Buffer by token if present
                    if token is not None:
                        if token not in self._response_buffers:
                            self._response_buffers[token] = []
                        self._response_buffers[token].append(payload)
                        
                elif resp_type == "output":
                    # Inferior stdout
                    self.result.append(payload)
                    self._add_to_buffer(self._stdout_buffer, payload)
                    
                elif resp_type == "log":
                    # GDB logs/errors
                    self.logs.append(payload)
                    self._add_to_buffer(self._stderr_buffer, payload)
                    
                elif resp_type == "result":
                    # Command completion - flush buffers
                    self._handle_result(response, token)
                    
                elif resp_type == "notify":
                    # State changes
                    self._handle_notify(response)
                    
    def _handle_result(self, response: Dict[str, Any], token: Optional[int]):
        """Handle result messages (command completion)"""
        message = response.get("message", "")
        
        # Handle error messages
        if message == "error" and response.get("payload"):
            error_msg = response["payload"].get("msg", "Unknown error")
            self.result.append(error_msg)
            
        # Process token-based responses
        if token is not None and token in self._response_buffers:
            # Get buffered output for this token
            output = "".join(self._response_buffers[token])
            del self._response_buffers[token]
            
            # Store in context cache if it's a context token
            try:
                token_enum = ResponseToken(token)
                from pwnomcp.context import context_manager
                context_type = context_manager.get_context_type(token_enum)
                if context_type:
                    context_manager.store_context(context_type, output)
            except:
                pass
                
        # Clear result/log buffers
        self.result = []
        self.logs = []
        
    def _handle_notify(self, response: Dict[str, Any]):
        """Handle notify messages (state changes)"""
        message = response.get("message", "")
        
        if message == "running":
            self.inferior_state = InferiorState.RUNNING
            logger.debug("Inferior state: RUNNING")
            
        elif message == "stopped":
            if self.inferior_state != InferiorState.EXITED:
                self.inferior_state = InferiorState.STOPPED
                logger.debug("Inferior state: STOPPED")
                
        elif message == "thread-group-exited":
            self.inferior_state = InferiorState.EXITED
            logger.debug("Inferior state: EXITED")
            
        elif message == "thread-group-started":
            # Handle attach case (following pwndbg-gui)
            self.inferior_state = InferiorState.RUNNING
            logger.debug("Inferior state: RUNNING (attached)")
            
    def execute(self, command: str, token: Optional[ResponseToken] = None) -> ResponseToken:
        """
        Execute a GDB command synchronously
        Returns the token used for tracking the response
        """
        if not self.controller:
            raise RuntimeError("GDB controller not initialized")
            
        # Use provided token or default to USER
        if token is None:
            token = ResponseToken.USER
            
        # Send command with token prefix
        with self._command_lock:
            prefixed_cmd = f"{token.value}-{command}"
            self.controller.write(prefixed_cmd, read_response=False)
            logger.debug(f"Sent command: {command} (token: {token.value})")
            
        return token
        
    def execute_and_wait(self, command: str, timeout: float = 5.0) -> Optional[str]:
        """
        Execute command and wait for response synchronously
        Returns the console output or None on timeout
        """
        if not self.controller:
            return None
            
        # Create unique token
        token_value = self._token_counter
        self._token_counter += 1
        
        # Clear any existing buffer for this token
        with self._response_lock:
            self._response_buffers[token_value] = []
            
        # Send command
        with self._command_lock:
            prefixed_cmd = f"{token_value}-{command}"
            self.controller.write(prefixed_cmd, read_response=False)
            
        # Wait for response with polling
        start_time = time.time()
        while time.time() - start_time < timeout:
            with self._response_lock:
                if token_value in self._response_buffers:
                    # We have a response
                    output = "".join(self._response_buffers[token_value])
                    # Clean up
                    del self._response_buffers[token_value]
                    return output
                    
            time.sleep(0.01)  # Small sleep to avoid busy waiting
            
        # Timeout - clean up
        with self._response_lock:
            if token_value in self._response_buffers:
                del self._response_buffers[token_value]
                
        return None
        
    def is_running(self) -> bool:
        """Check if inferior is running"""
        return self.inferior_state == InferiorState.RUNNING
        
    def is_stopped(self) -> bool:
        """Check if inferior is stopped"""
        return self.inferior_state == InferiorState.STOPPED
        
    def _add_to_buffer(self, buffer: List[str], content: str):
        """Add content to buffer with size limit"""
        buffer.append(content)
        # Trim buffer if too large
        if len(buffer) > self._max_buffer_size:
            buffer[:] = buffer[-self._max_buffer_size:]
            
    def get_stdout(self, clear: bool = False) -> str:
        """Get buffered stdout content"""
        with self._response_lock:
            content = "".join(self._stdout_buffer)
            if clear:
                self._stdout_buffer.clear()
            return content
        
    def get_stderr(self, clear: bool = False) -> str:
        """Get buffered stderr content"""
        with self._response_lock:
            content = "".join(self._stderr_buffer)
            if clear:
                self._stderr_buffer.clear()
            return content
        
    def get_console(self, clear: bool = False) -> str:
        """Get buffered console output"""
        with self._response_lock:
            content = "".join(self._console_buffer)
            if clear:
                self._console_buffer.clear()
            return content
        
    def clear_buffers(self):
        """Clear all output buffers"""
        with self._response_lock:
            self._stdout_buffer.clear()
            self._stderr_buffer.clear()
            self._console_buffer.clear()


# Global GDB controller instance
gdb_controller = GDBController()