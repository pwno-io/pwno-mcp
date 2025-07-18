"""
GDB Controller wrapper for PwnoMCP
Handles pygdbmi integration with proper state management and response handling
"""

import asyncio
import logging
from enum import Enum, auto
from pathlib import Path
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass
from pygdbmi import gdbcontroller
import threading
import queue
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
    Implements patterns from pwndbg-gui for robust async operation
    """
    
    def __init__(self):
        self.controller: Optional[gdbcontroller.GdbController] = None
        self.inferior_state = InferiorState.NONE
        self.response_queue = queue.Queue()
        self.command_queue = queue.Queue()
        self.callbacks: Dict[ResponseToken, List[Callable]] = {}
        self.reader_thread: Optional[threading.Thread] = None
        self.writer_thread: Optional[threading.Thread] = None
        self.running = False
        self._token_counter = 1000
        self._response_buffer: Dict[ResponseToken, List[str]] = {}
        self._gdbinit_loaded = False
        
        # Stdio buffers
        self._stdout_buffer: List[str] = []
        self._stderr_buffer: List[str] = []
        self._console_buffer: List[str] = []
        self._max_buffer_size = 10000  # Max lines to keep in buffers
        
        # WebSocket update queue for thread-safe updates
        self._ws_update_queue: queue.Queue = queue.Queue()
        
    def initialize(self) -> bool:
        """Initialize GDB controller and start worker threads"""
        try:
            self.controller = gdbcontroller.GdbController()
            self.running = True
            
            # Start reader thread
            self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
            self.reader_thread.start()
            
            # Start writer thread  
            self.writer_thread = threading.Thread(target=self._writer_loop, daemon=True)
            self.writer_thread.start()
            
            # Load .gdbinit if it exists
            self._load_gdbinit()
            
            logger.info("GDB controller initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize GDB controller: {e}")
            return False
            
    def shutdown(self):
        """Shutdown GDB controller and worker threads"""
        self.running = False
        
        # Give threads a moment to finish
        import time
        time.sleep(0.2)
        
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
            self._send_command(ResponseToken.INTERNAL, f"source {gdbinit_path}")
            self._gdbinit_loaded = True
            
    def _reader_loop(self):
        """Continuously read responses from GDB"""
        while self.running:
            try:
                if not self.controller:
                    break
                    
                response = self.controller.get_gdb_response(
                    timeout_sec=0.1,
                    raise_error_on_timeout=False
                )
                if response:
                    for resp in response:
                        self._handle_response(resp)
            except Exception as e:
                if "closed file" in str(e).lower():
                    logger.info("GDB process closed, stopping reader")
                    self.running = False
                    break
                else:
                    logger.error(f"Error in reader loop: {e}")
                
    def _writer_loop(self):
        """Process command queue and send to GDB"""
        while self.running:
            try:
                if not self.controller:
                    break
                    
                token, command = self.command_queue.get(timeout=0.1)
                if token and command:
                    # Prefix command with token for tracking
                    prefixed_cmd = f"{token.value}-{command}"
                    self.controller.write(prefixed_cmd, read_response=False)
                    logger.debug(f"Sent command: {prefixed_cmd}")
            except queue.Empty:
                continue
            except Exception as e:
                if "closed file" in str(e).lower():
                    logger.info("GDB process closed, stopping writer")
                    self.running = False
                    break
                else:
                    logger.error(f"Error in writer loop: {e}")
                
    def _handle_response(self, response: Dict[str, Any]):
        """Parse and handle GDB response"""
        try:
            # Extract token if present
            token = None
            if "token" in response and response["token"]:
                try:
                    token_value = int(response["token"])
                    token = ResponseToken(token_value)
                except:
                    pass
                    
            # Create parsed response
            parsed = GDBResponse(
                token=token,
                type=response.get("type", ""),
                message=response.get("message", ""),
                payload=response.get("payload"),
                raw=response
            )
            
            # Update inferior state based on notifications
            if parsed.type == "notify":
                self._update_inferior_state(parsed)
                
            # Buffer different types of output
            if parsed.payload:
                if parsed.type == "console":
                    # GDB console output
                    self._add_to_buffer(self._console_buffer, parsed.payload)
                    
                    # Follow pwndbg-gui pattern: buffer based on token
                    if token and token not in self._response_buffer:
                        self._response_buffer[token] = []
                    if token:
                        self._response_buffer[token].append(parsed.payload)
                elif parsed.type == "output":
                    # Inferior stdout
                    self._add_to_buffer(self._stdout_buffer, parsed.payload)
                    self._emit_ws_update("stdout", parsed.payload, token)
                elif parsed.type == "log":
                    # GDB log/error output
                    self._add_to_buffer(self._stderr_buffer, parsed.payload)
                    self._emit_ws_update("stderr", parsed.payload, token)
                    
            # Handle result type (command completion) - emit buffered content
            if parsed.type == "result" and token and token in self._response_buffer:
                # Get the appropriate update type based on token
                from pwnomcp.context import context_manager
                update_type = context_manager.get_update_type(token)
                
                # Combine buffered output and emit
                combined_output = "".join(self._response_buffer[token])
                self._response_buffer.pop(token)
                
                # Store in context cache if it's a context command
                try:
                    from pwnomcp.context import context_manager
                    if token in [ResponseToken.CONTEXT_REGS, ResponseToken.CONTEXT_STACK,
                                ResponseToken.CONTEXT_CODE, ResponseToken.CONTEXT_DISASM,
                                ResponseToken.CONTEXT_BACKTRACE, ResponseToken.HEAP_CHUNKS]:
                        context_manager.store_context(update_type.value, combined_output)
                except:
                    pass
                
                # Emit via WebSocket using token-determined destination
                self._emit_ws_update(update_type.value, combined_output, token)
            
            # Queue response for processing
            self.response_queue.put(parsed)
            
            # Trigger callbacks
            if token in self.callbacks:
                for callback in self.callbacks[token]:
                    callback(parsed)
                    
        except Exception as e:
            logger.error(f"Error handling response: {e}")
            
    def _update_inferior_state(self, response: GDBResponse):
        """Update inferior state based on GDB notifications"""
        old_state = self.inferior_state
        if response.payload:
            if "stopped" in str(response.payload):
                self.inferior_state = InferiorState.STOPPED
            elif "running" in str(response.payload):
                self.inferior_state = InferiorState.RUNNING
            elif "exited" in str(response.payload):
                self.inferior_state = InferiorState.EXITED
                
        # Emit state change via WebSocket
        if old_state != self.inferior_state:
            self._emit_ws_update("state", {
                "old_state": old_state.name,
                "new_state": self.inferior_state.name
            })
                
    def _send_command(self, token: ResponseToken, command: str):
        """Queue command for sending to GDB"""
        self.command_queue.put((token, command))
        
        # Register command for context tracking if needed
        pass
        
    def execute(self, command: str, token: Optional[ResponseToken] = None) -> ResponseToken:
        """
        Execute a GDB command
        Returns the token used for tracking the response
        """
        if not token:
            token = ResponseToken.USER
            
        self._send_command(token, command)
        return token
        
    def execute_and_wait(self, command: str, timeout: float = 5.0) -> Optional[str]:
        """
        Execute command and wait for response
        Returns the console output or None on timeout
        """
        token = ResponseToken(self._token_counter)
        self._token_counter += 1
        
        result_event = threading.Event()
        result_output = []
        
        def callback(response: GDBResponse):
            if response.type == "output":
                result_output.append(response.payload)
                result_event.set()
                
        self.register_callback(token, callback)
        self._send_command(token, command)
        
        if result_event.wait(timeout):
            self.unregister_callback(token, callback)
            return "".join(result_output)
        else:
            self.unregister_callback(token, callback)
            return None
            
    def register_callback(self, token: ResponseToken, callback: Callable):
        """Register callback for specific token responses"""
        if token not in self.callbacks:
            self.callbacks[token] = []
        self.callbacks[token].append(callback)
        
    def unregister_callback(self, token: ResponseToken, callback: Callable):
        """Unregister callback"""
        if token in self.callbacks:
            self.callbacks[token].remove(callback)
            if not self.callbacks[token]:
                del self.callbacks[token]
                
    def get_response(self, timeout: float = 0.1) -> Optional[GDBResponse]:
        """Get response from queue"""
        try:
            return self.response_queue.get(timeout=timeout)
        except queue.Empty:
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
        content = "".join(self._stdout_buffer)
        if clear:
            self._stdout_buffer.clear()
        return content
        
    def get_stderr(self, clear: bool = False) -> str:
        """Get buffered stderr content"""
        content = "".join(self._stderr_buffer)
        if clear:
            self._stderr_buffer.clear()
        return content
        
    def get_console(self, clear: bool = False) -> str:
        """Get buffered console output"""
        content = "".join(self._console_buffer)
        if clear:
            self._console_buffer.clear()
        return content
        
    def clear_buffers(self):
        """Clear all output buffers"""
        self._stdout_buffer.clear()
        self._stderr_buffer.clear()
        self._console_buffer.clear()
        
    def _emit_ws_update(self, update_type: str, data: Any, token: Optional[ResponseToken] = None):
        """Emit update via WebSocket (thread-safe)"""
        try:
            # Queue the update for processing in the main thread
            self._ws_update_queue.put((update_type, data, token))
        except Exception as e:
            # Don't let WebSocket errors affect GDB operation
            logger.debug(f"WebSocket update error: {e}")
            
    def emit_context_update(self, context_type: str, data: str):
        """Emit context update via WebSocket"""
        self._emit_ws_update(context_type, data)
        
    async def process_ws_updates(self):
        """Process WebSocket updates from the queue (call from main thread)"""
        while True:
            try:
                # Get update from queue with timeout
                update_data = self._ws_update_queue.get(timeout=0.1)
                update_type, data, token = update_data
                
                # Import here to avoid circular dependency
                from pwnomcp.websocket import ws_manager, WSUpdate, UpdateType
                
                # Map string types to enum
                type_map = {
                    "console": UpdateType.CONSOLE,
                    "stdout": UpdateType.STDOUT,
                    "stderr": UpdateType.STDERR,
                    "state": UpdateType.STATE,
                    "context": UpdateType.CONTEXT,
                    "breakpoint": UpdateType.BREAKPOINT,
                    "heap": UpdateType.HEAP,
                    "registers": UpdateType.REGISTERS,
                    "stack": UpdateType.STACK,
                    "memory": UpdateType.MEMORY,
                    "error": UpdateType.ERROR
                }
                
                update = WSUpdate(
                    type=type_map.get(update_type, UpdateType.CONSOLE),
                    data=data,
                    token=token.value if token else None
                )
                
                # Queue update for WebSocket
                await ws_manager.queue_update(update)
                
            except queue.Empty:
                await asyncio.sleep(0.01)
            except Exception as e:
                logger.debug(f"Error processing WebSocket update: {e}")
                await asyncio.sleep(0.1)


# Global GDB controller instance
gdb_controller = GDBController()