"""
Context management and routing for PwnoMCP
Combines context caching, automatic updates, and token-based routing
"""

import asyncio
import logging
from typing import Dict, Optional
from dataclasses import dataclass
from datetime import datetime

from pwnomcp.gdb_controller import gdb_controller, ResponseToken, InferiorState

logger = logging.getLogger(__name__)


@dataclass
class ContextCache:
    """Cached context data"""
    registers: Optional[str] = None
    stack: Optional[str] = None
    code: Optional[str] = None
    disasm: Optional[str] = None
    backtrace: Optional[str] = None
    heap: Optional[str] = None
    timestamp: Optional[datetime] = None
    
    def clear(self):
        """Clear all cached data"""
        self.registers = None
        self.stack = None
        self.code = None
        self.disasm = None
        self.backtrace = None
        self.heap = None
        self.timestamp = None
        
    def is_valid(self, max_age_seconds: float = 1.0) -> bool:
        """Check if cache is still valid"""
        if not self.timestamp:
            return False
        age = (datetime.now() - self.timestamp).total_seconds()
        return age < max_age_seconds


class TokenRouter:
    """Routes GDB responses based on pre-assigned tokens (pwndbg-gui pattern)"""
    
    # Map tokens to context types for caching
    TOKEN_TO_CONTEXT: Dict[ResponseToken, str] = {
        ResponseToken.CONTEXT_REGS: "registers",
        ResponseToken.CONTEXT_STACK: "stack",
        ResponseToken.CONTEXT_CODE: "code",
        ResponseToken.CONTEXT_DISASM: "disasm",
        ResponseToken.CONTEXT_BACKTRACE: "backtrace",
        ResponseToken.HEAP_CHUNKS: "heap",
        ResponseToken.HEAP_BINS: "heap",
        ResponseToken.HEAP_TCACHE: "heap",
    }
    
    def get_context_type(self, token: Optional[ResponseToken]) -> Optional[str]:
        """Get context type for caching based on token"""
        if token is None:
            return None
        return self.TOKEN_TO_CONTEXT.get(token)


class ContextManager:
    """
    Manages context updates following pwndbg-gui pattern:
    - Updates contexts after every user command
    - Caches context data
    - Routes updates via tokens
    """
    
    def __init__(self):
        self.cache = ContextCache()
        self.router = TokenRouter()
        self.updating = False
        self._context_tokens = {
            'regs': ResponseToken.CONTEXT_REGS,
            'stack': ResponseToken.CONTEXT_STACK,
            'code': ResponseToken.CONTEXT_CODE,
            'disasm': ResponseToken.CONTEXT_DISASM,
            'backtrace': ResponseToken.CONTEXT_BACKTRACE,
        }
        
    async def update_contexts(self, force: bool = False):
        """Update all contexts (called after user commands)"""
        # Only update if inferior is stopped
        if gdb_controller.inferior_state != InferiorState.STOPPED:
            logger.debug("Skipping context update - inferior not stopped")
            return
            
        # Skip if already updating
        if self.updating and not force:
            logger.debug("Context update already in progress")
            return
            
        self.updating = True
        try:
            # Clear old cache
            self.cache.clear()
            
            # Send context commands with specific tokens
            for context_name, token in self._context_tokens.items():
                gdb_controller.execute(f"context {context_name}", token)
                
            # Also update heap info
            gdb_controller.execute("heap", ResponseToken.HEAP_CHUNKS)
            gdb_controller.execute("bins", ResponseToken.HEAP_BINS)
            
            # Update timestamp
            self.cache.timestamp = datetime.now()
            
            logger.debug("Context update commands sent")
            
        finally:
            self.updating = False
            
    def store_context(self, context_type: str, data: str):
        """Store context data in cache"""
        if context_type == "registers":
            self.cache.registers = data
        elif context_type == "stack":
            self.cache.stack = data
        elif context_type == "code":
            self.cache.code = data
        elif context_type == "disasm":
            self.cache.disasm = data
        elif context_type == "backtrace":
            self.cache.backtrace = data
        elif context_type == "heap":
            self.cache.heap = data
            
    def get_cached_context(self) -> Dict[str, Optional[str]]:
        """Get all cached context data"""
        return {
            "registers": self.cache.registers,
            "stack": self.cache.stack,
            "code": self.cache.code,
            "disasm": self.cache.disasm,
            "backtrace": self.cache.backtrace,
            "heap": self.cache.heap,
            "timestamp": self.cache.timestamp.isoformat() if self.cache.timestamp else None
        }
        
    async def on_command_executed(self, command: str):
        """Called after any user command is executed"""
        # Skip context update for certain commands
        skip_commands = ["context", "help", "pwndbg"]
        if any(command.startswith(cmd) for cmd in skip_commands):
            return
            
        # For commands that start execution, wait a bit for inferior to stop
        execution_commands = ["run", "continue", "c", "r"]
        if any(command.startswith(cmd) for cmd in execution_commands):
            # Wait a bit to see if inferior stops (e.g., at a breakpoint)
            await asyncio.sleep(0.3)
            
        # Update contexts asynchronously
        await self.update_contexts()
        
    def get_context_type(self, token: Optional[ResponseToken]) -> Optional[str]:
        """Get context type for token (delegates to router)"""
        return self.router.get_context_type(token)


# Global context manager instance
context_manager = ContextManager()