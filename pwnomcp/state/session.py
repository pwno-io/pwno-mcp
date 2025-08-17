"""
Session state management for Pwno MCP

Maintains the current debugging session state including:
- Loaded binary information
- Breakpoints
- Watches
- Execution history
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class Breakpoint:
    """Represents a breakpoint in the debugging session"""

    number: int
    address: str
    enabled: bool = True
    hit_count: int = 0
    condition: str | None = None


@dataclass
class Watch:
    """Represents a memory watch"""

    address: str
    size: int = 64  # Default watch size in bytes
    format: str = "hex"  # hex, string, int


@dataclass
class SessionState:
    """Maintains the complete state of a debugging session"""

    # Binary information
    binary_path: str | None = None
    binary_loaded: bool = False
    entry_point: str | None = None

    # Process state
    pid: int | None = None
    state: str = "idle"  # idle, running, stopped, exited

    # Debugging artifacts
    breakpoints: dict[int, Breakpoint] = field(default_factory=dict)
    watches: list[Watch] = field(default_factory=list)

    # Execution history
    command_history: list[dict[str, Any]] = field(default_factory=list)

    # Session metadata
    session_id: str = field(default_factory=lambda: datetime.now().isoformat())
    created_at: datetime = field(default_factory=datetime.now)

    def add_breakpoint(self, number: int, address: str, condition: str | None = None) -> Breakpoint:
        """Add a new breakpoint"""
        bp = Breakpoint(number=number, address=address, condition=condition)
        self.breakpoints[number] = bp
        logger.info(f"Added breakpoint #{number} at {address}")
        return bp

    def remove_breakpoint(self, number: int) -> bool:
        """Remove a breakpoint by number"""
        if number in self.breakpoints:
            del self.breakpoints[number]
            logger.info(f"Removed breakpoint #{number}")
            return True
        return False

    def toggle_breakpoint(self, number: int) -> bool:
        """Toggle breakpoint enabled state"""
        if number in self.breakpoints:
            self.breakpoints[number].enabled = not self.breakpoints[number].enabled
            state = "enabled" if self.breakpoints[number].enabled else "disabled"
            logger.info(f"Breakpoint #{number} {state}")
            return True
        return False

    def add_watch(self, address: str, size: int = 64, format: str = "hex") -> Watch:
        """Add a memory watch"""
        watch = Watch(address=address, size=size, format=format)
        self.watches.append(watch)
        logger.info(f"Added watch for {address} ({size} bytes, {format})")
        return watch

    def remove_watch(self, address: str) -> bool:
        """Remove a watch by address"""
        for i, watch in enumerate(self.watches):
            if watch.address == address:
                self.watches.pop(i)
                logger.info(f"Removed watch for {address}")
                return True
        return False

    def record_command(self, command: str, result: dict[str, Any]):
        """Record a command and its result in history"""
        self.command_history.append({"timestamp": datetime.now().isoformat(), "command": command, "result": result})

    def update_state(self, new_state: str):
        """Update the process state"""
        old_state = self.state
        self.state = new_state
        logger.debug(f"State transition: {old_state} -> {new_state}")

    def clear(self):
        """Clear session state for a new debugging session"""
        self.binary_path = None
        self.binary_loaded = False
        self.entry_point = None
        self.pid = None
        self.state = "idle"
        self.breakpoints.clear()
        self.watches.clear()
        # Keep command history for analysis
        logger.info("Session state cleared")

    def to_dict(self) -> dict[str, Any]:
        """Convert session state to dictionary for serialization"""
        return {
            "session_id": self.session_id,
            "created_at": self.created_at.isoformat(),
            "binary_path": self.binary_path,
            "binary_loaded": self.binary_loaded,
            "entry_point": self.entry_point,
            "pid": self.pid,
            "state": self.state,
            "breakpoints": {
                num: {
                    "address": bp.address,
                    "enabled": bp.enabled,
                    "hit_count": bp.hit_count,
                    "condition": bp.condition,
                }
                for num, bp in self.breakpoints.items()
            },
            "watches": [{"address": w.address, "size": w.size, "format": w.format} for w in self.watches],
            "command_count": len(self.command_history),
        }
