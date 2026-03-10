"""Multi-session debug registry for Pwno MCP."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import logging
import os
import threading
import uuid
from typing import Dict, List, Optional, Any

from pwnomcp.tools.backends import GdbController, PwndbgTools
from pwnomcp.state.session import SessionState
from pwnomcp.utils.paths import RuntimePaths, sanitize_session_id

logger = logging.getLogger(__name__)


@dataclass
class DebugSession:
    """Container for a full debugger session and associated resources."""

    session_id: str
    runtime_dir: str
    gdb: GdbController
    state: SessionState
    tools: PwndbgTools
    created_at: datetime = field(default_factory=datetime.utcnow)
    lock: threading.RLock = field(default_factory=threading.RLock)
    driver_pid: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize lightweight metadata for API responses."""
        return {
            "session_id": self.session_id,
            "created_at": self.created_at.isoformat(),
            "runtime_dir": self.runtime_dir,
            "binary_path": self.state.binary_path,
            "binary_loaded": self.state.binary_loaded,
            "inferior_pid": self.state.pid,
            "driver_pid": self.driver_pid,
            "state": self.state.state,
            "gdb_state": self.gdb.get_state(),
        }


class DebugSessionRegistry:
    """Tracks independent debugger sessions keyed by session id."""

    def __init__(self, runtime_paths: RuntimePaths):
        self.runtime_paths = runtime_paths
        self.sessions: Dict[str, DebugSession] = {}
        self.default_session_id: Optional[str] = None
        self._lock = threading.RLock()

    def _new_session_id(self) -> str:
        return uuid.uuid4().hex[:12]

    def _runtime_dir_for(self, session_id: str) -> str:
        path = os.path.join(
            self.runtime_paths.sessions_dir, sanitize_session_id(session_id)
        )
        os.makedirs(path, exist_ok=True)
        return path

    def create_session(self, session_id: Optional[str] = None) -> DebugSession:
        """Create (or return existing) debugger session by id."""
        with self._lock:
            chosen_id = (
                sanitize_session_id(session_id)
                if session_id
                else self._new_session_id()
            )
            if chosen_id in self.sessions:
                return self.sessions[chosen_id]

            runtime_dir = self._runtime_dir_for(chosen_id)
            gdb = GdbController()
            state = SessionState(session_id=chosen_id)
            tools = PwndbgTools(gdb, state)
            session = DebugSession(
                session_id=chosen_id,
                runtime_dir=runtime_dir,
                gdb=gdb,
                state=state,
                tools=tools,
            )
            self.sessions[chosen_id] = session
            if self.default_session_id is None:
                self.default_session_id = chosen_id
            logger.info("Created debug session '%s'", chosen_id)
            return session

    def get_session(self, session_id: str) -> Optional[DebugSession]:
        lookup_id = sanitize_session_id(session_id)
        with self._lock:
            return self.sessions.get(lookup_id)

    def ensure_session(self, session_id: Optional[str] = None) -> DebugSession:
        """Return an existing session, creating if necessary."""
        with self._lock:
            if session_id:
                existing = self.sessions.get(session_id)
                if existing:
                    return existing
                return self.create_session(session_id)

            if self.default_session_id and self.default_session_id in self.sessions:
                return self.sessions[self.default_session_id]
            return self.create_session("default")

    def list_sessions(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [session.to_dict() for session in self.sessions.values()]

    def close_session(self, session_id: str) -> Dict[str, Any]:
        """Close a session and release associated resources."""
        lookup_id = sanitize_session_id(session_id)
        with self._lock:
            session = self.sessions.pop(lookup_id, None)
            if not session:
                return {
                    "success": False,
                    "error": f"Session '{lookup_id}' not found",
                }

            try:
                session.gdb.close()
            except Exception:
                logger.exception("Failed to close gdb for session '%s'", lookup_id)

            if self.default_session_id == lookup_id:
                self.default_session_id = next(iter(self.sessions), None)

            logger.info("Closed debug session '%s'", lookup_id)
            return {"success": True, "session_id": lookup_id}

    def close_all(self) -> None:
        """Close all tracked sessions."""
        with self._lock:
            for session_id in list(self.sessions.keys()):
                self.close_session(session_id)
