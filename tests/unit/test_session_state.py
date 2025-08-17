"""
Unit tests for Session State management
"""

import pytest
from datetime import datetime
from pwnomcp.state.session import SessionState, Breakpoint, Watch


class TestSessionState:
    """Test session state management"""

    @pytest.fixture
    def session(self):
        """Create a fresh session state"""
        return SessionState()

    def test_initial_state(self, session):
        """Test initial session state"""
        assert session.binary_path is None
        assert session.binary_loaded is False
        assert session.state == "idle"
        assert len(session.breakpoints) == 0
        assert len(session.watches) == 0

    def test_add_breakpoint(self, session):
        """Test adding breakpoints"""
        bp = session.add_breakpoint(1, "0x401234", "x == 5")
        assert bp.number == 1
        assert bp.address == "0x401234"
        assert bp.condition == "x == 5"
        assert bp.enabled is True
        assert 1 in session.breakpoints

    def test_remove_breakpoint(self, session):
        """Test removing breakpoints"""
        session.add_breakpoint(1, "0x401234")
        assert session.remove_breakpoint(1) is True
        assert 1 not in session.breakpoints
        assert session.remove_breakpoint(999) is False

    def test_toggle_breakpoint(self, session):
        """Test toggling breakpoint state"""
        session.add_breakpoint(1, "0x401234")
        assert session.breakpoints[1].enabled is True
        
        session.toggle_breakpoint(1)
        assert session.breakpoints[1].enabled is False
        
        session.toggle_breakpoint(1)
        assert session.breakpoints[1].enabled is True

    def test_add_watch(self, session):
        """Test adding memory watches"""
        watch = session.add_watch("0x7fff1234", 128, "hex")
        assert watch.address == "0x7fff1234"
        assert watch.size == 128
        assert watch.format == "hex"
        assert len(session.watches) == 1

    def test_remove_watch(self, session):
        """Test removing watches"""
        session.add_watch("0x7fff1234")
        assert session.remove_watch("0x7fff1234") is True
        assert len(session.watches) == 0
        assert session.remove_watch("0x9999") is False

    def test_record_command(self, session):
        """Test command history recording"""
        session.record_command("break main", {"success": True})
        assert len(session.command_history) == 1
        assert session.command_history[0]["command"] == "break main"
        assert session.command_history[0]["result"]["success"] is True

    def test_update_state(self, session):
        """Test state transitions"""
        session.update_state("running")
        assert session.state == "running"
        
        session.update_state("stopped")
        assert session.state == "stopped"

    def test_clear_session(self, session):
        """Test clearing session state"""
        # Set up some state
        session.binary_path = "/test/binary"
        session.binary_loaded = True
        session.add_breakpoint(1, "0x401234")
        session.add_watch("0x7fff1234")
        session.record_command("test", {})
        
        # Clear session
        session.clear()
        
        assert session.binary_path is None
        assert session.binary_loaded is False
        assert len(session.breakpoints) == 0
        assert len(session.watches) == 0
        # Command history should be preserved
        assert len(session.command_history) == 1

    def test_to_dict_serialization(self, session):
        """Test session serialization to dict"""
        session.binary_path = "/test/binary"
        session.add_breakpoint(1, "0x401234", "x > 0")
        session.add_watch("0x7fff1234", 64, "hex")
        
        data = session.to_dict()
        
        assert data["binary_path"] == "/test/binary"
        assert 1 in data["breakpoints"]
        assert data["breakpoints"][1]["address"] == "0x401234"
        assert len(data["watches"]) == 1
        assert data["watches"][0]["address"] == "0x7fff1234"
