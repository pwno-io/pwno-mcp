"""
Unit tests for GDB Controller
"""

import pytest
from unittest.mock import MagicMock, patch, call
from pwnomcp.gdb.controller import GdbController


class TestGdbController:
    """Test GDB Controller functionality"""

    @pytest.fixture
    def mock_gdbmi(self):
        """Mock pygdbmi GdbController"""
        with patch("pwnomcp.gdb.controller.gdbcontroller.GdbController") as mock:
            yield mock

    @pytest.fixture
    def gdb_controller(self, mock_gdbmi):
        """Create GDB controller with mocked pygdbmi"""
        mock_instance = MagicMock()
        mock_gdbmi.return_value = mock_instance
        controller = GdbController()
        controller.controller = mock_instance
        return controller

    def test_initialization(self, mock_gdbmi):
        """Test GDB controller initialization"""
        controller = GdbController()
        mock_gdbmi.assert_called_once_with(
            command=["pwndbg", "--interpreter=mi3", "--quiet"]
        )
        assert controller._initialized is False
        assert controller._inferior_pid is None
        assert controller._state == "idle"

    def test_initialize_command(self, gdb_controller):
        """Test GDB initialization with pwndbg"""
        gdb_controller.controller.write.return_value = [
            {"type": "result", "message": "done", "payload": {}}
        ]

        result = gdb_controller.initialize()
        assert result["status"] == "initialized"
        assert gdb_controller._initialized is True

    def test_execute_command(self, gdb_controller):
        """Test command execution"""
        gdb_controller.controller.write.return_value = None
        gdb_controller.controller.get_gdb_response.return_value = [
            {"type": "console", "payload": "Test output\n"},
            {"type": "result", "message": "done"},
        ]

        result = gdb_controller.execute_command("info registers")
        assert result["command"] == "info registers"
        assert result["output"] == "Test output\n"
        assert result["error"] is None

    def test_set_file(self, gdb_controller):
        """Test loading a binary file"""
        gdb_controller.controller.write.return_value = [
            {"type": "result", "message": "done", "payload": {}}
        ]

        result = gdb_controller.set_file("/path/to/binary")
        assert result["command"] == "file /path/to/binary"
        assert gdb_controller._state == "stopped"

    def test_set_breakpoint(self, gdb_controller):
        """Test setting a breakpoint"""
        gdb_controller.controller.write.return_value = [
            {
                "type": "result",
                "message": "done",
                "payload": {
                    "bkpt": {
                        "number": "1",
                        "addr": "0x401234",
                        "func": "main",
                        "file": "test.c",
                        "line": "10",
                    }
                },
            }
        ]

        result = gdb_controller.set_breakpoint("main")
        assert "Breakpoint 1 at 0x401234" in result["output"]
        assert result["error"] is None

    def test_state_transitions(self, gdb_controller):
        """Test state transition handling"""
        # Test running state
        gdb_controller._handle_notify({"message": "running"})
        assert gdb_controller._state == "running"

        # Test stopped state
        gdb_controller._handle_notify(
            {"message": "stopped", "payload": {"reason": "breakpoint-hit"}}
        )
        assert gdb_controller._state == "stopped"

        # Test exited state
        gdb_controller._handle_notify({"message": "thread-group-exited"})
        assert gdb_controller._state == "exited"

    def test_evaluate_expression(self, gdb_controller):
        """Test expression evaluation"""
        gdb_controller.controller.write.return_value = [
            {"type": "result", "message": "done", "payload": {"value": "42"}}
        ]

        result = gdb_controller.evaluate_expression("$rax")
        assert result["value"] == "42"
        assert result["command"] == "print $rax"

    def test_interrupt(self, gdb_controller):
        """Test interrupt functionality"""
        with patch.object(gdb_controller.controller, "interrupt_gdb") as mock_interrupt:
            gdb_controller.controller.get_gdb_response.return_value = []
            result = gdb_controller.interrupt()
            mock_interrupt.assert_called_once()
            assert result["success"] is True

    def test_get_context_invalid_state(self, gdb_controller):
        """Test getting context in invalid state"""
        gdb_controller._state = "running"
        result = gdb_controller.get_context("regs")
        assert result["error"] == "Cannot get context while inferior is running"
