from pwnomcp.state import SessionState


def test_breakpoint_lifecycle():
    state = SessionState()

    bp = state.add_breakpoint(1, "0xdeadbeef")
    assert state.breakpoints[1] == bp
    assert bp.enabled is True

    assert state.toggle_breakpoint(1) is True
    assert state.breakpoints[1].enabled is False

    assert state.remove_breakpoint(1) is True
    assert 1 not in state.breakpoints
    assert state.remove_breakpoint(1) is False


def test_watch_lifecycle():
    state = SessionState()

    watch = state.add_watch("0x4141", size=32, format="string")
    assert watch in state.watches

    assert state.remove_watch("0x4141") is True
    assert state.watches == []


def test_to_dict_contains_expected_fields():
    state = SessionState()
    state.add_breakpoint(2, "0x1000", condition="eax==0")
    state.add_watch("0x2000")

    payload = state.to_dict()
    assert payload["binary_loaded"] is False
    assert payload["state"] == "idle"
    assert payload["breakpoints"][2]["address"] == "0x1000"
    assert payload["breakpoints"][2]["condition"] == "eax==0"
    assert payload["watches"][0]["address"] == "0x2000"
