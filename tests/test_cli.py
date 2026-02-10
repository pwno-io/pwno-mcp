from pwnomcp.cli import _normalize_script_lines


def test_normalize_script_lines_strips_and_dedents():
    script = """
        set pagination off

        break *0x401000
    """

    assert _normalize_script_lines(script) == [
        "set pagination off",
        "break *0x401000",
    ]


def test_normalize_script_lines_empty():
    assert _normalize_script_lines("") == []
