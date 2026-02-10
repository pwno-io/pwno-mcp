import pytest

from pwnomcp.router.mcp import catch_errors


@pytest.mark.asyncio
async def test_catch_errors_returns_error_dict():
    @catch_errors()
    async def boom():
        raise ValueError("boom")

    result = await boom()
    assert result["success"] is False
    assert result["error"] == "boom"
    assert result["type"] == "ValueError"


@pytest.mark.asyncio
async def test_catch_errors_tuple_mode():
    @catch_errors(tuple_on_error=True)
    async def boom():
        raise RuntimeError("nope")

    result, context = await boom()
    assert result["success"] is False
    assert result["error"] == "nope"
    assert result["type"] == "RuntimeError"
    assert context == []
