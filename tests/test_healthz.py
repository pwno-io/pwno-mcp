import httpx
import pytest

from pwnomcp.asgi import app


def test_healthz_route_registered():
    paths = {getattr(route, "path", None) for route in app.routes}
    assert "/healthz" in paths


@pytest.mark.asyncio
async def test_healthz_returns_ok():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
