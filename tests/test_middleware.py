"""Gateway credential middleware tests: missing-header 401 (TC-DNSF-009),
and request-level contextvar isolation under concurrency (TC-DNSF-013).
"""

import asyncio

from starlette.testclient import TestClient

from dnsfilter_mcp.__main__ import _build_http_app
from dnsfilter_mcp.auth import GatewayTokenMiddleware, _gateway_creds_var, get_api_key_from_context
from dnsfilter_mcp.server import create_mcp_server
from dnsfilter_mcp.settings import Settings


def _make_app():
    settings = Settings()
    mcp = create_mcp_server(settings)
    return _build_http_app(mcp, settings), settings


def test_health_is_local_and_does_not_require_credentials():
    app, _ = _make_app()
    with TestClient(app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


def test_missing_header_returns_401_with_required_headers_listed():
    """TC-DNSF-009 (AC9)."""
    app, _ = _make_app()
    with TestClient(app) as client:
        resp = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            headers={"Accept": "application/json, text/event-stream"},
        )
        assert resp.status_code == 401
        body = resp.json()
        assert body["required_headers"] == ["X-Dnsfilter-Api-Key"]


def test_header_present_reaches_request_context_and_resets_after():
    import asyncio as _asyncio

    seen = {}

    async def fake_app(scope, receive, send):
        seen["key"] = get_api_key_from_context()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = GatewayTokenMiddleware(fake_app)

    async def run():
        scope = {
            "type": "http",
            "path": "/mcp",
            "headers": [(b"x-dnsfilter-api-key", b"test-key-123")],
        }

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            pass

        await middleware(scope, receive, send)

    _asyncio.run(run())
    assert seen["key"] == "test-key-123"
    # After the request completes, the contextvar must be reset — a fresh
    # get() outside any request context sees no leftover credential.
    assert _gateway_creds_var.get() is None


def test_client_factory_returns_none_without_context():
    from dnsfilter_mcp.server import get_client_from_context

    assert get_client_from_context() is None


def test_concurrent_requests_never_cross_credentials():
    """TC-DNSF-013 (AC13): two concurrent requests carrying two different
    X-Dnsfilter-Api-Key values must never see each other's key — this is
    the request-level isolation test for a connector with no platform
    tenant field of its own (contextvars, not a global/module variable).
    """
    seen: dict[str, str | None] = {}

    async def fake_app(scope, receive, send):
        # Yield control so the other concurrent call's middleware has a
        # chance to run first — if isolation were broken (e.g. a shared
        # module-level variable instead of a contextvar), this is exactly
        # where the two calls would stomp on each other.
        await asyncio.sleep(0)
        label = scope["_label"]
        seen[label] = get_api_key_from_context()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    middleware = GatewayTokenMiddleware(fake_app)

    async def call(label: str, key: str):
        scope = {
            "type": "http",
            "path": "/mcp",
            "_label": label,
            "headers": [(b"x-dnsfilter-api-key", key.encode())],
        }

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            pass

        await middleware(scope, receive, send)

    async def run():
        await asyncio.gather(
            call("tenant-a", "key-for-tenant-a"),
            call("tenant-b", "key-for-tenant-b"),
        )

    asyncio.run(run())
    assert seen["tenant-a"] == "key-for-tenant-a"
    assert seen["tenant-b"] == "key-for-tenant-b"
