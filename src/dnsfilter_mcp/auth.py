"""Gateway credential middleware: reads X-Dnsfilter-Api-Key per request and
stores it in a contextvar for the lifetime of that one request only.

Per-request isolation via contextvars (not a global/module-level variable)
is what keeps two concurrent tool calls carrying two different tenants'
API keys from ever crossing (AC13) — Python's asyncio copies context per
task, so concurrent requests on the same event loop never see each
other's value, and the `finally: reset()` below guarantees no leakage to
whatever request handles next even when the two races onto the same task.
"""

import contextvars
from typing import NamedTuple

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

_API_KEY_HEADER = "x-dnsfilter-api-key"


class _GatewayCreds(NamedTuple):
    api_key: str


_gateway_creds_var: contextvars.ContextVar[_GatewayCreds | None] = contextvars.ContextVar(
    "dnsfilter_gateway_creds", default=None
)


def get_api_key_from_context() -> str | None:
    """Resolve the active DNSFilter API key for the current request context."""
    creds = _gateway_creds_var.get()
    return creds.api_key if creds else None


class GatewayTokenMiddleware:
    """ASGI middleware.

    Reads X-Dnsfilter-Api-Key (the only credential DNSFilter needs — a
    single static API key, no OAuth) from request headers and stores it in
    the contextvar. Returns 401 if the header is missing on /mcp requests,
    covering AC9 without ever calling DNSFilter.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if not path.startswith("/mcp"):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        api_key = request.headers.get(_API_KEY_HEADER)
        if not api_key:
            response = JSONResponse(
                {
                    "error": "Missing credentials",
                    "message": (
                        "This server requires the X-Dnsfilter-Api-Key header "
                        "(the DNSFilter account's API key)."
                    ),
                    "required_headers": ["X-Dnsfilter-Api-Key"],
                },
                status_code=401,
            )
            await response(scope, receive, send)
            return

        ctx_token = _gateway_creds_var.set(_GatewayCreds(api_key))
        try:
            await self.app(scope, receive, send)
        finally:
            _gateway_creds_var.reset(ctx_token)
