"""Client for DNSFilter's public REST API (https://api.dnsfilter.com).

Auth is a single static API key sent as the raw value of the Authorization
header — no Bearer/Basic prefix (dnsfilter-openapi@2026-10-27's
`header_authorization` security scheme: "Authentication is required for
most, but not all, endpoints, and is done by setting the Authorization
request header, with the header value being the API key itself" — the
docs' own curl example confirms no scheme prefix). There is no token
exchange to run: the key *is* the credential on every call, so unlike
vendors with an OAuth client_credentials grant (cisco-umbrella-mcp) or a
multi-step bearer-token exchange (sonicwall-mcp), this client has nothing
to re-authenticate — it attaches the header and calls DNSFilter directly.
"""

import asyncio
from typing import Any

import httpx

from .errors import DNSFilterError

BASE_URL = "https://api.dnsfilter.com"

_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_MAX_RETRIES = 3
_MAX_BACKOFF_SECONDS = 20.0

# One shared connection pool for the process lifetime. No credentials are
# ever stored on it — the API key is passed per-call as a request header,
# so sharing the pool across tenants/requests is safe (see auth.py's
# contextvar-based credential isolation, which is what actually keeps
# tenants apart).
_http_client: httpx.AsyncClient | None = None


def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True)
    return _http_client


def _retry_delay(resp: httpx.Response, attempt: int) -> float:
    retry_after = resp.headers.get("Retry-After")
    if retry_after:
        try:
            return min(float(retry_after), _MAX_BACKOFF_SECONDS)
        except ValueError:
            pass
    return min(2**attempt, _MAX_BACKOFF_SECONDS)


def _extract_error(resp: httpx.Response) -> str:
    try:
        detail = resp.json()
        if isinstance(detail, dict):
            return str(detail.get("error") or detail)
        return str(detail)
    except ValueError:
        return resp.text


class DNSFilterClient:
    def __init__(self, api_key: str):
        self._api_key = api_key

    def _clean_params(self, params: dict[str, Any] | None) -> dict[str, Any]:
        if not params:
            return {}
        return {k: v for k, v in params.items() if v is not None}

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        """Issue one authenticated GET against the DNSFilter API, with
        limited retry + exponential backoff on 429/5xx (honoring
        Retry-After when DNSFilter sends one) and on network-level errors.
        """
        client = _get_http_client()
        url = f"{BASE_URL}{path}"
        headers = {"Authorization": self._api_key, "Accept": "application/json"}
        clean_params = self._clean_params(params)

        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                resp = await client.get(url, headers=headers, params=clean_params)
            except httpx.RequestError as e:
                last_exc = e
                if attempt < _MAX_RETRIES:
                    await asyncio.sleep(min(2**attempt, _MAX_BACKOFF_SECONDS))
                    continue
                raise DNSFilterError(0, f"{e or type(e).__name__} (url={url})") from e

            if resp.status_code in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
                await asyncio.sleep(_retry_delay(resp, attempt))
                continue

            if resp.status_code >= 400:
                raise DNSFilterError(resp.status_code, _extract_error(resp))
            if resp.status_code == 204 or not resp.content:
                return None
            try:
                return resp.json()
            except ValueError:
                return {"raw_response": resp.text}

        # Unreachable in practice (loop always returns or raises above), but
        # keeps type checkers happy and guards against future edits.
        if last_exc:
            raise DNSFilterError(0, f"{last_exc}") from last_exc
        raise DNSFilterError(0, "request failed with no response")
