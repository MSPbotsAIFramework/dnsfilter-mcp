"""Content category taxonomy — read only.

Endpoint shape cited from dnsfilter-openapi@2026-10-27
(https://api.dnsfilter.com/docs/api.json): GET /v1/categories.
"""

from collections.abc import Callable
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped
from ..client import DNSFilterClient
from ..errors import DNSFilterError
from ..pagination import has_more, page_params
from ._common import NO_TOKEN, resolve_id

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 100
_LIMIT_DESC = f"Max results per page (default {_DEFAULT_LIMIT}, hard cap {_MAX_LIMIT})."


def register(mcp: FastMCP, client_factory: Callable[[], DNSFilterClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def dnsfilter_list_categories(
        limit: Annotated[int, Field(description=_LIMIT_DESC, ge=1)] = _DEFAULT_LIMIT,
        page: Annotated[int, Field(description="Page number (default 1).", ge=1)] = 1,
    ) -> str:
        """List the DNSFilter content category taxonomy.

        Use to resolve category ids returned by dnsfilter_get_policy
        (blacklist_categories) or dnsfilter_get_top_report
        (dimension=categories) to human-readable names, and to see which
        categories are security-flagged (threat categories, as opposed to
        general content categories).
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        limit = min(limit, _MAX_LIMIT)
        params = page_params(page, limit)
        try:
            result = await client.get("/v1/categories", params=params)
            data = (result or {}).get("data") or []
            items = [
                {
                    "id": resolve_id(spec.get("id")),
                    "name": (spec.get("attributes") or {}).get("name"),
                    "description": (spec.get("attributes") or {}).get("description"),
                    "security": (spec.get("attributes") or {}).get("security"),
                }
                for spec in data
            ]
            return dump_json_capped({"items": items, "has_more": has_more(data, limit)})
        except DNSFilterError as e:
            return e.to_envelope()
