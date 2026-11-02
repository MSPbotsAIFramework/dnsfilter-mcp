"""Organization discovery — read only.

Endpoint shapes cited from dnsfilter-openapi@2026-10-27
(https://api.dnsfilter.com/docs/api.json): GET /v1/organizations and
GET /v1/organizations/{id}.
"""

from collections.abc import Callable
from typing import Annotated, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped
from ..client import DNSFilterClient
from ..errors import DNSFilterError
from ..pagination import has_more, page_params
from ._common import NO_TOKEN, resolve_id

_DEFAULT_LIMIT = 25
_MAX_LIMIT = 100
_LIMIT_DESC = f"Max results per page (default {_DEFAULT_LIMIT}, hard cap {_MAX_LIMIT})."


def _organization_item(spec: dict) -> dict:
    attrs = spec.get("attributes") or {}
    return {
        "id": resolve_id(spec.get("id")),
        "name": attrs.get("name"),
        # DNSFilter's Organization attributes have no documented "type"
        # field matching the normal/msp/sub_organization filter enum — the
        # best candidate in the spec is the undocumented string field
        # "role" (dnsfilter-openapi@2026-10-27's Organization schema:
        # {"role": {"type": "string", "description": "Role"}}). Surfaced
        # as-is, not independently confirmed against a live account — see
        # README Known Gaps.
        "type": attrs.get("role"),
    }


def register(mcp: FastMCP, client_factory: Callable[[], DNSFilterClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def dnsfilter_list_organizations(
        name: Annotated[
            str | None, Field(description="Optional substring filter on organization name.")
        ] = None,
        type: Annotated[  # noqa: A002 - matches DNSFilter's own filter param name
            Literal["normal", "msp", "sub_organization"] | None,
            Field(description="Optional. Filter by organization type."),
        ] = None,
        limit: Annotated[int, Field(description=_LIMIT_DESC, ge=1)] = _DEFAULT_LIMIT,
        page: Annotated[int, Field(description="Page number (default 1).", ge=1)] = 1,
    ) -> str:
        """List the organizations visible to this API key.

        Each item's "type" field is best-effort (see README Known Gaps) —
        treat it as informational, not authoritative, if it comes back
        null for an account where it's expected to be set.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        limit = min(limit, _MAX_LIMIT)
        params = {"name": name, "type": type, **page_params(page, limit)}
        try:
            result = await client.get("/v1/organizations", params=params)
            data = (result or {}).get("data") or []
            items = [_organization_item(spec) for spec in data]
            return dump_json_capped({"items": items, "has_more": has_more(data, limit)})
        except DNSFilterError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def dnsfilter_get_organization(
        organization_id: Annotated[int, Field(description="The organization's id.")],
    ) -> str:
        """Get one organization's basic information (name, address, feature flags)."""
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(f"/v1/organizations/{organization_id}")
            spec = (result or {}).get("data") or {}
            attrs = spec.get("attributes") or {}
            item = {
                "id": resolve_id(spec.get("id")),
                "name": attrs.get("name"),
                "address": attrs.get("address"),
                "feature_flags": attrs.get("feature_flags") or [],
                "canceled": attrs.get("canceled"),
            }
            return dump_json_capped(item)
        except DNSFilterError as e:
            return e.to_envelope()
