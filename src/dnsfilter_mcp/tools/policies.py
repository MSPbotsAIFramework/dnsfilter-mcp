"""Policy configuration — read only.

Endpoint shapes cited from dnsfilter-openapi@2026-10-27
(https://api.dnsfilter.com/docs/api.json): GET /v1/policies (native
organization_id + include_global_policies filters) and GET
/v1/policies/{id}.
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

_DEFAULT_LIMIT = 25
_MAX_LIMIT = 100
_LIMIT_DESC = f"Max results per page (default {_DEFAULT_LIMIT}, hard cap {_MAX_LIMIT})."


def _policy_item(spec: dict) -> dict:
    attrs = spec.get("attributes") or {}
    return {
        "id": resolve_id(spec.get("id")),
        "name": attrs.get("name"),
        "organization_id": attrs.get("organization_id"),
        "is_global_policy": attrs.get("is_global_policy"),
    }


def register(mcp: FastMCP, client_factory: Callable[[], DNSFilterClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def dnsfilter_list_policies(
        organization_id: Annotated[
            int | None,
            Field(description="Optional. Only return policies belonging to this organization."),
        ] = None,
        include_global_policies: Annotated[
            bool,
            Field(
                description=(
                    "Include global (account-wide) policies alongside "
                    "organization-specific ones."
                )
            ),
        ] = True,
        limit: Annotated[int, Field(description=_LIMIT_DESC, ge=1)] = _DEFAULT_LIMIT,
        page: Annotated[int, Field(description="Page number (default 1).", ge=1)] = 1,
    ) -> str:
        """List policies, optionally scoped to one organization."""
        client = client_factory()
        if client is None:
            return NO_TOKEN
        limit = min(limit, _MAX_LIMIT)
        params = {
            "organization_id": organization_id,
            "include_global_policies": include_global_policies,
            **page_params(page, limit),
        }
        try:
            result = await client.get("/v1/policies", params=params)
            data = (result or {}).get("data") or []
            items = [_policy_item(spec) for spec in data]
            return dump_json_capped({"items": items, "has_more": has_more(data, limit)})
        except DNSFilterError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def dnsfilter_get_policy(
        policy_id: Annotated[int, Field(description="The policy's id.")],
    ) -> str:
        """Get one policy's full configuration.

        Allow/block domain lists, blocked category ids, per-engine
        safe-search flags, YouTube restriction, allow-list-only, and which
        networks it applies to.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(f"/v1/policies/{policy_id}")
            spec = (result or {}).get("data") or {}
            attrs = spec.get("attributes") or {}
            networks_rel = (
                (spec.get("relationships") or {}).get("networks") or {}
            ).get("data") or []
            network_ids = [resolve_id(n.get("id")) for n in networks_rel]
            item = {
                "id": resolve_id(spec.get("id")),
                "name": attrs.get("name"),
                "organization_id": attrs.get("organization_id"),
                "whitelist_domains": attrs.get("whitelist_domains") or [],
                "blacklist_domains": attrs.get("blacklist_domains") or [],
                "blacklist_categories": attrs.get("blacklist_categories") or [],
                "allow_list_only": attrs.get("allow_list_only"),
                "allow_unknown_domains": attrs.get("allow_unknown_domains"),
                "google_safesearch": attrs.get("google_safesearch"),
                "bing_safe_search": attrs.get("bing_safe_search"),
                "duck_duck_go_safe_search": attrs.get("duck_duck_go_safe_search"),
                "ecosia_safesearch": attrs.get("ecosia_safesearch"),
                "yandex_safe_search": attrs.get("yandex_safe_search"),
                "youtube_restricted": attrs.get("youtube_restricted"),
                "youtube_restricted_level": attrs.get("youtube_restricted_level"),
                "network_ids": network_ids,
            }
            return dump_json_capped(item)
        except DNSFilterError as e:
            return e.to_envelope()
