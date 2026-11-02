"""Network discovery — read only.

Endpoint shapes cited from dnsfilter-openapi@2026-10-27
(https://api.dnsfilter.com/docs/api.json): GET /v1/networks and
GET /v1/networks/{id}.

GET /v1/networks takes no organization_id query parameter (confirmed
absent from the spec's parameter list for that operation) — organization
scoping is done client-side here by filtering on each item's
relationships.organization.data.id after fetching DNSFilter's own page.
This means when organization_id is given, has_more still reflects whether
DNSFilter's own (unfiltered) page was full, not whether the
organization-filtered result was full — see README Known Gaps.

Every network response here strips the vendor's own `secret_key`
attribute (see tools/_common.py's NO_TOKEN sibling constant and the
module docstring in server.py): DNSFilter's own OpenAPI spec documents it
as "Network secret key for user agents and LAN proxies" — a live
credential used by that network's user-agents/LAN proxies to authenticate
to DNSFilter. Returning it to an agent/LLM context would hand out a
working DNSFilter credential as "just data"; this is a straightforward
data-exposure bug to avoid, not a design trade-off.
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
from ._common import NO_TOKEN, relationship_id, resolve_id

_DEFAULT_LIMIT = 25
_MAX_LIMIT = 100
_LIMIT_DESC = f"Max results per page (default {_DEFAULT_LIMIT}, hard cap {_MAX_LIMIT})."


def _network_item(spec: dict) -> dict:
    attrs = spec.get("attributes") or {}
    # secret_key is deliberately never read out of attrs into this dict —
    # see module docstring.
    return {
        "id": resolve_id(spec.get("id")),
        "name": attrs.get("name"),
        "organization_id": relationship_id(spec, "organization"),
        "policy_id": relationship_id(spec, "policy"),
        "protected": relationship_id(spec, "policy") is not None,
    }


def register(mcp: FastMCP, client_factory: Callable[[], DNSFilterClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def dnsfilter_list_networks(
        organization_id: Annotated[
            int | None,
            Field(description="Optional. Only return networks belonging to this organization."),
        ] = None,
        search: Annotated[
            str | None,
            Field(description="Optional. Search network name, hostname, IP address, etc."),
        ] = None,
        protected: Annotated[
            bool | None,
            Field(
                description=(
                    "Optional. True for networks with a policy assigned, "
                    "False for networks without one."
                )
            ),
        ] = None,
        limit: Annotated[int, Field(description=_LIMIT_DESC, ge=1)] = _DEFAULT_LIMIT,
        page: Annotated[int, Field(description="Page number (default 1).", ge=1)] = 1,
    ) -> str:
        """List networks, each with its organization_id/policy_id and whether a policy is assigned.

        organization_id is applied client-side after DNSFilter's own
        pagination (the vendor API has no such filter on this endpoint) —
        see README Known Gaps for what that means for has_more. Never
        includes the live network secret_key.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        limit = min(limit, _MAX_LIMIT)
        params = {"search": search, **page_params(page, limit)}
        if protected is True:
            params["protected"] = True
        elif protected is False:
            params["unprotected"] = True
        try:
            result = await client.get("/v1/networks", params=params)
            data = (result or {}).get("data") or []
            page_was_full = has_more(data, limit)
            items = [_network_item(spec) for spec in data]
            if organization_id is not None:
                items = [item for item in items if item["organization_id"] == organization_id]
            return dump_json_capped({"items": items, "has_more": page_was_full})
        except DNSFilterError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def dnsfilter_get_network(
        network_id: Annotated[int, Field(description="The network's id.")],
    ) -> str:
        """Get one network's details: organization_id, policy_id, protected, and local_domains.

        Never includes the live network secret_key.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        try:
            result = await client.get(f"/v1/networks/{network_id}")
            spec = (result or {}).get("data") or {}
            attrs = spec.get("attributes") or {}
            item = {
                "id": resolve_id(spec.get("id")),
                "name": attrs.get("name"),
                "organization_id": relationship_id(spec, "organization"),
                "policy_id": relationship_id(spec, "policy"),
                "protected": relationship_id(spec, "policy") is not None,
                "local_domains": attrs.get("local_domains") or [],
            }
            return dump_json_capped(item)
        except DNSFilterError as e:
            return e.to_envelope()
