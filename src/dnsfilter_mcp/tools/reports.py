"""Traffic/threat reporting — read only.

Endpoint shapes cited from dnsfilter-openapi@2026-10-27
(https://api.dnsfilter.com/docs/api.json):
- GET /v1/traffic_reports/total_requests, GET /v1/traffic_reports/total_threats
  (wrapped behind dnsfilter_get_traffic_summary's `metric` enum)
- GET /v1/traffic_reports/top_categories, top_domains, top_networks,
  top_organizations_requests (wrapped behind dnsfilter_get_top_report's
  `dimension` enum)

The vendor's own filters are plural and comma-separated
(organization_ids, network_ids) except top_organizations_requests, which
takes a single organization_id and has no network_id or security_report
filter at all (it has no per-network breakdown to filter — see
_TOP_REPORT.organizations below). This connector's tool contract stays
singular (organization_id / network_id) for a simpler agent-facing shape;
client.py / this module do the join.
"""

from collections.abc import Callable
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .._json import dump_json_capped
from ..client import DNSFilterClient
from ..errors import DNSFilterError
from ..pagination import page_params
from ._common import NO_TOKEN

_DEFAULT_TOP_LIMIT = 10
_MAX_TOP_LIMIT = 50
_LIMIT_DESC = f"Top-N size (default {_DEFAULT_TOP_LIMIT}, hard cap {_MAX_TOP_LIMIT})."

_METRIC_PATHS = {
    "requests": "/v1/traffic_reports/total_requests",
    "threats": "/v1/traffic_reports/total_threats",
}


class _TopReportDimension:
    def __init__(
        self,
        path: str,
        key: str,
        label: str,
        count: str,
        *,
        supports_network_ids: bool = True,
        supports_organization_ids: bool = True,
        supports_security_report: bool = True,
    ):
        self.path = path
        self.key_field = key
        self.label_field = label
        self.count_field = count
        self.supports_network_ids = supports_network_ids
        self.supports_organization_ids = supports_organization_ids
        self.supports_security_report = supports_security_report


_TOP_REPORT: dict[str, _TopReportDimension] = {
    "categories": _TopReportDimension(
        "/v1/traffic_reports/top_categories", "category_id", "category_name", "total"
    ),
    "domains": _TopReportDimension("/v1/traffic_reports/top_domains", "domain", "domain", "total"),
    "networks": _TopReportDimension(
        "/v1/traffic_reports/top_networks", "network_id", "network_name", "total"
    ),
    # top_organizations_requests has no network_ids or security_report filter
    # (confirmed absent from its parameter list), and takes a single
    # organization_id rather than the plural organization_ids every other
    # traffic_reports/* operation uses.
    "organizations": _TopReportDimension(
        "/v1/traffic_reports/top_organizations_requests",
        "organization_id",
        "organization_name",
        "total_requests",
        supports_network_ids=False,
        supports_organization_ids=False,
        supports_security_report=False,
    ),
}


def register(mcp: FastMCP, client_factory: Callable[[], DNSFilterClient | None]) -> None:
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def dnsfilter_get_traffic_summary(
        metric: Annotated[
            Literal["requests", "threats"], Field(description="Which aggregate to report.")
        ],
        from_: Annotated[
            str, Field(description="Start of the time range (ISO 8601, e.g. 2026-10-01T00:00:00Z).")
        ],
        to: Annotated[str, Field(description="End of the time range (ISO 8601).")],
        organization_id: Annotated[
            int | None, Field(description="Optional. Scope to one organization.")
        ] = None,
        network_id: Annotated[
            int | None, Field(description="Optional. Scope to one network.")
        ] = None,
        bucket_size: Annotated[
            str | None,
            Field(description='Optional. "auto" (default), "15min", or "1day".'),
        ] = None,
        type: Annotated[  # noqa: A002 - matches DNSFilter's own filter param name
            Literal["all", "allowed", "blocked"],
            Field(description="Which subset of traffic to count."),
        ] = "all",
    ) -> str:
        """Get an aggregate request or threat count over a time window, bucketed by time.

        metric="requests" for overall DNS request volume, metric="threats"
        for threat/blocked-category volume. Pair with
        dnsfilter_get_top_report for a breakdown by category/domain/
        network/organization instead of a time series.
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        params: dict[str, Any] = {
            "from": from_,
            "to": to,
            "organization_ids": str(organization_id) if organization_id is not None else None,
            "network_ids": str(network_id) if network_id is not None else None,
            "bucket_size": bucket_size,
            "type": type,
        }
        try:
            result = await client.get(_METRIC_PATHS[metric], params=params)
            data = (result or {}).get("data") or {}
            values = data.get("values") or []
            buckets = [
                {"timestamp": v.get("bucket"), "count": v.get("total")} for v in values
            ]
            total = sum(v.get("total") or 0 for v in values)
            return dump_json_capped(
                {"metric": metric, "from": from_, "to": to, "buckets": buckets, "total": total}
            )
        except DNSFilterError as e:
            return e.to_envelope()

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
    async def dnsfilter_get_top_report(
        dimension: Annotated[
            Literal["categories", "domains", "networks", "organizations"],
            Field(description="Which breakdown to rank."),
        ],
        from_: Annotated[str, Field(description="Start of the time range (ISO 8601).")],
        to: Annotated[str, Field(description="End of the time range (ISO 8601).")],
        organization_id: Annotated[
            int | None, Field(description="Optional. Scope to one organization.")
        ] = None,
        network_id: Annotated[
            int | None,
            Field(
                description=(
                    "Optional. Scope to one network. Not supported for "
                    "dimension=organizations."
                )
            ),
        ] = None,
        security_report: Annotated[
            bool,
            Field(
                description=(
                    "Scope to threat/security-flagged activity (default True, matching "
                    "the 'threat reporting' use case). Set False for all traffic. "
                    "Ignored for dimension=organizations, which has no such filter."
                )
            ),
        ] = True,
        limit: Annotated[int, Field(description=_LIMIT_DESC, ge=1)] = _DEFAULT_TOP_LIMIT,
    ) -> str:
        """Get the top-N entries for a traffic/threat dimension over a time window.

        dimension="categories"/"domains"/"networks" rank by blocked/threat
        activity by default (security_report=True); dimension="organizations"
        ranks by total request volume and ignores security_report/network_id
        (DNSFilter's own endpoint for it has no such filters).
        """
        client = client_factory()
        if client is None:
            return NO_TOKEN
        spec = _TOP_REPORT[dimension]
        limit = min(limit, _MAX_TOP_LIMIT)
        params: dict[str, Any] = {"from": from_, "to": to, **page_params(1, limit)}
        if spec.supports_organization_ids:
            params["organization_ids"] = (
                str(organization_id) if organization_id is not None else None
            )
        elif organization_id is not None:
            params["organization_id"] = organization_id
        if spec.supports_network_ids and network_id is not None:
            params["network_ids"] = str(network_id)
        if spec.supports_security_report:
            params["security_report"] = security_report
        try:
            result = await client.get(spec.path, params=params)
            data = (result or {}).get("data") or {}
            values = data.get("values") or []
            items = [
                {
                    "key": _stringify(v.get(spec.key_field)),
                    "label": v.get(spec.label_field),
                    "count": v.get(spec.count_field),
                }
                for v in values
            ]
            return dump_json_capped(
                {"dimension": dimension, "from": from_, "to": to, "items": items}
            )
        except DNSFilterError as e:
            return e.to_envelope()


def _stringify(value: Any) -> Any:
    return str(value) if value is not None else value
