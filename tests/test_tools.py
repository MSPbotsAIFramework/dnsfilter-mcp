"""tools/list snapshot, error-envelope mapping, and per-tool success/error
coverage against a respx-mocked DNSFilter API — no real account needed for
any of this.

Maps to docs/tickets/PRD-21229.ac.json:
TC-DNSF-001..013 (all type=auto). TC-DNSF-014 is manual and needs a real
DNSFilter account — see docs/tickets/PRD-21229.md Test strategy.
"""

import json

import httpx
import pytest
import respx
from mcp.server.fastmcp import FastMCP

from dnsfilter_mcp.client import DNSFilterClient
from dnsfilter_mcp.errors import DNSFilterError
from dnsfilter_mcp.server import create_mcp_server
from dnsfilter_mcp.settings import Settings

BASE = "https://api.dnsfilter.com"
_FROM = "2026-10-01T00:00:00Z"
_TO = "2026-10-02T00:00:00Z"

# name -> (required params, expected annotation hint set to True)
EXPECTED_TOOLS = {
    "dnsfilter_list_organizations": (set(), {"readOnlyHint"}),
    "dnsfilter_get_organization": ({"organization_id"}, {"readOnlyHint"}),
    "dnsfilter_list_networks": (set(), {"readOnlyHint"}),
    "dnsfilter_get_network": ({"network_id"}, {"readOnlyHint"}),
    "dnsfilter_list_policies": (set(), {"readOnlyHint"}),
    "dnsfilter_get_policy": ({"policy_id"}, {"readOnlyHint"}),
    "dnsfilter_list_categories": (set(), {"readOnlyHint"}),
    "dnsfilter_get_traffic_summary": ({"metric", "from_", "to"}, {"readOnlyHint"}),
    "dnsfilter_get_top_report": ({"dimension", "from_", "to"}, {"readOnlyHint"}),
}


@pytest.mark.asyncio
async def test_tools_list_snapshot():
    mcp = create_mcp_server(Settings())
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    assert names == set(EXPECTED_TOOLS), f"unexpected tool set: {names}"
    assert len(names) <= 20  # SOP SS2.1 tool-budget guidance

    by_name = {t.name: t for t in tools}
    for name, (expected_required, expected_hints) in EXPECTED_TOOLS.items():
        tool = by_name[name]
        required = set(tool.inputSchema.get("required", []))
        assert required == expected_required, f"{name}: required={required}"

        description = tool.description or ""
        assert len(description) <= 500, f"{name}: description too long ({len(description)})"
        first_line = description.strip().splitlines()[0] if description.strip() else ""
        assert len(first_line) <= 100, f"{name}: first line too long: {first_line!r}"
        assert "GET /" not in description and "POST /" not in description, (
            f"{name}: leaked implementation detail"
        )

        annotations = tool.annotations
        actual_hints = set()
        if annotations is not None:
            for hint in ("readOnlyHint", "destructiveHint", "idempotentHint"):
                if getattr(annotations, hint, None) is True:
                    actual_hints.add(hint)
        assert actual_hints == expected_hints, f"{name}: hints={actual_hints}"


@pytest.mark.asyncio
async def test_service_instructions_present_and_bounded():
    mcp = create_mcp_server(Settings())
    assert mcp.instructions
    assert len(mcp.instructions) <= 1500


@pytest.mark.parametrize(
    "status_code,expected_code,expected_retryable",
    [
        (0, "upstream_error", True),
        (400, "invalid_argument", False),
        (401, "unauthorized", False),
        (403, "unauthorized", False),
        (404, "not_found", False),
        (422, "invalid_argument", False),
        (429, "rate_limited", True),
        (500, "upstream_error", True),
        (503, "upstream_error", True),
    ],
)
def test_error_envelope_mapping(status_code, expected_code, expected_retryable):
    """TC-DNSF-010 (429), TC-DNSF-011 (404) — the fixed code/retryable mapping."""
    err = DNSFilterError(status_code, "boom")
    envelope = json.loads(err.to_envelope())
    assert envelope["error"]["code"] == expected_code
    assert envelope["error"]["retryable"] is expected_retryable
    assert envelope["error"]["message"] == "boom"


@pytest.mark.asyncio
async def test_no_credentials_returns_not_configured_without_calling_api():
    """TC-DNSF-009 (AC9): missing header -> unauthorized/not_configured envelope,
    zero outbound calls to DNSFilter (respx has no mocked routes at all here,
    so any outbound call would raise respx.RouteNotFoundError before we even
    get to asserting the envelope).
    """
    from dnsfilter_mcp.tools import organizations

    mcp = FastMCP(name="test")
    organizations.register(mcp, lambda: None)
    with respx.mock(assert_all_called=False) as router:
        router.route(host="api.dnsfilter.com").mock(
            side_effect=AssertionError("must not call DNSFilter without credentials")
        )
        result = await mcp.call_tool("dnsfilter_list_organizations", {})
    text = result[0][0].text if isinstance(result, tuple) else str(result)
    assert "not_configured" in text


# ---------------------------------------------------------------------------
# Per-tool success paths (respx-mocked DNSFilter responses)
# ---------------------------------------------------------------------------


def _org_spec(id_, name, role="normal"):
    return {
        "id": str(id_),
        "type": "organizations",
        "attributes": {"name": name, "role": role},
    }


def _network_spec(id_, name, org_id, policy_id, secret_key="s3cr3t"):
    return {
        "id": str(id_),
        "type": "networks",
        "attributes": {"name": name, "secret_key": secret_key, "local_domains": ["corp.local"]},
        "relationships": {
            "organization": {"data": {"id": str(org_id), "type": "organizations"}},
            "policy": (
                {"data": {"id": str(policy_id), "type": "policies"}}
                if policy_id is not None
                else {"data": None}
            ),
        },
    }


def _policy_spec(id_, name, org_id, network_ids=None):
    return {
        "id": str(id_),
        "type": "policies",
        "attributes": {
            "name": name,
            "organization_id": org_id,
            "whitelist_domains": ["allowed.example.com"],
            "blacklist_domains": ["blocked.example.com"],
            "blacklist_categories": [142],
            "allow_list_only": False,
            "allow_unknown_domains": True,
            "google_safesearch": True,
            "bing_safe_search": False,
            "duck_duck_go_safe_search": False,
            "ecosia_safesearch": False,
            "yandex_safe_search": False,
            "youtube_restricted": True,
            "youtube_restricted_level": "strict",
        },
        "relationships": {
            "organization": {"data": {"id": str(org_id), "type": "organizations"}},
            "networks": {
                "data": [{"id": str(n), "type": "networks"} for n in (network_ids or [])]
            },
        },
    }


@pytest.mark.asyncio
@respx.mock
async def test_list_organizations_returns_visible_orgs_paginated():
    """TC-DNSF-001 (AC1)."""
    route = respx.get(f"{BASE}/v1/organizations").mock(
        return_value=httpx.Response(
            200,
            json={"data": [_org_spec(1, "Acme MSP", role="msp"), _org_spec(2, "Acme Customer")]},
        )
    )
    client = DNSFilterClient("test-key")
    from dnsfilter_mcp.tools import organizations

    mcp = FastMCP(name="test")
    organizations.register(mcp, lambda: client)
    result = await mcp.call_tool("dnsfilter_list_organizations", {})
    body = json.loads(_text(result))
    assert route.called
    sent_headers = route.calls[0].request.headers
    assert sent_headers["authorization"] == "test-key"
    assert body["items"] == [
        {"id": 1, "name": "Acme MSP", "type": "msp"},
        {"id": 2, "name": "Acme Customer", "type": "normal"},
    ]
    assert body["has_more"] is False


@pytest.mark.asyncio
@respx.mock
async def test_list_organizations_sends_bracketed_page_params():
    """Confirms page[number]/page[size] are sent as the two bracketed keys
    DNSFilter's spec documents (page is an object, not a flat query key).
    """
    route = respx.get(f"{BASE}/v1/organizations").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    client = DNSFilterClient("test-key")
    from dnsfilter_mcp.tools import organizations

    mcp = FastMCP(name="test")
    organizations.register(mcp, lambda: client)
    await mcp.call_tool("dnsfilter_list_organizations", {"limit": 10, "page": 2})
    sent = route.calls[0].request.url.params
    assert sent["page[number]"] == "2"
    assert sent["page[size]"] == "10"


@pytest.mark.asyncio
@respx.mock
async def test_get_organization_returns_basic_info():
    """TC-DNSF-002 (AC2)."""
    respx.get(f"{BASE}/v1/organizations/2").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "id": "2",
                    "type": "organizations",
                    "attributes": {
                        "name": "Acme Customer",
                        "address": "1 Main St",
                        "feature_flags": ["clientless"],
                        "canceled": False,
                    },
                }
            },
        )
    )
    client = DNSFilterClient("test-key")
    from dnsfilter_mcp.tools import organizations

    mcp = FastMCP(name="test")
    organizations.register(mcp, lambda: client)
    result = await mcp.call_tool("dnsfilter_get_organization", {"organization_id": 2})
    body = json.loads(_text(result))
    assert body == {
        "id": 2,
        "name": "Acme Customer",
        "address": "1 Main St",
        "feature_flags": ["clientless"],
        "canceled": False,
    }


@pytest.mark.asyncio
@respx.mock
async def test_list_networks_populates_ids_and_strips_secret_key():
    """TC-DNSF-003 (AC3): organization_id/policy_id populated, secret_key never present."""
    respx.get(f"{BASE}/v1/networks").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    _network_spec(10, "HQ", org_id=2, policy_id=5),
                    _network_spec(11, "Branch", org_id=2, policy_id=None),
                ]
            },
        )
    )
    client = DNSFilterClient("test-key")
    from dnsfilter_mcp.tools import networks

    mcp = FastMCP(name="test")
    networks.register(mcp, lambda: client)
    result = await mcp.call_tool("dnsfilter_list_networks", {})
    raw = _text(result)
    assert "secret_key" not in raw
    assert "s3cr3t" not in raw
    body = json.loads(raw)
    assert body["items"] == [
        {"id": 10, "name": "HQ", "organization_id": 2, "policy_id": 5, "protected": True},
        {"id": 11, "name": "Branch", "organization_id": 2, "policy_id": None, "protected": False},
    ]


@pytest.mark.asyncio
@respx.mock
async def test_list_networks_filters_by_organization_id_client_side():
    """AC3's organization scoping — DNSFilter's own /v1/networks has no
    organization_id query filter, so this connector filters after fetch.
    """
    respx.get(f"{BASE}/v1/networks").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    _network_spec(10, "HQ", org_id=2, policy_id=5),
                    _network_spec(20, "Other Org Net", org_id=99, policy_id=None),
                ]
            },
        )
    )
    client = DNSFilterClient("test-key")
    from dnsfilter_mcp.tools import networks

    mcp = FastMCP(name="test")
    networks.register(mcp, lambda: client)
    result = await mcp.call_tool("dnsfilter_list_networks", {"organization_id": 2})
    body = json.loads(_text(result))
    assert [item["id"] for item in body["items"]] == [10]


@pytest.mark.asyncio
@respx.mock
async def test_get_network_strips_secret_key():
    respx.get(f"{BASE}/v1/networks/10").mock(
        return_value=httpx.Response(
            200, json={"data": _network_spec(10, "HQ", org_id=2, policy_id=5)}
        )
    )
    client = DNSFilterClient("test-key")
    from dnsfilter_mcp.tools import networks

    mcp = FastMCP(name="test")
    networks.register(mcp, lambda: client)
    result = await mcp.call_tool("dnsfilter_get_network", {"network_id": 10})
    raw = _text(result)
    assert "secret_key" not in raw
    body = json.loads(raw)
    assert body == {
        "id": 10,
        "name": "HQ",
        "organization_id": 2,
        "policy_id": 5,
        "protected": True,
        "local_domains": ["corp.local"],
    }


@pytest.mark.asyncio
@respx.mock
async def test_get_policy_returns_full_configuration():
    """TC-DNSF-004 (AC4)."""
    respx.get(f"{BASE}/v1/policies/5").mock(
        return_value=httpx.Response(
            200, json={"data": _policy_spec(5, "Default", org_id=2, network_ids=[10])}
        )
    )
    client = DNSFilterClient("test-key")
    from dnsfilter_mcp.tools import policies

    mcp = FastMCP(name="test")
    policies.register(mcp, lambda: client)
    result = await mcp.call_tool("dnsfilter_get_policy", {"policy_id": 5})
    body = json.loads(_text(result))
    assert body["whitelist_domains"] == ["allowed.example.com"]
    assert body["blacklist_domains"] == ["blocked.example.com"]
    assert body["blacklist_categories"] == [142]
    assert body["allow_list_only"] is False
    assert body["google_safesearch"] is True
    assert body["youtube_restricted"] is True
    assert body["youtube_restricted_level"] == "strict"
    assert body["network_ids"] == [10]


@pytest.mark.asyncio
@respx.mock
async def test_list_policies_scoped_to_organization():
    """TC-DNSF-005 (AC5)."""
    route = respx.get(f"{BASE}/v1/policies").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    _policy_spec(5, "Default", org_id=2),
                    _policy_spec(6, "Strict", org_id=2),
                ]
            },
        )
    )
    client = DNSFilterClient("test-key")
    from dnsfilter_mcp.tools import policies

    mcp = FastMCP(name="test")
    policies.register(mcp, lambda: client)
    result = await mcp.call_tool("dnsfilter_list_policies", {"organization_id": 2})
    assert route.calls[0].request.url.params["organization_id"] == "2"
    body = json.loads(_text(result))
    assert {item["id"] for item in body["items"]} == {5, 6}
    assert all(item["organization_id"] == 2 for item in body["items"])


@pytest.mark.asyncio
@respx.mock
async def test_list_categories_includes_security_flag():
    """TC-DNSF-006 (AC6)."""
    respx.get(f"{BASE}/v1/categories").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "142",
                        "type": "categories",
                        "attributes": {
                            "name": "Malware",
                            "description": "Known malware distribution",
                            "security": True,
                        },
                    },
                    {
                        "id": "7",
                        "type": "categories",
                        "attributes": {
                            "name": "News",
                            "description": "News sites",
                            "security": False,
                        },
                    },
                ]
            },
        )
    )
    client = DNSFilterClient("test-key")
    from dnsfilter_mcp.tools import categories

    mcp = FastMCP(name="test")
    categories.register(mcp, lambda: client)
    result = await mcp.call_tool("dnsfilter_list_categories", {})
    body = json.loads(_text(result))
    by_id = {item["id"]: item for item in body["items"]}
    assert by_id[142]["security"] is True
    assert by_id[7]["security"] is False


@pytest.mark.asyncio
@respx.mock
async def test_get_traffic_summary_both_metrics():
    """TC-DNSF-007 (AC7)."""
    respx.get(f"{BASE}/v1/traffic_reports/total_requests").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"values": [{"bucket": "2026-10-01T00:00:00Z", "total": 1000}]}},
        )
    )
    respx.get(f"{BASE}/v1/traffic_reports/total_threats").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"values": [{"bucket": "2026-10-01T00:00:00Z", "total": 12}]}},
        )
    )
    client = DNSFilterClient("test-key")
    from dnsfilter_mcp.tools import reports

    mcp = FastMCP(name="test")
    reports.register(mcp, lambda: client)

    req = json.loads(
        _text(
            await mcp.call_tool(
                "dnsfilter_get_traffic_summary",
                {"metric": "requests", "from_": _FROM, "to": _TO},
            )
        )
    )
    assert req["metric"] == "requests"
    assert req["buckets"] == [{"timestamp": "2026-10-01T00:00:00Z", "count": 1000}]
    assert req["total"] == 1000

    threats = json.loads(
        _text(
            await mcp.call_tool(
                "dnsfilter_get_traffic_summary",
                {"metric": "threats", "from_": _FROM, "to": _TO},
            )
        )
    )
    assert threats["metric"] == "threats"
    assert threats["total"] == 12


@pytest.mark.asyncio
@respx.mock
async def test_get_top_report_all_dimensions():
    """TC-DNSF-008 (AC8)."""
    respx.get(f"{BASE}/v1/traffic_reports/top_categories").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {"values": [{"category_id": 142, "category_name": "Malware", "total": 50}]}
            },
        )
    )
    respx.get(f"{BASE}/v1/traffic_reports/top_domains").mock(
        return_value=httpx.Response(
            200, json={"data": {"values": [{"domain": "evil.example.com", "total": 30}]}}
        )
    )
    respx.get(f"{BASE}/v1/traffic_reports/top_networks").mock(
        return_value=httpx.Response(
            200, json={"data": {"values": [{"network_id": 10, "network_name": "HQ", "total": 20}]}}
        )
    )
    org_route = respx.get(f"{BASE}/v1/traffic_reports/top_organizations_requests").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "values": [
                        {"organization_id": 2, "organization_name": "Acme", "total_requests": 100}
                    ]
                }
            },
        )
    )
    client = DNSFilterClient("test-key")
    from dnsfilter_mcp.tools import reports

    mcp = FastMCP(name="test")
    reports.register(mcp, lambda: client)

    for dimension, expected in [
        ("categories", {"key": "142", "label": "Malware", "count": 50}),
        ("domains", {"key": "evil.example.com", "label": "evil.example.com", "count": 30}),
        ("networks", {"key": "10", "label": "HQ", "count": 20}),
        ("organizations", {"key": "2", "label": "Acme", "count": 100}),
    ]:
        result = await mcp.call_tool(
            "dnsfilter_get_top_report",
            {"dimension": dimension, "from_": _FROM, "to": _TO},
        )
        body = json.loads(_text(result))
        assert body["dimension"] == dimension
        assert body["items"] == [expected]

    # organizations dimension has no security_report filter on the vendor
    # side — confirm this connector doesn't send one it doesn't support.
    assert "security_report" not in org_route.calls[0].request.url.params


@pytest.mark.asyncio
@respx.mock
async def test_get_organization_not_found():
    """TC-DNSF-011 (AC11)."""
    respx.get(f"{BASE}/v1/organizations/999").mock(
        return_value=httpx.Response(404, json={"error": "Not Found"})
    )
    client = DNSFilterClient("test-key")
    from dnsfilter_mcp.tools import organizations

    mcp = FastMCP(name="test")
    organizations.register(mcp, lambda: client)
    result = await mcp.call_tool("dnsfilter_get_organization", {"organization_id": 999})
    body = json.loads(_text(result))
    assert body["error"]["code"] == "not_found"
    assert body["error"]["retryable"] is False


@pytest.mark.asyncio
@respx.mock
async def test_get_network_not_found():
    """TC-DNSF-011 (AC11)."""
    respx.get(f"{BASE}/v1/networks/999").mock(
        return_value=httpx.Response(404, json={"error": "Not Found"})
    )
    client = DNSFilterClient("test-key")
    from dnsfilter_mcp.tools import networks

    mcp = FastMCP(name="test")
    networks.register(mcp, lambda: client)
    result = await mcp.call_tool("dnsfilter_get_network", {"network_id": 999})
    body = json.loads(_text(result))
    assert body["error"]["code"] == "not_found"


@pytest.mark.asyncio
@respx.mock
async def test_get_policy_not_found():
    """TC-DNSF-011 (AC11)."""
    respx.get(f"{BASE}/v1/policies/999").mock(
        return_value=httpx.Response(404, json={"error": "Not Found"})
    )
    client = DNSFilterClient("test-key")
    from dnsfilter_mcp.tools import policies

    mcp = FastMCP(name="test")
    policies.register(mcp, lambda: client)
    result = await mcp.call_tool("dnsfilter_get_policy", {"policy_id": 999})
    body = json.loads(_text(result))
    assert body["error"]["code"] == "not_found"


@pytest.mark.asyncio
@respx.mock
async def test_list_tool_empty_result_is_not_not_found():
    """TC-DNSF-012 (AC12): empty data -> empty items, not a not_found error."""
    respx.get(f"{BASE}/v1/organizations").mock(return_value=httpx.Response(200, json={"data": []}))
    client = DNSFilterClient("test-key")
    from dnsfilter_mcp.tools import organizations

    mcp = FastMCP(name="test")
    organizations.register(mcp, lambda: client)
    result = await mcp.call_tool("dnsfilter_list_organizations", {})
    body = json.loads(_text(result))
    assert body == {"items": [], "has_more": False}
    assert "error" not in body


@pytest.mark.asyncio
@respx.mock
async def test_rate_limit_retries_then_surfaces_rate_limited():
    """TC-DNSF-010 (AC10): a persisting 429 (mocked for every attempt) is
    retried with backoff and then surfaces a structured rate_limited error,
    never a raw exception.
    """
    route = respx.get(f"{BASE}/v1/organizations").mock(
        return_value=httpx.Response(
            429, json={"error": "Too Many Requests"}, headers={"Retry-After": "0"}
        )
    )
    client = DNSFilterClient("test-key")
    from dnsfilter_mcp.tools import organizations

    mcp = FastMCP(name="test")
    organizations.register(mcp, lambda: client)
    result = await mcp.call_tool("dnsfilter_list_organizations", {})
    body = json.loads(_text(result))
    assert body["error"]["code"] == "rate_limited"
    assert body["error"]["retryable"] is True
    # 1 initial attempt + 3 retries (client.py's _MAX_RETRIES)
    assert route.call_count == 4


def _text(result) -> str:
    return result[0][0].text if isinstance(result, tuple) else str(result)
