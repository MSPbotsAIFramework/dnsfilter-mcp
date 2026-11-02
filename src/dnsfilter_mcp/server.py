from collections.abc import Callable

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from .auth import get_api_key_from_context
from .client import DNSFilterClient
from .settings import Settings


def get_client_from_context() -> DNSFilterClient | None:
    """Resolve the active DNSFilterClient for the current request context."""
    api_key = get_api_key_from_context()
    if not api_key:
        return None
    return DNSFilterClient(api_key)


def create_mcp_server(settings: Settings) -> FastMCP:
    """Build the FastMCP server instance and register all DNSFilter tools."""
    # DNS-rebinding protection is a browser-oriented safeguard that rejects
    # non-localhost Host headers with 421. Disable it so the server works
    # correctly behind a reverse proxy or docker network.
    mcp = FastMCP(
        name="dnsfilter-mcp",
        instructions=(
            "DNSFilter is a DNS-layer content-filtering and threat-protection "
            "vendor. This server gives read-only visibility into a DNSFilter "
            "account's organizations, networks, filtering policies, the "
            "content-category taxonomy, and traffic/threat reporting — it "
            "never changes a customer's live filtering policy (no "
            "write/config-push tools exist here by design). Typical flow: "
            "dnsfilter_list_organizations to find an organization, "
            "dnsfilter_list_networks (optionally scoped to it) to find a "
            "network and its policy_id, dnsfilter_get_policy to read that "
            "policy's full configuration, dnsfilter_list_categories to "
            "resolve category ids to names, and "
            "dnsfilter_get_traffic_summary / dnsfilter_get_top_report for "
            "request/threat volume over a time window."
        ),
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        stateless_http=True,
        json_response=True,
    )

    client_factory: Callable[[], DNSFilterClient | None] = get_client_from_context

    from .tools import categories, networks, organizations, policies, reports

    organizations.register(mcp, client_factory)
    networks.register(mcp, client_factory)
    policies.register(mcp, client_factory)
    categories.register(mcp, client_factory)
    reports.register(mcp, client_factory)

    return mcp
