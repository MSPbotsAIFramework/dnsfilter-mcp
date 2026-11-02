# dnsfilter-mcp

MCP server for **DNSFilter** — organization/network/policy configuration,
content categories, and traffic/threat reporting, read-only — over the
[Model Context Protocol](https://modelcontextprotocol.io/) (Streamable
HTTP transport), built against DNSFilter's own public REST API
(`https://api.dnsfilter.com`, OpenAPI spec at
`https://api.dnsfilter.com/docs/api.json`).

Built for [PRD-21229](https://app.clickup.com/t/86e3v6w7f): "Review
org/network/policy configuration, content categories, and traffic/threat
reporting via DNSFilter." No existing DNSFilter connector was found in
MSPbotsAIFramework, so this is a from-scratch, clean-room build from
DNSFilter's own documented API — see `docs/tickets/PRD-21229.md` for the
full design.

<div align="center">

## MSPbots Connector

**The MCP Gateway built for MSPs: visible, controlled, and your data stays where it belongs.**

[**Get started at connect.mspbots.ai →**](https://connect.mspbots.ai)

</div>

---

MSPbots Connector gives your AI clients one MCP URL to reach your entire MSP stack (RMM, PSA, documentation, security, finance), and gives you control over who can call which tool and a record of everything that was called.

**Hosted service: [connect.mspbots.ai](https://connect.mspbots.ai)** · Free to use.

### Why Connector

![MSPbots Connector](https://stgoss.mspbots.ai/files/mcp/mspbots-mcp.png)

| | |
|---|---|
| **Visible** | Every tool call is logged: who, which vendor, when. Usage dashboard, CSV export, SIEM streaming. |
| **Controlled** | Role-based, per-tool allowlist. Deny by default. |
| **Protected** | Credentials encrypted per record. AI clients never see your vendor passwords or tokens. |
| **MSP-native** | Built for the MSP stack only: RMM, PSA, documentation, security, finance. |

### Quick start

1. **Sign up** at [connect.mspbots.ai](https://connect.mspbots.ai).
2. **Connect your vendors.** Pick from 150+ connectors and authorize each one on the vendor's own page, or bring your own API keys. No extra vendor accounts needed.
3. **Set access.** Create roles and decide which tools each role may call. Nothing is allowed until you allow it.
4. **Add your MCP URL to your AI client.** Copy the URL from your Connector dashboard into Claude, ChatGPT, Cursor, VS Code, Gemini, Codex, or any MCP-capable client.
5. **Ask your AI to do real work**, and watch every call appear in the audit log.

### Features

**Unified gateway**
- One MCP URL for all your AI clients
- 150+ connectors across the MSP stack
- Custom MCP servers supported, free
- Authorization happens on each vendor's own page; the AI never sees passwords or tokens
- Bring your own credentials: use the vendor API keys you already have
- Multiple accounts per app; connect once, reuse across AI clients
- Tool search: finds the right action for the task
- One sign-in; vendor credentials are injected behind the scenes and OAuth tokens refresh automatically

**Visibility**
- Audit log for every tool call (who, which vendor, when)
- Usage dashboard: call volume, top vendors, error rate, per-user activity
- Export audit logs to CSV, or stream to Loki, Graylog, or LogScale (SIEM)
- Optional recording of tool arguments and result summaries (off by default, enabled per organization)

**Control**
- Per-role, per-tool allowlist, deny by default
- owner / admin / member roles
- SCIM provisioning with Entra ID, Okta, JumpCloud, and Google Workspace

**Security**
- Credentials encrypted one record at a time (AES-256-GCM, per-record key)
- AI clients authenticate with OAuth 2.1 + PKCE
- Vendor responses are scanned for prompt-injection patterns and returned as structured data. This is one layer of defense, not a guarantee against every attack.
- Static egress IP for customer firewall and API allowlisting

### Pricing

**Free.**

Links: [connect.mspbots.ai](https://connect.mspbots.ai) · [mspbots.ai](https://mspbots.ai)

---

## Authentication headers

| Header | Required | Meaning | Where to get it |
|---|---|---|---|
| `X-Dnsfilter-Api-Key` | Yes | DNSFilter API key, sent through as-is to DNSFilter's own `Authorization` header (no scheme prefix) | DNSFilter dashboard → Account Settings → Security → API Keys |

Missing the header returns `401 Unauthorized` and lists the required header name; this server never calls DNSFilter without it, and never falls back to an environment variable.

## Tools

All 9 tools are read-only; there are no configuration-change tools in this
service (DNSFilter's policy-mutation endpoints — add/remove block or allow
entries, etc. — are intentionally not wired up; see Known Gaps).

| Tool | Description | Required args |
|---|---|---|
| `dnsfilter_list_organizations` | List the organizations visible to this API key | None |
| `dnsfilter_get_organization` | Get one organization's basic information | `organization_id` |
| `dnsfilter_list_networks` | List networks, with organization_id/policy_id and whether a policy is assigned | None |
| `dnsfilter_get_network` | Get one network's details | `network_id` |
| `dnsfilter_list_policies` | List policies, optionally scoped to one organization | None |
| `dnsfilter_get_policy` | Get one policy's full filtering configuration | `policy_id` |
| `dnsfilter_list_categories` | List the content category taxonomy | None |
| `dnsfilter_get_traffic_summary` | Aggregate request/threat count over a time window, bucketed by time | `metric`, `from_`, `to` |
| `dnsfilter_get_top_report` | Top-N breakdown by category/domain/network/organization over a time window | `dimension`, `from_`, `to` |

## Quick Start

### Docker (recommended)

```bash
docker compose up --build
```

The server starts on `http://localhost:8080`.

### Local (uv)

```bash
uv sync
python -m dnsfilter_mcp
```

## Health Check

```bash
curl http://localhost:8080/health
# {"status": "ok"}
```

No credentials are required for the health endpoint.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `MCP_HTTP_PORT` | `8080` | Listening port |
| `MCP_HTTP_HOST` | `0.0.0.0` | Listening host |

## MCP Endpoint

```
POST http://localhost:8080/mcp
```

Connect your MCP client with:
- Transport: `http` (Streamable HTTP)
- Headers: `X-Dnsfilter-Api-Key` (required)

## Test Example

```bash
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "X-Dnsfilter-Api-Key: <customer-dnsfilter-api-key>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": { "name": "dnsfilter_list_organizations", "arguments": {} }
  }'
```

> ⚠️ This is a private repository, but do not write real customer API keys into any committed file regardless. The placeholders above are for illustration only.

## Known Gaps

- **Nothing here has been exercised against a real DNSFilter account.**
  Every endpoint shape, field name, and error body comes from reading
  `dnsfilter-openapi@2026-10-27` (`https://api.dnsfilter.com/docs/api.json`,
  fetched and parsed live during both design and development), not from a
  live call. Unit tests mock every DNSFilter response; nothing here
  confirms the real API matches its own published spec in practice.
- **Organization `type` is a best-effort field.** DNSFilter's own
  `Organization` attribute schema has no field matching the
  `normal`/`msp`/`sub_organization` enum used by `GET /v1/organizations`'s
  own `type` *filter* parameter — the closest candidate is an undocumented
  string field named `role` (`{"type": "string", "description": "Role"}`,
  no further description in the spec). `dnsfilter_list_organizations`
  surfaces `role` as `type`; if a real account's `role` values turn out
  not to match the three documented `type` filter values, this is a
  one-line fix in `tools/organizations.py` (`_organization_item`), not a
  tool-contract change.
- **`dnsfilter_list_networks`'s `organization_id` filter is client-side.**
  `GET /v1/networks` has no `organization_id` query parameter (confirmed
  absent from the spec); this connector fetches DNSFilter's own page and
  filters by `relationships.organization.data.id` afterward. This means
  when `organization_id` is given, `has_more` reflects whether DNSFilter's
  *unfiltered* page was full, not whether the organization-scoped result
  was — a page can come back with fewer same-organization items than
  `limit` even when more exist on a later page. Pass a larger `limit`
  and/or page through multiple calls if this matters for a given query.
- **`dnsfilter_get_top_report`'s `dimension=organizations` has a narrower
  contract than the other three dimensions.** DNSFilter's
  `GET /v1/traffic_reports/top_organizations_requests` has no
  `network_ids` or `security_report` filter and takes a single
  `organization_id` rather than the plural, comma-separated
  `organization_ids` every other `traffic_reports/*` operation in this
  connector uses — confirmed from the spec's parameter list for that one
  operation. `network_id` and `security_report` are silently ignored for
  this dimension (not rejected); see the tool's own description.
- **`dnsfilter_get_traffic_summary`/`dnsfilter_get_top_report`'s `network_id`
  and `organization_id` args are singular** (matching every other tool in
  this connector) even though DNSFilter's own filters for these endpoints
  are plural/comma-separated (`organization_ids`, `network_ids`) — this
  connector joins a single value into the one-element list form DNSFilter
  expects. Scoping to more than one organization or network in a single
  call isn't exposed; it's additive if a future ticket asks for it.
- **Raw query-log export (`query_logs`) is out of scope for v1**, by
  design, not an oversight — DNSFilter's own docs describe that endpoint
  as "intended for investigation and reporting... not designed for bulk
  or continuous log export," and the ticket's "traffic/threat reporting"
  ask is covered by the aggregate/top-N report tools above. See
  `docs/tickets/PRD-21229.md` Non-goals.
- **No write/config-change tools exist, and none are planned for this
  ticket** — DNSFilter's policy-mutation endpoints (`add_blacklist_domain`,
  `add_allowed_application`, etc.) are real and documented in the vendor's
  spec, but deliberately not wired up: the ticket asks to "Review", not
  "manage", DNSFilter's filtering configuration, and a write tool for a
  live filtering policy is customer-impacting enough to deserve its own
  ticket with an explicit confirmation/guardrail story.
