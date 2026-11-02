"""Shared helpers for shaping DNSFilter's JSON:API resource objects into
the flat, agent-facing shapes this connector's tools return.

DNSFilter wraps every resource as {"id": "<id>", "type": "...",
"attributes": {...}, "relationships": {...}} (JSON:API-flavored, per
dnsfilter-openapi@2026-10-27's IdType/*Spec schemas). `id` is typed as a
string in the spec (it documents "integer or uuid"); every resource this
connector touches (organizations, networks, policies) in practice uses
numeric ids, so resolve_id casts numeric-looking strings to int for a
cleaner agent-facing value while passing through anything else as-is.
"""

from typing import Any

from .._json import error_envelope

NO_TOKEN = error_envelope(
    "not_configured",
    "No DNSFilter credentials. Send the X-Dnsfilter-Api-Key header.",
    False,
)

# Hard cap on page[size] — DNSFilter's own documented max for list endpoints.
MAX_LIMIT = 100


def resolve_id(value: Any) -> Any:
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return value


def relationship_id(spec: dict, name: str) -> Any:
    """Pull a to-one relationship's id out of a JSON:API resource object,
    e.g. relationship_id(network_spec, "organization") for
    relationships.organization.data.id. Returns None if the relationship
    is absent or null (e.g. a network with no policy assigned).
    """
    rel = ((spec.get("relationships") or {}).get(name) or {}).get("data")
    if not rel:
        return None
    return resolve_id(rel.get("id"))
