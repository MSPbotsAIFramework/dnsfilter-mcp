"""Shared pagination helpers for DNSFilter's list endpoints.

DNSFilter's `page` query parameter is documented as an object
({"number": int, "size": int}) rather than a flat query key — most HTTP
clients, httpx included, do not serialize a nested dict to query string
automatically, so it must be built explicitly as the two bracketed keys
`page[number]` / `page[size]` (confirmed against every list operation in
dnsfilter-openapi@2026-10-27, e.g. GET /v1/organizations).

List responses carry a JSON:API `links.self` with no `has_more`/`total`
field (confirmed absent from every list response schema in the same
spec), so `has_more` is derived heuristically here: true when the page
returned exactly the requested page size, false otherwise. Each list
tool's own docstring calls this out as a heuristic.
"""

from typing import Any


def page_params(page: int, size: int) -> dict[str, int]:
    return {"page[number]": page, "page[size]": size}


def has_more(items: list[Any], requested_size: int) -> bool:
    return requested_size > 0 and len(items) == requested_size
