"""Maps DNSFilter HTTP responses to the SOP error envelope.

Code table per vendor-mcp-development-sop.md SS4.2's fixed vocabulary.
status_code 0 means a network/connection-level failure (no response at
all). DNSFilter's own error body is {"error": "<message>"} (confirmed from
dnsfilter-openapi@2026-10-27's Error schema); that string is surfaced
as-is in `message`.
"""

from ._json import error_envelope

_STATUS_TO_CODE: dict[int, tuple[str, bool]] = {
    0: ("upstream_error", True),
    400: ("invalid_argument", False),
    401: ("unauthorized", False),
    403: ("unauthorized", False),
    404: ("not_found", False),
    422: ("invalid_argument", False),
    429: ("rate_limited", True),
}


def classify(status_code: int) -> tuple[str, bool]:
    if status_code in _STATUS_TO_CODE:
        return _STATUS_TO_CODE[status_code]
    if status_code >= 500:
        return "upstream_error", True
    return "invalid_argument", False


class DNSFilterError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(f"DNSFilter API error {status_code}: {message}")

    def to_envelope(self) -> str:
        code, retryable = classify(self.status_code)
        return error_envelope(code, self.message, retryable)
