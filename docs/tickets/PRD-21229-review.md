# PRD-21229 · Code review

## Round 1 · 2026-11-02 · reviewed dev/PRD-21229 @ caac8fb (base main @ b7901cf)

Verdict: approved

### Scope

`git diff b7901cf...caac8fb` — new repo `MSPbotsAIFramework/dnsfilter-mcp`, first version (9 read-only
tools). Checked against `docs/tickets/PRD-21229.md` (product design, tech design, test cases,
self-test), `docs/tickets/PRD-21229.ac.json`, `references/REVIEW.md`, and the vendor-mcp-development
SOP §1–§11 and §14 Checklist.

### Verification performed (re-run independently, not taken on the dev leg's word)

- `uv sync && uv run pytest -q` → 33 passed, 0 failed (matches the `[DEV]` stub).
- `uv run ruff check .` → all checks passed.
- `grep -rnP '[\x{4e00}-\x{9fff}]' --exclude-dir=.git --exclude-dir=.venv .` → no output (CJK scan clean).
- `gitleaks detect --source . --no-git` → no leaks found.
- Live smoke (`uv run python -m dnsfilter_mcp`): `GET /health` → `200 {"status":"ok"}`; `POST /mcp`
  with no `X-Dnsfilter-Api-Key` → `401`, `required_headers: ["X-Dnsfilter-Api-Key"]`; `POST /mcp`
  `tools/list` with a placeholder header and **no prior `initialize`** → `200` with all 9 tools
  (confirms `stateless_http=True`).
- `docker build --platform linux/amd64 .` — **not run**: this review environment also has no
  `docker.sock` permission (`permission denied`, same class of sandbox limitation the dev leg
  reported, confirmed independently). `Dockerfile` reviewed by inspection instead: matches the SOP §8
  reference template verbatim (multi-stage, non-root `app` user, `curl` installed, `EXPOSE 8080`,
  `HEALTHCHECK` on `/health`, `ENV MCP_HTTP_PORT=8080`/`MCP_HTTP_HOST=0.0.0.0`), only the vendor name
  substituted. Flagged for the next environment with Docker access to build once before real traffic.
- README's `## MSPbots Connector` section diffed byte-for-byte against
  `~/.claude/skills/vendor-mcp-development/reference/readme-connector-section.md` → identical.
- Diffed the Tech design's "Data & API contract" section against each tool's actual return shape in
  `src/dnsfilter_mcp/tools/*.py` and the respx-mocked fixtures in `tests/test_tools.py` field by field.

### Findings

1. [suggestion] `docs/tickets/PRD-21229.md:300` vs `src/dnsfilter_mcp/tools/categories.py:47-54` —
   the Tech design's "Data & API contract" section documents `dnsfilter_list_categories`'s return
   shape as `{"id","name","description","security","internal"}`, but the implementation's
   `_organization`-style item dict only returns `id`/`name`/`description`/`security` — `internal` is
   never read from `attrs` or included in the response, and `tests/test_tools.py`'s
   `test_list_categories_includes_security_flag` fixture doesn't mock or assert it either. This
   doesn't violate AC6 (AC6's wording is "id, name, description, whether it is security-flagged" —
   it never names `internal`), so it's not a user-visible behavior gap, just a Tech design ↔
   implementation mismatch that wasn't called out in the "Corrections to the design's assumed field
   shapes" section the way the other two field-shape deviations (organization `type`/`role`, network
   `protected`) were. Low risk to ship as-is; worth a one-line fix (add the field) or a doc correction
   in a follow-up, not worth a round-trip for.
2. [suggestion] `src/dnsfilter_mcp/tools/_common.py:24` — `MAX_LIMIT = 100` is dead code: every tool
   module (`organizations.py:22`, `networks.py:39`, `policies.py:23`, `categories.py:21`) redefines
   its own private `_MAX_LIMIT = 100` instead of importing this shared constant. Harmless duplication
   (all four copies agree with DNSFilter's own documented page-size cap), falls under the 2026-10-28
   "leftover dead code in a module this ticket touched" suggestion category, not a must-fix.

No must-fix findings.

### Standards checked, all satisfied

- Credentials: `X-Dnsfilter-Api-Key` only, read per-request via `contextvars` (not a module/global),
  `finally: reset()` always runs (`src/dnsfilter_mcp/auth.py`); never logged, never falls back to an
  env var (`settings.py` carries no credential field at all); `secret_key` stripped from every
  `Network` response (`tools/networks.py:45-50`, asserted by
  `test_list_networks_populates_ids_and_strips_secret_key` / `test_get_network_strips_secret_key`).
- Tool/param/return/error shape matches the Tech design (bar finding 1); errors are the fixed SOP §4.2
  envelope (`errors.py:12-19` — table matches the SOP vocabulary exactly), never a raw exception.
- Tests changed alongside the tools they cover; Self-test has real test results on the actual
  synced-with-main code, plus a `tools/list` snapshot (`tests/test_tools.py::test_tools_list_snapshot`).
- README's Connector section is byte-identical to the template (verified above); no CJK anywhere in
  the repo (verified above).
- Cross-repo header/field compatibility (mcp-track.md §1.2): not applicable — this ticket only
  touches the new `dnsfilter-mcp` repo, no shared contract with another repo.
- SOP §14 Checklist: all "must" items satisfied by inspection + the verification run above, except the
  Docker build itself, which neither leg's environment can execute (see Findings — not a code defect).

### Fixes

N/A — no must-fix findings, nothing to fix.

---
Status: frozen @ caac8fb
