# AGENTS.md

Hermes Agent plugin: deterministic secret redaction, a loop guard, bounded tool
output, and a local audit ledger. Runtime code is standard library plus the
host's `hermes_constants`. No network, no telemetry, no subprocesses.

Setup, test commands, the release gate, and the demo internals live in
[CONTRIBUTING.md](CONTRIBUTING.md). This file is only what you must not get wrong.

## Layout

- Root `__init__.py` is the directory-loader wrapper. Implementation lives only in `hermes_sentinel/`.
- `hermes_sentinel/__init__.py` owns the four hooks, the CLI/slash handlers, and registration.
- `hermes_sentinel/rules.py` owns `SECRET_PATTERNS`, loop detection, and truncation.
- `hermes_sentinel/audit.py` owns the SQLite ledger.

## Invariants

- Audit path comes from `hermes_constants.get_hermes_home()`: `<home>/plugin-data/hermes-sentinel/sentinel_audit.db`. Never read `HERMES_HOME` directly; never add a database-path override.
- `requires_hermes >=0.22.6`: earlier releases ignore the `pre_llm_call` block return.
- `scan_and_redact()` applies `SECRET_PATTERNS` in order. Specific prefixes go above the generic `sk-` rule; the labelled `token=` / `api_key:` catch-all stays last.
- The version is written in `plugin.yaml`, `pyproject.toml`, the `status` line in `hermes_sentinel/__init__.py`, and both demo scripts. Not in the README.
- No file in this repo carries the release SHA. The catalogue entry is the only place it is written.
- Test fixtures for credentials are built by concatenation; `test_admission` runs Hermes's `tools.plugin_guard` against committed literals.

## Commits

`fix: ... - vX.Y.Z` or `docs: ... - vX.Y.Z`, matching history. Do release work
on a dedicated branch. Never push without explicit approval.
