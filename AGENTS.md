# AGENTS.md

Hermes Agent plugin: loop guard, credential redaction, bounded tool output, and a
local audit ledger. Standard library plus the host's `hermes_constants`. No
network, no telemetry, no subprocesses.

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

## Tests

Need the Hermes source on `PYTHONPATH` (or the Hermes interpreter) and a
throwaway home:

```powershell
$env:PYTHONPATH = 'C:\path\to\hermes-agent'
$env:HERMES_HOME = Join-Path $env:TEMP 'sentinel-test-home'
python -B -m unittest discover -s regression_tests -v
```

`unittest`, despite the pytest section in `pyproject.toml`. Keep `-B`; never
write to a real profile. Single test:

```powershell
python -B -m unittest regression_tests.test_regressions.TurnRegressions.<name> -v
```

## Guard budgets

Positive integers read at startup; invalid values fall back to defaults.

| Variable | Default | Meaning |
| --- | --- | --- |
| `HERMES_SENTINEL_LOOP_THRESHOLD` | 3 | identical results before an ordinary call is blocked |
| `HERMES_SENTINEL_POLL_THRESHOLD` | 8 | same, for polling/status calls |
| `HERMES_SENTINEL_REPEAT_CAP` | 30 | identical-argument calls blocked even when results change |

Polling set: `status`, `check`, `poll`, `wait`, `deploy`, `deployment`,
`rollout`, `health`, `ready`, `progress`, `watch`, `describe`, matched as a
delimited word in the tool name or arguments. Counters are per session and held
in memory; only a SHA-256 digest of each result is retained.

## Storage

If the ledger cannot be opened, auditing falls back to memory for that process,
and to disabled if that also fails; the guards keep working. `reset` clears this
process immediately and other processes on their next tool call. `clear` deletes
rows transactionally without unlinking the file.

## Demo

`python -B scripts/run_demo.py`, or `scripts/run_demo.ps1` on Windows. No model
calls. It creates one temporary home and runs the checks in a child with an
allowlisted environment; it copies no configuration, `.env`, or credentials, and
creates no registered profiles. The child closes its ledger before exit, and the
owner removes the directory on success, exceptions, child failure or timeout, and
handled SIGINT/SIGTERM, restoring previous handlers. Cleanup errors surface
rather than report success. Forced termination cannot run Python cleanup.

## Release

Stop on any nonzero exit or missing result:

1. Full suite, isolated home, bytecode disabled.
2. Demo, and the PowerShell wrapper on Windows.
3. `hermes plugins validate <candidate> --json`, `hermes plugins doctor <candidate> --ci`.
4. `hermes plugins validate <candidate> --install-deps --json`.
5. Four hooks, zero tools, matching metadata, no bytecode in the index or tree.
6. Review the diff, get owner approval, commit.

Then the catalogue PR pins that commit in `plugin-catalog/hermes-sentinel.yaml`.
The SHA is written there and nowhere else: a commit cannot name its own hash.
Pushing is a separate, explicit approval.

Commits look like `fix: ... - vX.Y.Z` or `docs: ... - vX.Y.Z`. Do release work on
a dedicated branch.
