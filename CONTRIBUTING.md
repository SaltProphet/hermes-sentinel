# Contributing

## Setup

The test suite and demo import host modules (`hermes_constants`, `hermes_yaml`,
`hermes_cli.plugins`, `tools.plugin_guard`), so run them with the Hermes source
on `PYTHONPATH` or with Hermes's own interpreter:

```powershell
$env:PYTHONPATH = 'C:\path\to\hermes-agent'
$env:HERMES_HOME = Join-Path $env:TEMP 'sentinel-test-home'
python -B -m unittest discover -s regression_tests -v
```

Use a throwaway `HERMES_HOME` so tests never touch a real profile's ledger, and
keep `-B` so no bytecode lands in the tree.

Single test:

```powershell
python -B -m unittest regression_tests.test_regressions.TurnRegressions.<name> -v
```

Tests are `unittest` despite the pytest section in `pyproject.toml`.
`test_demo` runs the real demo; its PowerShell wrapper test runs on Windows only.

## Layout

- Root `__init__.py` is the directory-loader wrapper. Implementation lives only
  in `hermes_sentinel/`.
- `hermes_sentinel/__init__.py` — the four hooks, CLI/slash handlers, registration.
- `hermes_sentinel/rules.py` — `SECRET_PATTERNS`, loop detection, truncation.
- `hermes_sentinel/audit.py` — the SQLite ledger.

Directory imports keep state per Hermes profile and build a fresh ledger on
reload; unloading one profile does not close another's ledger.

The audit path must come from `hermes_constants.get_hermes_home()`. Do not read
`HERMES_HOME` directly and do not add a database-path override.

## Guard budgets

Positive integers read at startup; invalid values fall back to the defaults.

| Variable | Default | Meaning |
| --- | --- | --- |
| `HERMES_SENTINEL_LOOP_THRESHOLD` | 3 | identical results before an ordinary call is blocked |
| `HERMES_SENTINEL_POLL_THRESHOLD` | 8 | same, for polling/status calls |
| `HERMES_SENTINEL_REPEAT_CAP` | 30 | identical-argument calls blocked even when results change |

The polling set is `status`, `check`, `poll`, `wait`, `deploy`, `deployment`,
`rollout`, `health`, `ready`, `progress`, `watch`, `describe`, matched as a
delimited word in the tool name or its arguments. Counters are per session and
held in memory; only a SHA-256 digest of each result is retained.

## Storage

The ledger is `<hermes home>/plugin-data/hermes-sentinel/sentinel_audit.db`. If
it cannot be opened, auditing falls back to memory for that process, and to
disabled if that also fails; the guards keep working.

`reset` clears this process immediately and other processes on their next tool
call. `clear` deletes rows transactionally without unlinking the file. In
memory-only or disabled mode, reset applies to this process alone.

## Redaction ordering

`scan_and_redact()` applies `SECRET_PATTERNS` in list order, so order is
behavior. Specific prefixed formats go above the generic `sk-` rule, and the
labelled `token=` / `api_key:` catch-all stays last. The generic
`sk-[A-Za-z0-9]{32,}` rule stops at the hyphen in `sk-proj-` and `sk-ant-`, which
is why those prefixes have dedicated patterns.

Build fixtures by concatenation (`"sk-ant-" + "A" * 40`); `test_admission` runs
Hermes's `tools.plugin_guard`, which flags credential-shaped literals committed
to the repo.

## Versioning

Change the version in one commit across:

- `plugin.yaml`
- `pyproject.toml`
- `hermes_sentinel/__init__.py` (the `status` line)
- `scripts/run_demo.py` and `scripts/run_demo.ps1`

The README does not carry a version, and no file in this repo carries the
release SHA. The catalogue entry does.

## Release gate

Stop on any nonzero exit or missing result.

1. Full suite, isolated home, bytecode disabled.
2. `python -B scripts/run_demo.py`, and the PowerShell wrapper on Windows.
3. `hermes plugins validate <candidate> --json` and
   `hermes plugins doctor <candidate> --ci` in an isolated Hermes home.
4. `hermes plugins validate <candidate> --install-deps --json` in a disposable
   runtime.
5. Confirm four hooks, zero tools, matching metadata, and no bytecode in the
   index or tree.
6. Review the full diff, get owner approval, then commit and push.

The catalogue PR pins that commit in `plugin-catalog/hermes-sentinel.yaml`. The
SHA is written there and nowhere else: a commit cannot name its own hash, so any
copy of it inside this repo is stale the moment it is committed.

Pushing is a separate, explicit approval. Nothing here authorizes it.

## Demo internals

`scripts/run_demo.py` makes no model calls. It creates one temporary home and
runs the checks in a child process with an allowlisted environment; it copies no
configuration, `.env`, model credentials, or messaging credentials, and it does
not create or delete registered Hermes profiles. The PowerShell wrapper
delegates to the same runner and propagates failure.

The child closes its ledger before exit. The owner removes the directory on
success, exceptions, child failure or timeout, and handled SIGINT/SIGTERM, then
restores the previous signal handlers. Cleanup errors are surfaced rather than
reported as success. Forced termination or power loss cannot run Python cleanup
handlers.
