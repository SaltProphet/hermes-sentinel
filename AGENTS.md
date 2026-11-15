# AGENTS.md

Hermes Agent plugin providing deterministic secret redaction, a loop guard, bounded tool output, and a local audit ledger. Runtime code is standard library only plus the host's `hermes_constants`; no network requests or telemetry.

## Layout

- Root `__init__.py` is a directory-loader wrapper. Implementation lives only in `hermes_sentinel/`.
- `hermes_sentinel/__init__.py` owns the four hooks (`pre_llm_call`, `pre_tool_call`, `post_tool_call`, `transform_tool_result`), the CLI/slash handlers, and registration.
- `hermes_sentinel/rules.py` owns `SECRET_PATTERNS`, loop detection, and truncation. `hermes_sentinel/audit.py` owns the SQLite ledger.
- Audit path: `<Hermes home>/plugin-data/hermes-sentinel/sentinel_audit.db`, resolved through `hermes_constants.get_hermes_home()`. Do not read `HERMES_HOME` directly or add a `HERMES_SENTINEL_DB` override.
- `requires_hermes >=0.22.6`: earlier releases do not honor the `pre_llm_call` block return.

## Tests

The suite imports host modules (`hermes_constants`, `hermes_yaml`, `hermes_cli.plugins`, `tools.plugin_guard`), so a bare `python` fails unless the Hermes source checkout is on `PYTHONPATH` (on this machine: `C:\Users\Shadow\hermes-agent`) or you use the Hermes-managed interpreter.

Full suite from the repo root:

```powershell
$env:PYTHONPATH = 'C:\Users\Shadow\hermes-agent'
$env:HERMES_HOME = Join-Path $env:TEMP 'sentinel-test-home'
python -B -m unittest discover -s regression_tests -v
```

Use an isolated `HERMES_HOME` so tests do not touch the real profile's audit database. Keep `-B`; compiled bytecode must not enter the tree.

- Single test: `python -B -m unittest regression_tests.test_regressions.TurnRegressions.<test_name> -v`
- Tests are `unittest`, despite `[tool.pytest.ini_options]` in `pyproject.toml`.
- `test_demo` runs the real demo; the PowerShell wrapper test runs only on Windows.
- Demo: `python -B scripts/run_demo.py` (or `scripts/run_demo.ps1`). It makes no model calls and owns a disposable home.

## Redaction ordering

`scan_and_redact()` applies `SECRET_PATTERNS` sequentially, so list order is behavior. Put specific prefixed formats above the generic `sk-` rule and the labelled `token=`/`api_key:` catch-all, which must stay last. The generic `sk-[A-Za-z0-9]{32,}` rule stops at the hyphen in `sk-proj-`/`sk-ant-`, so those prefixes need dedicated patterns.

Build test and demo fixtures by concatenation (`"sk-ant-" + "A" * 40`). `test_admission` runs Hermes `tools.plugin_guard`, which flags credential-shaped literals committed to the repo.

## Versioning and release

- Keep the version identical in `plugin.yaml`, `pyproject.toml`, `README.md` (heading, prose, catalog YAML), `hermes_sentinel/__init__.py`, `scripts/run_demo.py`, `scripts/run_demo.ps1`, and the hard-coded assertions in `regression_tests/test_metadata.py`. `test_metadata` compares the parsed manifest, project, catalog, and CLI output.
- Release gate: README "Tests and local release gate". Validate and doctor in an isolated Hermes home, run the demo and PowerShell wrapper, confirm metadata and no bytecode, review the full diff, and get owner approval. Never push automatically; a placeholder catalog SHA blocks release.
- `release/` is git-ignored scratch output. Edit the source tree, not `release/hermes-sentinel/`.
- Commit style from history: `fix: ... - vX.Y.Z`. Do release work on a dedicated branch until approved.
