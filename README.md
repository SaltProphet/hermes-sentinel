# Hermes Sentinel 0.1.1

![Hermes Sentinel — Audit · Block · Truncate](assets/hermes-sentinel-start-card.png)

Deterministic tool-loop protection, bounded tool output, and a best-effort local
execution ledger for Hermes Agent. Runtime code uses Python's standard library
and the host's `hermes_constants` API. No external network requests or telemetry.

## Behavior and disclosure

- **Loop guard (`pre_tool_call`):** blocks the third consecutive identical tool
  call with identical arguments, tracked per session. It records dispatch
  attempts, not proof that an OS command executed.
- **Tool results (`transform_tool_result`):** replaces recognized credential
  patterns with redaction markers and truncates output to at most 4,000
  characters and 100 lines **before the model sees it**. The model therefore
  receives a modified, potentially incomplete result.
- **New messages (`pre_llm_call`):** blocks a new `user_message` containing a
  credential-shaped string, including matching examples in code snippets.
  It does not scan or rewrite conversation history. An old credential-shaped
  string in history does not block later clean turns; submitting it again as
  a new message still blocks. Pattern matching is not exhaustive secret detection.
- **Audit (`post_tool_call` and guard hooks):** records dispatch attempts,
  observed completion/error status, sizes, supplied durations, and interventions.
  Argument previews are redacted before slicing; raw prompt and tool-result
  bodies are not stored. Tool names, timestamps and redacted previews are still
  local usage data. Ordinary unchanged tool results do not create a separate
  transform event.

## Audit storage and failures

The database is resolved using `hermes_constants.get_hermes_home()`:

```text
<active Hermes home>/plugin-data/hermes-sentinel/sentinel_audit.db
```

This honors Hermes's platform defaults and context/profile overrides. Sentinel
does not read `HERMES_HOME` directly or support `HERMES_SENTINEL_DB`.
No audit database is written to a fallback temporary directory.

If home resolution, directory creation, database opening, or schema creation
fails, Sentinel uses a retained in-memory SQLite database. Its events disappear
when the plugin/process closes. If that also fails, auditing is disabled.
Subsequent storage errors skip the affected audit operation; the credential and
loop guards remain active. The ledger is best-effort, not a guaranteed record.

## Compatibility

**Requires Hermes `>=0.22.6`.** Hermes 0.22.0–0.22.5 expose `pre_llm_call`
but do not honor its `{"action": "block", "message": ...}` return as a turn
veto. That behavior is present in the 0.22.6 release
([source at `f0d94882e89ab8d4098b5bb2f166adfb9ee0a0ab`](https://github.com/NousResearch/hermes-agent/blob/f0d94882e89ab8d4098b5bb2f166adfb9ee0a0ab/agent/turn_context.py)).
The path resolver, four hooks, CLI/slash registrars, and unload callback are
available at this floor. The catalog and manifest declare the same requirement.

## Local installation

Run in a Hermes-managed Python environment:

```bash
hermes plugins validate .
hermes plugins doctor . --ci
hermes plugins install .
```

The root `__init__.py` is a directory-loader wrapper; implementation lives only
in `hermes_sentinel/`. Relative directory imports isolate state per Hermes profile
and create a fresh ledger on reload; unloading one profile does not close another
profile's ledger. No compiled Python bytecode should be committed.

## CLI and slash commands

```bash
hermes sentinel status
hermes sentinel audit
hermes sentinel reset
hermes sentinel clear
```

In chat, use `/sentinel` to view the ledger, `/sentinel reset` to reset loop
counters, or `/sentinel clear` to clear audit rows.

Reset clears this process's loop counters and increments a shared reset epoch
when persistent storage works. Other processes using that database clear their
counters on their next tool call. In memory-only or disabled mode, reset applies
only to this process. Reset never permits credentials in a new message. No
history acknowledgment or history modification is needed for clean turns.

Clear deletes audit rows transactionally and advances the epoch without
unlinking the live database. It reports failure if auditing is unavailable.
Status displays the database path and persistent/memory/disabled storage mode.

## Deterministic demo and cleanup

Use the Python interpreter from your Hermes environment (or put the Hermes
source directory on `PYTHONPATH` so `hermes_constants` is importable):

```bash
python -B scripts/run_demo.py
```

On Windows:

```powershell
.\scripts\run_demo.ps1 -PythonExe 'C:\path\to\Hermes\python.exe'
```

The demo makes no model calls. Python owns one new temporary directory and runs
the checks in a child with an allowlisted OS/runtime environment. It copies no
default configuration, `.env`, model credentials, or messaging credentials.
It does not create or delete registered Hermes profiles. PowerShell delegates
to the same runner and propagates failure.

The child closes its ledger before exit. The owner removes its directory on
success, exceptions, child failure/timeout, and handled SIGINT/SIGTERM; previous
signal handlers are restored and the parent environment is not changed. Cleanup
errors are surfaced rather than silently reported as success. Forced process
termination or power loss cannot run Python cleanup handlers.

## Tests and local release gate

The tests use `unittest`; metadata checks use the host's `hermes_yaml` parser.
Run in the Hermes environment with an isolated `HERMES_HOME` and bytecode generation disabled:

```bash
python -B -m unittest discover -s regression_tests -v
```

Before an approved release, stop on any nonzero exit or missing result:

1. Run the entire suite in an isolated home.
2. Run the Python demo and PowerShell wrapper on Windows.
3. Run real `hermes plugins validate <candidate> --json` and
   `hermes plugins doctor <candidate> --ci` in an isolated Hermes home.
4. In a disposable Hermes runtime, run admission-equivalent
   `hermes plugins validate <candidate> --install-deps --json`.
5. Confirm all four hooks, zero tools, matching parsed metadata, no candidate
   bytecode, and no bytecode in the proposed Git index/tree.
6. Review the complete diff and obtain owner approval before applying to clones
   or committing. Replace the catalog placeholder with the actual approved
   plugin commit, revalidate the pinned tree, and obtain explicit push approval.

These steps never authorize an automatic push. A placeholder pin is a release
blocker, not a fabricated validation success.

## Proposed catalog YAML

Version 0.1.1; the SHA remains a placeholder until an owner-approved commit
exists. This example is not install-ready.

```yaml
name: hermes-sentinel
repo: https://github.com/SaltProphet/hermes-sentinel
sha: "<approved-plugin-commit-sha>"
maintainer: Justin Strange
tier: community
category: tools
description: >-
  Deterministic runtime circuit breaker and local execution auditor.
  Disclosure: blocks credential-shaped strings in new user messages and
  repetitive tool calls; redacts and truncates tool results before the model
  sees them; stores audit events under the active Hermes home's
  plugin-data/hermes-sentinel/sentinel_audit.db, falling back to memory-only
  storage or skipped auditing on failure; performs no external network
  requests or telemetry.
requires_hermes: ">=0.22.6"
version: "0.1.1"
capabilities:
  provides_tools: []
  provides_hooks:
    - pre_llm_call
    - pre_tool_call
    - post_tool_call
    - transform_tool_result
  provides_middleware: []
  requires_env: []
```
