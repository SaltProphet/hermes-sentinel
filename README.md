# Hermes Sentinel

![Hermes Sentinel — Audit · Block · Truncate](assets/hermes-sentinel-start-card.png)

A deterministic guard for Hermes Agent: it stops repeated identical tool calls,
redacts and truncates tool output before the model sees it, blocks new messages
that contain credential-shaped text, and keeps a local audit ledger.

No network requests, no telemetry, no subprocesses.

## Install

From the Hermes plugin catalog:

```bash
hermes plugins install hermes-sentinel
```

From a local checkout, in a Hermes-managed Python environment:

```bash
hermes plugins validate .
hermes plugins doctor . --ci
hermes plugins install .
```

## What it does

- **Stops stuck loops.** A tool call repeated with identical arguments and
  identical results is blocked. Repeats whose result changed count as progress,
  so deliberate polling keeps working. Calls whose name or arguments mention
  `status`, `check`, `poll`, `wait`, `deploy`, `health`, `ready`, `progress`,
  `watch`, or `describe` get a larger budget, and any identical-argument call is
  still stopped at the hard cap. Counters are per session; only SHA-256 digests
  of results are held, in memory.
- **Sanitizes tool output.** Recognized credential patterns are replaced with
  redaction markers and the result is cut to at most 4,000 characters and 100
  lines before the model receives it. The model therefore sees a modified,
  sometimes incomplete result.
- **Checks new messages.** A new user message containing credential-shaped text
  is refused, including examples inside code blocks. Conversation history is not
  scanned or rewritten, so an old secret in the transcript does not block later
  clean turns. Pattern matching is not exhaustive secret detection.
- **Writes a local ledger.** Dispatch attempts, completion or error status,
  sizes, durations and interventions are recorded with redacted 200-character
  argument previews. Prompts and tool-result bodies are not stored. Tool names,
  timestamps and previews are still local usage data.

## Configuration

The guard budgets are positive integers read at startup; invalid values fall
back to the defaults.

| Variable | Default | Meaning |
| --- | --- | --- |
| `HERMES_SENTINEL_LOOP_THRESHOLD` | 3 | identical results before an ordinary call is blocked |
| `HERMES_SENTINEL_POLL_THRESHOLD` | 8 | same, for polling/status calls |
| `HERMES_SENTINEL_REPEAT_CAP` | 30 | identical-argument calls blocked even when results change |

## Commands

```bash
hermes sentinel status
hermes sentinel audit
hermes sentinel reset
hermes sentinel clear
```

In chat: `/sentinel` shows the ledger, `/sentinel reset` clears loop counters,
`/sentinel clear` deletes audit rows. `status` reports the database path and
whether storage is persistent, in-memory, or disabled.

## Data

The ledger lives inside the active Hermes home:

```text
<hermes home>/plugin-data/hermes-sentinel/sentinel_audit.db
```

It follows Hermes's profile and platform resolution; Sentinel never reads
`HERMES_HOME` itself and writes no temporary fallback database. If the database
cannot be opened, auditing falls back to memory for that process, and to disabled
if even that fails. The guards keep working either way. The ledger is
best-effort, not a guaranteed record.

`reset` affects this process immediately and other processes using the same
database on their next tool call. `clear` deletes rows transactionally without
unlinking the file.

## Compatibility

Requires **Hermes `>=0.22.6`**. Earlier releases expose `pre_llm_call` but ignore
its `{"action": "block"}` return, so the message guard would not stop a turn.

## Demo

Runs without model calls, in its own throwaway home:

```bash
python -B scripts/run_demo.py
```

```powershell
.\scripts\run_demo.ps1 -PythonExe 'C:\path\to\Hermes\python.exe'
```

## Contributing

Setup, tests, and the release checklist are in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
