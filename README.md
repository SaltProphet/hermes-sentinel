# Hermes Sentinel 0.1.0

![Hermes Sentinel — Audit · Block · Truncate](assets/hermes-sentinel-start-card.png)

Hermes Sentinel is a plugin that blocks repeated tool calls, filters tool results before they reach the model, and records execution events in a local SQLite ledger.

## Install

Run these commands in a Hermes test profile. The install command uses the published commit verified on Windows.

```bash
hermes plugins install https://github.com/SaltProphet/hermes-sentinel --ref v0.1.0 --no-enable
hermes plugins enable hermes-sentinel
hermes plugins doctor hermes-sentinel
hermes sentinel status
```

Doctor should report four hooks and zero tools. Status should report Sentinel 0.1.0 as active. The [catalog entry](https://github.com/NousResearch/hermes-agent/pull/150321) is pending review.

If you have the release ZIP, extract it into a fresh directory and run `hermes plugins validate <extracted-directory> --install-deps`. The ZIP contains seven files, including this guide. The test suite and verification scripts live in the development workspace.

## What Sentinel does

| Hook | Behavior |
| --- | --- |
| `pre_tool_call` | Blocks the third consecutive call to the same tool with identical normalized arguments in a session. |
| `transform_tool_result` | Redacts matching credentials and truncates oversized tool results before they enter model context. Defaults are 4,000 characters and 100 physical lines, including the omission marker. |
| `pre_llm_call` | Checks outgoing user text and conversation history for matching raw credentials and blocks the model call on a match. |
| `post_tool_call` | Records completion or error, result sizes, and duration when Hermes supplies it. |

## Commands

| Action | Shell | In a Hermes session |
| --- | --- | --- |
| Show status and ledger location | `hermes sentinel status` | |
| Read recent audit events | `hermes sentinel audit` (up to 30) | `/sentinel` or `/sentinel audit` (up to 10) |
| Reset loop detection and preserve audit history | `hermes sentinel reset` | `/sentinel reset` |
| Recreate the ledger and clear the current handler's local loop history | `hermes sentinel clear` | `/sentinel clear` |

Reset advances a shared epoch. Processes using the same database clear their loop history the next time they synchronize.

## Local data

Sentinel inspects the prompt and history text and tool arguments and results supplied by Hermes. Best-effort SQLite writes store event metadata, sanitized argument previews, sizes, and outcomes. The ledger defaults to `sentinel_audit.db` in the Hermes profile directory. Set `HERMES_SENTINEL_DB` to choose a path. Credential detection uses patterns. The plugin makes zero network requests and sends zero telemetry.

## Verification

The pinned commit passed Hermes validation with a safe scan and zero warnings. An isolated Windows install verified discovery, enablement, all four hooks, and runtime version 0.1.0. The release record also includes 14 unit passes, nine live host scenarios with scripted model replies on loopback, and 15 Windows SQLite closure and fallback probes. Linux, commercial model responses, and interactive TUI keystrokes remain unverified.
