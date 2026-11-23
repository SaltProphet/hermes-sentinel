# Hermes Sentinel

![Hermes Sentinel](assets/hermes-sentinel-start-card.png)

Stops runaway tool loops and keeps secrets out of model context.

Sentinel guards Hermes Agent while it runs: it refuses a tool call that keeps
repeating, redacts credential-shaped text and oversized output before the model
sees it, and keeps a local log of what was blocked or allowed. It makes no
network requests and sends no telemetry.

## Install

```bash
hermes plugins install hermes-sentinel
```

## What it does

- **Breaks loops.** A tool call that repeats with the same arguments and the same
  result is blocked. Calls that return something new keep going, so polling a
  deployment or a build still works.
- **Redacts and truncates.** Credential-shaped strings in tool output are
  replaced, and long output is cut to 4,000 characters and 100 lines before the
  model reads it. The model sees a modified result, not the raw one.
- **Guards new messages.** A message containing a credential-shaped string is
  refused before it reaches the model. Earlier history is left alone.
- **Keeps a local log.** Blocked and completed calls are recorded in a local
  SQLite file under your Hermes home, with argument previews redacted.

Pattern matching catches common key formats, not every possible secret.

## Commands

```bash
hermes sentinel status     # storage mode and database path
hermes sentinel audit      # recent events
hermes sentinel reset      # clear loop counters
hermes sentinel clear      # delete audit rows
```

In chat, `/sentinel` shows the log, and `/sentinel reset` or `/sentinel clear`
do the same as above.

## Requirements

Hermes Agent 0.22.6 or newer.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
