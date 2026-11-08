"""
Hermes Sentinel Plugin Entrypoint.
Registers pre_llm_call, pre_tool_call, post_tool_call, transform_tool_result hooks and CLI commands.
"""
import sys
from typing import Any, Dict, List, Optional
from .rules import SentinelRulesEngine
from .audit import AuditLedger

# Singletons for plugin lifecycle
rules_engine = SentinelRulesEngine()
audit_ledger = AuditLedger()


def on_pre_llm_call(
    session_id: str = "default",
    user_message: str = "",
    conversation_history: Any = None,
    messages: Any = None,
    **kwargs
) -> Optional[Dict[str, str]]:
    """Block credential-shaped strings in the new message; leave history untouched.

    Hermes 0.22.6+ honors the pre_llm_call veto before inference.
    """
    msg_text = str(user_message or "")
    _, had_secret = rules_engine.scan_and_redact(msg_text)
    if had_secret:
        audit_ledger.record_event(
            session_id=session_id,
            event_type="pre_llm_call",
            action="BLOCKED",
            reason="Blocked turn: detected credential-shaped text in the new user message.",
            details={
                "user_message_length": len(msg_text),
                "history_scanned": False,
            },
        )
        return {
            "action": "block",
            "message": "[Sentinel] Outbound turn blocked: detected exposed credentials in the new user message.",
        }
    return None

def on_pre_tool_call(
    tool_name: str = "",
    args: Any = None,
    tool_args: Any = None,
    session_id: str = "default",
    **kwargs
) -> Optional[Dict[str, str]]:
    """
    Hook: pre_tool_call.
    Accepts both Hermes core keyword 'args' and legacy 'tool_args'.
    Intercepts and blocks identical repetitive tool loops on attempt 3.
    """
    rules_engine.sync_epoch(audit_ledger.get_reset_epoch())

    actual_args = args if args is not None else tool_args
    # Redact full argument representation FIRST, then slice to 200 chars so boundary secrets never leak
    full_args_str = str(actual_args) if actual_args is not None else ""
    redacted_full_args, _ = rules_engine.scan_and_redact(full_args_str)
    sanitized_args_preview = redacted_full_args[:200]

    loop_error = rules_engine.check_loop(session_id, tool_name, actual_args)
    if loop_error:
        audit_ledger.record_event(
            session_id=session_id,
            event_type="pre_tool_call",
            action="BLOCKED",
            tool_name=tool_name,
            reason=loop_error,
            details={"args": sanitized_args_preview},
        )
        return {"action": "block", "message": f"[Sentinel] Execution halted: {loop_error}"}

    # Record dispatch attempt
    rules_engine.record_call(session_id, tool_name, actual_args, status="dispatched")
    audit_ledger.record_event(
        session_id=session_id,
        event_type="pre_tool_call",
        action="ALLOWED",
        tool_name=tool_name,
        details={"args": sanitized_args_preview},
    )
    return None

def on_transform_tool_result(
    tool_name: str = "",
    args: Any = None,
    tool_args: Any = None,
    result: Any = None,
    tool_result: Any = None,
    session_id: str = "default",
    **kwargs
) -> str:
    """
    Hook: transform_tool_result.
    Official Hermes hook that replaces the tool result string BEFORE it enters LLM context.
    Performs deterministic secret redaction and middle-out context truncation.
    """
    raw_res = result if result is not None else tool_result
    result_str = str(raw_res) if raw_res is not None else ""

    # 1. Redact credentials that may have appeared in stdout/stderr
    clean_str, had_secret = rules_engine.scan_and_redact(result_str)

    # 2. Context protection: strictly enforce line and character bounds
    final_output, was_truncated = rules_engine.truncate_tool_output(clean_str)

    action = "RECORDED"
    if had_secret and was_truncated:
        action = "REDACTED_AND_TRUNCATED"
    elif had_secret:
        action = "REDACTED"
    elif was_truncated:
        action = "TRUNCATED"

    if had_secret or was_truncated:
        audit_ledger.record_event(
            session_id=session_id,
            event_type="transform_tool_result",
            action=action,
            tool_name=tool_name,
            reason=f"Chars: {len(result_str)} -> {len(final_output)}",
            details={"truncated": was_truncated, "redacted": had_secret},
        )

    return final_output

def on_post_tool_call(
    tool_name: str = "",
    args: Any = None,
    tool_args: Any = None,
    result: Any = None,
    tool_result: Any = None,
    session_id: str = "default",
    duration_ms: Optional[float] = None,
    **kwargs
) -> None:
    """
    Hook: post_tool_call.
    Observer hook that records tool completion outcomes, output size, and execution status to the audit ledger.
    """
    raw_res = result if result is not None else tool_result
    result_str = str(raw_res) if raw_res is not None else ""

    is_error = False
    if isinstance(raw_res, dict) and raw_res.get("error"):
        is_error = True
    elif result_str.lstrip().startswith(("Error:", "Traceback", "[ERROR]")):
        is_error = True

    action = "ERROR_OBSERVED" if is_error else "COMPLETED"
    details: Dict[str, Any] = {
        "result_chars": len(result_str),
        "result_lines": len(result_str.splitlines()),
        "is_error": is_error,
    }
    if duration_ms is not None:
        details["duration_ms"] = duration_ms

    audit_ledger.record_event(
        session_id=session_id,
        event_type="post_tool_call",
        action=action,
        tool_name=tool_name,
        reason=f"Completed ({len(result_str)} chars)",
        details=details,
    )

# --- CLI and Slash Command Handlers ---

def setup_sentinel_parser(parser):
    """Configures argparse subparser for `hermes sentinel` CLI."""
    parser.add_argument(
        "subcommand",
        nargs="?",
        default="status",
        choices=["status", "audit", "clear", "reset"],
        help="Sentinel subcommand (status, audit, clear, reset)",
    )

def handle_sentinel_cli(args):
    """Executes `hermes sentinel` CLI command."""
    if hasattr(args, "subcommand"):
        subcmd = args.subcommand or "status"
    elif isinstance(args, list) and args:
        subcmd = args[0]
    elif isinstance(args, str):
        subcmd = args
    else:
        subcmd = "status"

    if subcmd == "audit":
        print(audit_ledger.render_markdown_summary(limit=30))
        return 0
    elif subcmd == "clear":
        if audit_ledger.clear():
            rules_engine.call_history.clear()
            print("Sentinel audit database cleared.")
            return 0
        print("Sentinel audit storage unavailable; database was not cleared.", file=sys.stderr)
        return 1
    elif subcmd == "reset":
        new_epoch = audit_ledger.bump_reset_epoch()
        rules_engine.sync_epoch(new_epoch)
        rules_engine.call_history.clear()
        audit_ledger.record_event(
            session_id="cli",
            event_type="cli_command",
            action="RESET",
            reason=f"Loop counters reset (epoch {new_epoch})",
        )
        scope = "shared database" if audit_ledger.storage == "persistent" and new_epoch else "this process only"
        print(f"Sentinel loop tripwires reset ({scope}; epoch {new_epoch}).")
        return 0
    else:
        events = audit_ledger.get_recent_events(limit=5)
        print("Hermes Sentinel v0.1.1 Active")
        print(f"Database: {audit_ledger.db_path}")
        print(f"Audit storage: {audit_ledger.storage}")
        print(f"Recent events logged: {len(events)}")
        print("\nCommands:")
        print("  hermes sentinel audit   - View execution audit log")
        print("  hermes sentinel clear   - Reset SQLite audit database")
        print("  hermes sentinel reset   - Reset loop tripwires (shared when persistent storage works)")
        return 0

def handle_sentinel_slash(arg1: Any = "", arg2: Any = "", **kwargs) -> str:
    """
    Handles in-session slash command `/sentinel [audit|reset|clear]`.
    Supports both calling conventions:
      - handler(args_str) where Hermes passes "reset" as the first positional parameter
      - handler(session, text) where session is first and text is second
    """
    tokens: List[str] = []
    for candidate in (
        arg1 if isinstance(arg1, str) else None,
        arg2 if isinstance(arg2, str) else None,
        kwargs.get("args") if isinstance(kwargs.get("args"), str) else None,
        kwargs.get("text") if isinstance(kwargs.get("text"), str) else None,
        kwargs.get("command_args") if isinstance(kwargs.get("command_args"), str) else None,
    ):
        if candidate and candidate.strip():
            tokens.extend(candidate.strip().lower().split())

    if "reset" in tokens:
        new_epoch = audit_ledger.bump_reset_epoch()
        rules_engine.sync_epoch(new_epoch)
        rules_engine.call_history.clear()
        audit_ledger.record_event(
            session_id="slash",
            event_type="slash_command",
            action="RESET",
            reason=f"Loop counters reset via /sentinel reset (epoch {new_epoch})",
        )
        scope = "shared database" if audit_ledger.storage == "persistent" and new_epoch else "this process only"
        return f"Sentinel loop counters reset ({scope}; epoch {new_epoch})."
    if "clear" in tokens:
        if audit_ledger.clear():
            rules_engine.call_history.clear()
            return "Sentinel audit database cleared."
        return "Sentinel audit storage unavailable; database was not cleared."

    return audit_ledger.render_markdown_summary(limit=10)

def register(ctx):
    """Hermes plugin entrypoint called once on startup."""
    if hasattr(ctx, "on_unload"):
        ctx.on_unload(audit_ledger.close)
    # Register lifecycle hooks
    ctx.register_hook("pre_llm_call", on_pre_llm_call)
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    ctx.register_hook("transform_tool_result", on_transform_tool_result)

    # Register CLI command (name, help, setup_fn, handler_fn)
    if hasattr(ctx, "register_cli_command"):
        try:
            ctx.register_cli_command(
                "sentinel",
                "Hermes Sentinel runtime circuit breaker and audit ledger",
                setup_sentinel_parser,
                handle_sentinel_cli,
            )
        except TypeError:
            try:
                ctx.register_cli_command("sentinel", handle_sentinel_cli)
            except Exception:
                pass

    # Register in-chat slash command `/sentinel`
    if hasattr(ctx, "register_command"):
        try:
            ctx.register_command("sentinel", handle_sentinel_slash, "View or reset Hermes Sentinel (/sentinel [reset])")
        except Exception:
            pass
