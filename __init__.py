"""
Hermes Sentinel directory entrypoint.
Relative imports keep state under Hermes's per-profile module namespace and
allow unload/reload to replace the implementation and its ledger together.
"""
from .hermes_sentinel import (
    register,
    on_pre_llm_call,
    on_pre_tool_call,
    on_post_tool_call,
    on_transform_tool_result,
    rules_engine,
    audit_ledger,
    setup_sentinel_parser,
    handle_sentinel_cli,
    handle_sentinel_slash,
)

__all__ = [
    "register",
    "on_pre_llm_call",
    "on_pre_tool_call",
    "on_post_tool_call",
    "on_transform_tool_result",
    "rules_engine",
    "audit_ledger",
    "setup_sentinel_parser",
    "handle_sentinel_cli",
    "handle_sentinel_slash",
]
