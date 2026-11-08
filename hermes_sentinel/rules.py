"""
Deterministic security, loop detection, and truncation rules for Hermes Sentinel.
"""
import re
import json
from typing import Dict, Any, List, Optional, Tuple

# Patterns for secret scanning
SECRET_PATTERNS = [
    (re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}"), "[REDACTED_BEARER_TOKEN]"),
    (re.compile(r"sk-[a-zA-Z0-9]{32,}"), "[REDACTED_OPENAI_KEY]"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "[REDACTED_GITHUB_PAT]"),
    (re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"(?i)(?:api_key|apikey|secret|password|token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{16,})['\"]?"), "[REDACTED_SECRET]"),
]

# Strict output bounds
DEFAULT_MAX_OUTPUT_CHARS = 4000
DEFAULT_MAX_OUTPUT_LINES = 100
DEFAULT_LOOP_THRESHOLD = 3  # Block if identical tool + args called N times consecutively


class SentinelRulesEngine:
    def __init__(
        self,
        max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
        max_output_lines: int = DEFAULT_MAX_OUTPUT_LINES,
        loop_threshold: int = DEFAULT_LOOP_THRESHOLD,
    ):
        self.max_output_chars = max_output_chars
        self.max_output_lines = max_output_lines
        self.loop_threshold = loop_threshold
        # Track history per session_id: list of (tool_name, normalized_args, status)
        self.call_history: Dict[str, List[Tuple[str, str, str]]] = {}
        self.last_seen_epoch: int = 0

    def sync_epoch(self, db_epoch: int):
        """Synchronize loop counters with the persistent reset epoch when available."""
        if db_epoch > self.last_seen_epoch:
            self.call_history.clear()
            self.last_seen_epoch = db_epoch

    def _normalize_args(self, args: Any) -> str:
        """Canonicalizes nested dicts/lists for deterministic comparison."""
        try:
            return json.dumps(args, sort_keys=True, default=str)
        except Exception:
            return str(args)

    def scan_and_redact(self, text: str) -> Tuple[str, bool]:
        """Scans string for sensitive keys/credentials and replaces with redactions."""
        if not text:
            return "", False
        redacted = text
        found = False
        for pattern, replacement in SECRET_PATTERNS:
            if pattern.search(redacted):
                found = True
                redacted = pattern.sub(replacement, redacted)
        return redacted, found

    def check_loop(self, session_id: str, tool_name: str, args: Any) -> Optional[str]:
        """Detects if an agent is stuck calling the same tool with identical args repeatedly."""
        history = self.call_history.setdefault(session_id, [])
        normalized_args = self._normalize_args(args)

        # Check trailing identical calls
        recent = [
            item
            for item in history[-(self.loop_threshold - 1) :]
            if item[0] == tool_name and item[1] == normalized_args
        ]
        if len(recent) >= (self.loop_threshold - 1):
            return f"Sentinel Loop Trap: Tool '{tool_name}' invoked {self.loop_threshold} consecutive times with identical parameters."

        return None

    def record_call(self, session_id: str, tool_name: str, args: Any, status: str = "dispatched"):
        history = self.call_history.setdefault(session_id, [])
        normalized_args = self._normalize_args(args)
        history.append((tool_name, normalized_args, status))
        # Keep ring buffer per session and bound total tracked sessions
        if len(history) > 50:
            history.pop(0)
        if len(self.call_history) > 200:
            oldest_key = next(iter(self.call_history))
            if oldest_key != session_id:
                del self.call_history[oldest_key]

    def reset_session(self, session_id: str):
        """Clears memory history for a session."""
        if session_id in self.call_history:
            del self.call_history[session_id]

    def truncate_tool_output(self, content: str) -> Tuple[str, bool]:
        """
        Truncates excessively long tool returns to preserve local model context.
        Strictly guarantees BOTH:
          - len(output.splitlines()) <= self.max_output_lines
          - len(output) <= self.max_output_chars
        for ALL positive values of max_output_lines (including 1, 2) and max_output_chars (including <= 60).
        """
        if not content:
            return "", False

        max_lines = max(0, self.max_output_lines)
        max_chars = max(0, self.max_output_chars)

        if max_lines == 0 or max_chars == 0:
            return "", True

        lines = content.splitlines()
        needs_line_trunc = len(lines) > max_lines
        needs_char_trunc = len(content) > max_chars

        if not needs_line_trunc and not needs_char_trunc:
            return content, False

        working_content = content

        # Phase 1: Line truncation
        if needs_line_trunc:
            if max_lines == 1:
                working_content = lines[0]
            elif max_lines == 2:
                omitted_count = len(lines) - 1
                marker_line = f"[... Sentinel: Truncated {omitted_count} lines ...]"
                working_content = f"{lines[0]}\n{marker_line}"
            else:
                usable_lines = max_lines - 1
                head_count = usable_lines // 2
                tail_count = usable_lines - head_count
                head_lines = lines[:head_count]
                tail_lines = lines[-tail_count:] if tail_count > 0 else []
                omitted_count = len(lines) - (len(head_lines) + len(tail_lines))
                marker_line = f"[... Sentinel: Truncated {omitted_count} lines to protect context ...]"
                working_content = "\n".join(head_lines + [marker_line] + tail_lines)

        # Phase 2: Character truncation
        if len(working_content) > max_chars:
            full_marker = f" [... Sentinel: Truncated {len(content) - max_chars} chars ...] "
            short_marker = " [...] "
            if max_chars >= len(full_marker) + 4:
                usable_chars = max_chars - len(full_marker)
                head_chars = usable_chars // 2
                tail_chars = usable_chars - head_chars
                working_content = working_content[:head_chars] + full_marker + working_content[-tail_chars:]
            elif max_chars >= len(short_marker) + 2:
                usable_chars = max_chars - len(short_marker)
                head_chars = usable_chars // 2
                tail_chars = usable_chars - head_chars
                working_content = working_content[:head_chars] + short_marker + working_content[-tail_chars:]
            elif max_chars > 3:
                working_content = working_content[: max_chars - 3] + "..."
            else:
                working_content = working_content[:max_chars]

        # Final invariant guard: ensure neither line nor char limit is ever exceeded
        final_lines = working_content.splitlines()
        if len(final_lines) > max_lines:
            working_content = "\n".join(final_lines[:max_lines])
        if len(working_content) > max_chars:
            working_content = working_content[:max_chars]

        return working_content, True
