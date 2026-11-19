"""
Deterministic security, loop detection, and truncation rules for Hermes Sentinel.
"""
import re
import json
import hashlib
import threading
from typing import Dict, Any, List, Optional, Tuple

# Patterns for secret scanning
SECRET_PATTERNS = [
    (re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}"), "[REDACTED_BEARER_TOKEN]"),
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"), "[REDACTED_ANTHROPIC_KEY]"),
    (re.compile(r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}"), "[REDACTED_OPENAI_KEY]"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), "[REDACTED_GITHUB_PAT]"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"(?:sk|rk)_live_[A-Za-z0-9]{16,}"), "[REDACTED_STRIPE_KEY]"),
    (re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"), "[REDACTED_GITLAB_TOKEN]"),
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
# Polling/status tools legitimately repeat with identical arguments while they
# wait for a state change. Give them a larger budget, but still stop a genuinely
# stuck retry whose output never changes.
DEFAULT_POLL_THRESHOLD = 8
DEFAULT_POLL_TOOL_PATTERN = re.compile(
    r"(?i)(?:^|[_\-. /])(?:status|check|poll|wait|deploy|deployment|rollout|health|ready|progress|watch|describe)(?:$|[_\-. /])"
)
# Even when the output changes, an identical call repeated forever is still a
# loop. This is the hard stop for timestamped/volatile retry output.
DEFAULT_MAX_REPEAT_THRESHOLD = 30


class SentinelRulesEngine:
    def __init__(
        self,
        max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
        max_output_lines: int = DEFAULT_MAX_OUTPUT_LINES,
        loop_threshold: int = DEFAULT_LOOP_THRESHOLD,
        poll_threshold: int = DEFAULT_POLL_THRESHOLD,
        max_repeat_threshold: int = DEFAULT_MAX_REPEAT_THRESHOLD,
        poll_tool_pattern: Any = DEFAULT_POLL_TOOL_PATTERN,
    ):
        self.max_output_chars = max_output_chars
        self.max_output_lines = max_output_lines
        self.loop_threshold = max(1, int(loop_threshold))
        self.poll_threshold = max(1, int(poll_threshold))
        self.max_repeat_threshold = min(max(1, int(max_repeat_threshold)), 500)
        self._history_limit = max(50, self.max_repeat_threshold + 1)
        if isinstance(poll_tool_pattern, str):
            poll_tool_pattern = re.compile(poll_tool_pattern)
        self.poll_tool_pattern = poll_tool_pattern
        # Track history per session_id:
        # (tool_name, normalized_args, status, result_digest, tool_call_id)
        self.call_history: Dict[str, List[Tuple[str, str, str, Optional[str], Optional[str]]]] = {}
        self.last_seen_epoch: int = 0
        # Hermes may invoke hooks from worker threads. History mutations must not
        # interleave, or a result could be paired with another call's record.
        self._lock = threading.Lock()

    def sync_epoch(self, db_epoch: int):
        """Synchronize loop counters with the persistent reset epoch when available."""
        with self._lock:
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

    def _threshold_for(self, tool_name: str, normalized_args: str = "") -> int:
        """Polling/status calls get a larger budget than ordinary tools."""
        try:
            haystack = f"{tool_name or ''} {normalized_args or ''}"
            if self.poll_tool_pattern is not None and self.poll_tool_pattern.search(haystack):
                return self.poll_threshold
        except Exception:
            pass
        return self.loop_threshold

    def _digest_result(self, result: Any) -> str:
        """Hash the observed result without retaining its contents."""
        try:
            canonical = json.dumps(result, sort_keys=True, default=str)
        except Exception:
            canonical = str(result)
        return hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()

    def _trailing_match_count(
        self,
        history: List[Tuple[str, str, str, Optional[str], Optional[str]]],
        tool_name: str,
        normalized_args: str,
        limit: int,
    ) -> int:
        """Count the trailing run of calls with the same tool and arguments."""
        count = 0
        for item in reversed(history):
            if item[0] != tool_name or item[1] != normalized_args:
                break
            count += 1
            if count >= limit:
                break
        return count

    def check_loop(self, session_id: str, tool_name: str, args: Any) -> Optional[str]:
        """Detect a stuck retry while allowing repeats that return new output.

        A call is a loop when the same tool and arguments repeat and the
        observed results are identical (or have not been recorded). Repeated
        calls whose result changed are treated as progress, which covers
        deliberate polling such as waiting for a deployment to finish. A hard
        cap still stops an endless identical-argument loop even when volatile
        output keeps changing.
        """
        normalized_args = self._normalize_args(args)
        with self._lock:
            history = self.call_history.setdefault(session_id, [])

            # Hard cap: output changes do not excuse an unbounded identical call.
            hard_cap = self.max_repeat_threshold
            if hard_cap > 1:
                trailing = self._trailing_match_count(
                    history, tool_name, normalized_args, hard_cap - 1
                )
                if trailing >= (hard_cap - 1):
                    return (
                        f"Sentinel Loop Trap: Tool '{tool_name}' invoked {hard_cap} "
                        "consecutive times with identical parameters (hard repeat cap)."
                    )

            threshold = self._threshold_for(tool_name, normalized_args)
            window = history[-(threshold - 1) :] if threshold > 1 else []
            recent = [
                item
                for item in window
                if item[0] == tool_name and item[1] == normalized_args
            ]
            if len(recent) < (threshold - 1):
                return None

            digests = [item[3] for item in recent]
            if all(digest is not None for digest in digests) and len(set(digests)) > 1:
                # The output changed between calls, so this repeat is making
                # progress (for example, a deployment status poll).
                return None

            detail = (
                "no completion record"
                if any(d is None for d in digests)
                else "identical results"
            )
            return (
                f"Sentinel Loop Trap: Tool '{tool_name}' invoked {threshold} consecutive "
                f"times with identical parameters and {detail}."
            )

    def record_call(
        self,
        session_id: str,
        tool_name: str,
        args: Any,
        status: str = "dispatched",
        tool_call_id: Optional[str] = None,
    ):
        normalized_args = self._normalize_args(args)
        tool_call_id = tool_call_id or None
        with self._lock:
            history = self.call_history.setdefault(session_id, [])
            history.append((tool_name, normalized_args, status, None, tool_call_id))
            # Keep ring buffer per session and bound total tracked sessions
            if len(history) > self._history_limit:
                history.pop(0)
            if len(self.call_history) > 200:
                oldest_key = next(iter(self.call_history))
                if oldest_key != session_id:
                    del self.call_history[oldest_key]

    def record_result(
        self,
        session_id: str,
        tool_name: str,
        args: Any,
        result: Any,
        status: str = "completed",
        tool_call_id: Optional[str] = None,
        overwrite: bool = False,
    ):
        """Attach a result digest to its dispatched call for progress detection.

        Best-effort: malformed or concurrently trimmed history must never break
        a caller's result pipeline.
        """
        try:
            normalized_args = self._normalize_args(args)
            tool_call_id = tool_call_id or None
            digest = self._digest_result(result)
            with self._lock:
                history = self.call_history.get(session_id)
                if not history:
                    return

                matching = [
                    index
                    for index, item in enumerate(history)
                    if item[0] == tool_name and item[1] == normalized_args
                ]
                if not matching:
                    return

                # A known tool_call_id is authoritative: a later transform may
                # overwrite the post hook's raw digest for the same call.
                if tool_call_id is not None:
                    for index in matching:
                        item = history[index]
                        if item[4] == tool_call_id:
                            if item[3] is None or overwrite:
                                history[index] = (
                                    item[0], item[1], status, digest, tool_call_id
                                )
                            return
                    # Legacy/pre-hook path may not have supplied an ID.
                    for index in matching:
                        item = history[index]
                        if item[3] is None and item[4] in (None, ""):
                            history[index] = (
                                item[0], item[1], status, digest, tool_call_id
                            )
                            return
                    return

                # Without an ID, pair results with pending calls oldest-first so
                # concurrent identical calls stay aligned.
                for index in matching:
                    item = history[index]
                    if item[3] is None:
                        history[index] = (item[0], item[1], status, digest, item[4])
                        return

                # No pending entry: only the most recent call can be the current
                # call. Do not overwrite an older completed entry.
                if overwrite:
                    index = len(history) - 1
                    item = history[index]
                    if item[0] == tool_name and item[1] == normalized_args:
                        history[index] = (item[0], item[1], status, digest, item[4])
        except Exception:
            # Loop/progress bookkeeping is best-effort. A failure here must not
            # prevent the transform hook from returning sanitized output.
            return

    def reset_session(self, session_id: str):
        """Clears memory history for a session."""
        with self._lock:
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
