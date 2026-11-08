#!/usr/bin/env python3
"""Deterministic Sentinel 0.1.1 demo in one disposable home, without user config."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile


def build_demo_environment(profile_dir: Path) -> dict:
    # Only runtime/OS plumbing is inherited. No model, messaging or other
    # credentials are needed: this demo makes no LLM or network requests.
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "TMPDIR", "PYTHONPATH"}
    env = {k: v for k, v in os.environ.items() if k.upper() in allowed}
    env.update({
        "HERMES_HOME": str(profile_dir),
        "HOME": str(profile_dir),
        "USERPROFILE": str(profile_dir),
        "LOCALAPPDATA": str(profile_dir),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
    })
    return env


class TemporaryDemoProfile:
    """Own only a newly created temporary directory, never a registered profile."""

    def __init__(self):
        self.profile_dir = None
        self.db_path = None
        self.env = {}

    def __enter__(self):
        try:
            self.profile_dir = Path(tempfile.mkdtemp(prefix="hermes-sentinel-demo-"))
            self.db_path = self.profile_dir / "plugin-data/hermes-sentinel/sentinel_audit.db"
            self.env = build_demo_environment(self.profile_dir)
            return self
        except BaseException:
            self.cleanup()
            raise

    def cleanup(self):
        if self.profile_dir is not None and self.profile_dir.exists():
            # Surface failures instead of claiming deletion after ignore_errors.
            shutil.rmtree(self.profile_dir)

    def __exit__(self, exc_type, exc_value, traceback):
        self.cleanup()
        return False


def _run_worker() -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from hermes_sentinel import (
        audit_ledger, handle_sentinel_cli, handle_sentinel_slash,
        on_pre_llm_call, on_pre_tool_call, on_post_tool_call, on_transform_tool_result,
    )

    try:
        if audit_ledger.storage != "persistent":
            raise RuntimeError("Demo requires its disposable audit database to be writable")
        print(f"[Step 1] Isolated temporary profile active: {os.environ['HERMES_HOME']}")
        print("         Default profile configuration and credentials copied: False")
        # Generated all-zero fixtures exercise the recognizers without shipping
        # strings that look like accidentally committed live credentials.
        synthetic_openai = "sk-" + "0" * 32
        raw = "token: " + synthetic_openai + "\n" + "\n".join(f"log line {i}" for i in range(150))
        transformed = on_transform_tool_result(tool_name="terminal", result=raw, session_id="demo")
        assert "[REDACTED_OPENAI_KEY]" in transformed
        assert len(transformed) <= 4000 and len(transformed.splitlines()) <= 100
        on_post_tool_call(tool_name="terminal", result=transformed, session_id="demo", duration_ms=8.4)
        print("[Step 2] Tool output secret redacted; output bounded to 4,000 characters and 100 lines.")

        call = {"tool_name": "read_file", "args": {"path": "probe.txt"}, "session_id": "demo"}
        assert on_pre_tool_call(**call) is None
        assert on_pre_tool_call(**call) is None
        assert on_pre_tool_call(**call)["action"] == "block"
        print("[Step 3] Identical tool call blocked on attempt 3.")
        print(f"[Step 4] /sentinel reset -> {handle_sentinel_slash('reset')}")
        assert on_pre_tool_call(**call) is None

        secret = "ghp_" + "0" * 36
        assert on_pre_llm_call(user_message=secret)["action"] == "block"
        history = [{"role": "user", "content": secret}]
        handle_sentinel_cli(["reset"])
        for text in ("Continue after reset", "What is next?"):
            assert on_pre_llm_call(user_message=text, conversation_history=history) is None
        assert history[0]["content"] == secret
        synthetic_aws = "AKIA" + "0" * 16
        assert on_pre_llm_call(user_message=synthetic_aws, conversation_history=history)["action"] == "block"
        assert on_pre_llm_call(user_message=secret, conversation_history=history)["action"] == "block"
        print("[Step 5] Clean turns allowed with old credentials in unchanged history; new/repeated credentials blocked.")
        print("[Step 6] Audit summary:")
        handle_sentinel_cli(["audit"])
        return 0
    finally:
        audit_ledger.close()


def run_demo_sequence() -> int:
    profile = TemporaryDemoProfile()
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}

    def interrupted(signum, frame):
        raise SystemExit(128 + signum)

    try:
        for sig in previous:
            signal.signal(sig, interrupted)
        with profile:
            subprocess.run(
                [sys.executable, "-B", str(Path(__file__).resolve()), "--worker"],
                env=profile.env, cwd=Path(__file__).resolve().parents[1],
                check=True, timeout=60,
            )
        return 0
    finally:
        try:
            profile.cleanup()
            if profile.profile_dir is not None:
                print(f"[Cleanup] Temporary profile deleted: {not profile.profile_dir.exists()}")
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)


if __name__ == "__main__":
    sys.exit(_run_worker() if sys.argv[1:] == ["--worker"] else run_demo_sequence())
