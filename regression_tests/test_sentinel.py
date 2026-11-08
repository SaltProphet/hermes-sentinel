"""Hook, loop, redaction, truncation, CLI and directory-loader contracts."""
import argparse
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import hermes_sentinel as sentinel
from hermes_sentinel.audit import AuditLedger
from hermes_sentinel.rules import SentinelRulesEngine


class TestHermesSentinel(unittest.TestCase):
    def setUp(self):
        self.rules = SentinelRulesEngine()
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        self.path = str(Path(self.home.name) / "audit.db")
        self.ledger = AuditLedger(self.path)
        self.addCleanup(self.ledger.close)
        self.ledger_patch = patch.object(sentinel, "audit_ledger", self.ledger)
        self.rules_patch = patch.object(sentinel, "rules_engine", self.rules)
        self.ledger_patch.start()
        self.rules_patch.start()
        self.addCleanup(self.ledger_patch.stop)
        self.addCleanup(self.rules_patch.stop)

    def test_secret_redaction(self):
        text = "Keys: sk-abcdef1234567890abcdef1234567890 and Bearer eyJhbGciOiJIUzI1NiJ9.test and AKIAIOSFODNN7EXAMPLE"
        cleaned, found = self.rules.scan_and_redact(text)
        self.assertTrue(found)
        for marker in ("OPENAI_KEY", "BEARER_TOKEN", "AWS_KEY"):
            self.assertIn(f"[REDACTED_{marker}]", cleaned)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", cleaned)

    def test_private_key_and_generic_password_redaction(self):
        for text in ("-----BEGIN PRIVATE KEY-----\nsample\n-----END PRIVATE KEY-----", "password=abcdefghijklmnop"):
            cleaned, found = self.rules.scan_and_redact(text)
            self.assertTrue(found)
            self.assertNotEqual(cleaned, text)

    def test_output_truncation_strict_char_and_line_bounds(self):
        for chars, lines in [(4000, 100), (20, 100), (5, 100), (3, 100), (4000, 1), (4000, 2), (0, 100), (4000, 0)]:
            with self.subTest(chars=chars, lines=lines):
                rules = SentinelRulesEngine(max_output_chars=chars, max_output_lines=lines)
                output, truncated = rules.truncate_tool_output("\n".join(f"Line {n}: " + "x" * 1000 for n in range(105)))
                self.assertTrue(truncated)
                self.assertLessEqual(len(output), chars)
                self.assertLessEqual(len(output.splitlines()), lines)

    def test_short_output_is_unchanged(self):
        self.assertEqual(self.rules.truncate_tool_output("line one\nline two"), ("line one\nline two", False))

    def test_loop_detection_and_canonical_args(self):
        for args in ({"b": 2, "a": {"y": 1, "x": 2}}, {"a": {"x": 2, "y": 1}, "b": 2}):
            self.assertIsNone(self.rules.check_loop("session", "read_file", args))
            self.rules.record_call("session", "read_file", args)
        self.assertIn("Sentinel Loop Trap", self.rules.check_loop("session", "read_file", {"b": 2, "a": {"y": 1, "x": 2}}))
        self.assertIsNone(self.rules.check_loop("other", "read_file", {"b": 2}))
        self.rules.record_call("session", "other_tool", {})
        self.assertIsNone(self.rules.check_loop("session", "read_file", {"b": 2, "a": {"y": 1, "x": 2}}))

    def test_cross_process_cli_reset_epoch(self):
        call = {"tool_name": "terminal", "args": {"cmd": "echo 1"}, "session_id": "agent"}
        sentinel.on_pre_tool_call(**call)
        sentinel.on_pre_tool_call(**call)
        code = (
            "import hermes_sentinel as s; from hermes_sentinel.audit import AuditLedger; "
            f"s.audit_ledger = AuditLedger({self.path!r}); "
            "raise SystemExit(s.handle_sentinel_cli(['reset']))"
        )
        result = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.ledger.get_reset_epoch(), 1)
        self.assertIsNone(sentinel.on_pre_tool_call(**call))

    def test_slash_command_reset_first_param_and_second_param(self):
        for params in [("reset",), ({"id": "session"}, "reset")]:
            sentinel.on_pre_tool_call(tool_name="read_file", args={})
            sentinel.on_pre_tool_call(tool_name="read_file", args={})
            self.assertIn("reset", sentinel.handle_sentinel_slash(*params).lower())
            self.assertIsNone(sentinel.on_pre_tool_call(tool_name="read_file", args={}))

    def test_isolated_root_entrypoint_loading(self):
        root = Path(__file__).resolve().parents[1]
        code = (
            "import os, sys, importlib.util; "
            f"p = {str(root)!r}; "
            "sys.path = [x for x in sys.path if os.path.abspath(x) != os.path.abspath(p)]; "
            f"spec = importlib.util.spec_from_file_location('plugin_test_mod', {str(root / '__init__.py')!r}); "
            "mod = importlib.util.module_from_spec(spec); sys.modules[spec.name] = mod; spec.loader.exec_module(mod); "
            "assert callable(mod.register)"
        )
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        env.pop("PYTHONPATH", None)
        result = subprocess.run([sys.executable, "-B", "-c", code], cwd=self.home.name, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_boundary_secret_scrubbing_before_slice(self):
        sentinel.on_pre_tool_call(tool_name="curl", args={"data": "a" * 185 + "sk-1234567890abcdef1234567890abcdef1234"})
        events = self.ledger.get_recent_events(1)
        self.assertEqual(len(events), 1)
        self.assertNotIn("sk-1234", events[0]["details"])

    def test_post_tool_call_records_outcomes(self):
        sentinel.on_post_tool_call(tool_name="terminal", result="files", duration_ms=12.5)
        event = self.ledger.get_recent_events(1)[0]
        self.assertEqual(event["action"], "COMPLETED")
        self.assertIn('"duration_ms": 12.5', event["details"])
        for result in ("Error: command failed", {"error": "command failed"}):
            sentinel.on_post_tool_call(tool_name="terminal", result=result)
            self.assertEqual(self.ledger.get_recent_events(1)[0]["action"], "ERROR_OBSERVED")

    def test_transform_tool_result_hook_and_legacy_keywords(self):
        raw = "api_key = 'sk-12345678901234567890123456789012'\n" + "data\n" * 200
        output = sentinel.on_transform_tool_result(tool_name="read_file", tool_args={}, tool_result=raw)
        self.assertNotIn("sk-12345678901234567890123456789012", output)
        self.assertIn("[REDACTED_OPENAI_KEY]", output)
        self.assertLessEqual(len(output), 4000)
        self.assertLessEqual(len(output.splitlines()), 100)
        sentinel.on_pre_tool_call(tool_name="read_file", tool_args={"path": "a"})
        self.assertIn('path', self.ledger.get_recent_events(1)[0]["details"])

    def test_cli_parser_and_clear(self):
        parser = argparse.ArgumentParser()
        sentinel.setup_sentinel_parser(parser)
        self.assertEqual(parser.parse_args([]).subcommand, "status")
        self.assertEqual(parser.parse_args(["reset"]).subcommand, "reset")
        self.ledger.record_event("test", "test", "OK")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(sentinel.handle_sentinel_cli(["clear"]), 0)
        self.assertEqual(self.ledger.get_recent_events(), [])
        self.ledger.record_event("test", "test", "OK")
        self.assertIn("cleared", sentinel.handle_sentinel_slash("clear"))
        self.assertEqual(self.ledger.get_recent_events(), [])


if __name__ == "__main__":
    unittest.main()
