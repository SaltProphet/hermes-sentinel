"""Storage and turn regressions from the maintainer review."""
import copy
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import hermes_constants
import hermes_sentinel as sentinel
from hermes_sentinel.audit import AuditLedger
from hermes_sentinel.rules import SentinelRulesEngine


def dispose(ledger):
    close = getattr(ledger, "close", None)
    if close:
        close()


class AuditRegressions(unittest.TestCase):
    def ledger(self, *args, **kwargs):
        ledger = AuditLedger(*args, **kwargs)
        self.addCleanup(dispose, ledger)
        return ledger

    def test_context_override_owns_database_and_legacy_env_is_ignored(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root) / "profile"
            token = hermes_constants.set_hermes_home_override(home)
            try:
                with patch.dict("os.environ", {"HERMES_SENTINEL_DB": str(Path(root) / "wrong.db")}):
                    ledger = self.ledger()
                    ledger.record_event("test", "test", "OK")
                expected = home / "plugin-data/hermes-sentinel/sentinel_audit.db"
                self.assertEqual(Path(ledger.db_path), expected)
                self.assertTrue(expected.is_file())
                self.assertFalse((Path(root) / "wrong.db").exists())
                self.assertEqual(ledger.get_recent_events()[0]["action"], "OK")
                dispose(ledger)
            finally:
                hermes_constants.reset_hermes_home_override(token)

    def test_unusable_home_falls_back_to_retained_memory_not_temp_files(self):
        with tempfile.TemporaryDirectory() as root:
            blocker = Path(root) / "not-a-directory"
            blocker.write_text("keep", encoding="utf-8")
            with patch.object(hermes_constants, "get_hermes_home", return_value=blocker):
                ledger = self.ledger()
            self.assertEqual(ledger.db_path, ":memory:")
            ledger.record_event("test", "test", "FIRST")
            ledger.record_event("test", "test", "SECOND")
            self.assertEqual([e["action"] for e in ledger.get_recent_events()], ["SECOND", "FIRST"])
            self.assertEqual(ledger.bump_reset_epoch(), 1)
            self.assertEqual(ledger.get_reset_epoch(), 1)
            self.assertEqual(list(Path(root).iterdir()), [blocker])

    def test_resolver_failure_uses_memory(self):
        with patch.object(hermes_constants, "get_hermes_home", side_effect=OSError("home unavailable")):
            ledger = self.ledger()
        self.assertEqual(ledger.db_path, ":memory:")
        ledger.record_event("test", "test", "OK")
        self.assertEqual(len(ledger.get_recent_events()), 1)

    def test_schema_failure_uses_memory(self):
        with tempfile.TemporaryDirectory() as root:
            bad = Path(root) / "broken.db"
            bad.write_bytes(b"not sqlite")
            ledger = self.ledger(str(bad))
            self.assertEqual(ledger.db_path, ":memory:")
            ledger.record_event("test", "test", "OK")
            self.assertEqual(len(ledger.get_recent_events()), 1)
            self.assertEqual(bad.read_bytes(), b"not sqlite")

    def test_total_open_failure_skips_auditing_without_escaping(self):
        with patch("sqlite3.connect", side_effect=sqlite3.OperationalError("unavailable")):
            ledger = self.ledger(":memory:")
            ledger.record_event("test", "test", "OK")
            self.assertEqual(ledger.get_recent_events(), [])
            self.assertEqual(ledger.get_reset_epoch(), 0)
            self.assertEqual(ledger.bump_reset_epoch(), 0)
            self.assertFalse(ledger.clear())
            self.assertIn("disabled", ledger.render_markdown_summary().lower())

    def test_later_disk_open_failure_is_contained_for_every_operation(self):
        with tempfile.TemporaryDirectory() as root:
            ledger = self.ledger(str(Path(root) / "audit.db"))
            with patch("sqlite3.connect", side_effect=sqlite3.OperationalError("disk gone")):
                ledger.record_event("test", "test", "OK")
                self.assertEqual(ledger.get_recent_events(), [])
                self.assertEqual(ledger.get_reset_epoch(), 0)
                self.assertEqual(ledger.bump_reset_epoch(), 0)
                self.assertFalse(ledger.clear())

    def test_memory_connection_works_from_hook_worker_thread(self):
        from concurrent.futures import ThreadPoolExecutor
        ledger = self.ledger(":memory:")
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda n: ledger.record_event("test", "thread", str(n)), range(10)))
        self.assertEqual(len(ledger.get_recent_events()), 10)

    def test_clear_preserves_monotonic_epoch_for_other_processes(self):
        with tempfile.TemporaryDirectory() as root:
            path = str(Path(root) / "audit.db")
            first = self.ledger(path)
            second = self.ledger(path)
            self.assertEqual(first.bump_reset_epoch(), 1)
            first.record_event("test", "test", "OK")
            self.assertTrue(first.clear())
            self.assertEqual(second.get_recent_events(), [])
            self.assertEqual(second.get_reset_epoch(), 2)

    def test_memory_clear_and_close(self):
        ledger = self.ledger(":memory:")
        ledger.record_event("test", "test", "OK")
        self.assertTrue(ledger.clear())
        self.assertEqual(ledger.get_recent_events(), [])
        self.assertEqual(ledger.get_reset_epoch(), 1)
        ledger.close()
        ledger.close()
        self.assertEqual(ledger.get_recent_events(), [])


class TurnRegressions(unittest.TestCase):
    def setUp(self):
        self.ledger = AuditLedger(":memory:")
        self.addCleanup(dispose, self.ledger)
        self.patch_ledger = patch.object(sentinel, "audit_ledger", self.ledger)
        self.patch_rules = patch.object(sentinel, "rules_engine", SentinelRulesEngine())
        self.patch_ledger.start()
        self.patch_rules.start()
        self.addCleanup(self.patch_ledger.stop)
        self.addCleanup(self.patch_rules.stop)

    def test_history_is_neither_scanned_nor_mutated_even_without_reset(self):
        history = [{"role": "assistant", "content": [{"type": "text", "text": "ghp_1234567890abcdefghijklmnopqrstuvwxyz"}]}]
        before = copy.deepcopy(history)
        self.assertIsNone(sentinel.on_pre_llm_call(user_message="Continue", conversation_history=history))
        self.assertEqual(history, before)
        self.assertIsNone(sentinel.on_pre_llm_call(user_message="Continue", messages=history))

    def test_reset_allows_later_clean_turns_but_new_and_repeated_credentials_block(self):
        old_secret = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        self.assertEqual(sentinel.on_pre_llm_call(user_message=old_secret)["action"], "block")
        history = [{"role": "user", "content": old_secret}]
        sentinel.handle_sentinel_slash("reset")
        for message in ["Continue", "What next?", "Summarize"]:
            self.assertIsNone(sentinel.on_pre_llm_call(user_message=message, conversation_history=history))
            history.append({"role": "user", "content": message})
        self.assertEqual(history[0]["content"], old_secret)
        for secret in [old_secret, "sk-abcdef1234567890abcdef1234567890", "AKIAIOSFODNN7EXAMPLE"]:
            self.assertEqual(sentinel.on_pre_llm_call(user_message=secret, conversation_history=history)["action"], "block")
        self.assertNotIn(old_secret, str(self.ledger.get_recent_events()))

    def test_loop_reset_when_auditing_disabled(self):
        with patch("sqlite3.connect", side_effect=sqlite3.OperationalError("unavailable")):
            disabled = AuditLedger(":memory:")
        with patch.object(sentinel, "audit_ledger", disabled):
            self.assertIsNone(sentinel.on_pre_tool_call(tool_name="terminal", args={}))
            self.assertIsNone(sentinel.on_pre_tool_call(tool_name="terminal", args={}))
            self.assertEqual(sentinel.on_pre_tool_call(tool_name="terminal", args={})["action"], "block")
            sentinel.handle_sentinel_cli(["reset"])
            self.assertIsNone(sentinel.on_pre_tool_call(tool_name="terminal", args={}))
            self.assertEqual(sentinel.on_pre_llm_call(user_message="AKIAIOSFODNN7EXAMPLE")["action"], "block")
