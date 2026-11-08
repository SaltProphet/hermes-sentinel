"""Exercise the real Hermes directory loader, lifecycle ledger and profile scopes."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hermes_constants import set_hermes_home_override, reset_hermes_home_override
from hermes_cli.plugins import PluginContext, PluginManager
from hermes_cli.plugins_manifest import parse_manifest_file

ROOT = Path(__file__).resolve().parents[1]


class LoaderTests(unittest.TestCase):
    def load(self, home, manager=None):
        token = set_hermes_home_override(home)
        try:
            manager = manager or PluginManager(scope_key=str(home))
            manifest = parse_manifest_file(ROOT / "plugin.yaml", ROOT, "user", "")
            self.assertIsNotNone(manifest)
            module = manager._load_directory_module(manifest)
            module.register(PluginContext(manifest, manager))
        finally:
            reset_hermes_home_override(token)
        self.addCleanup(manager.unload)
        return manager, module

    def test_profile_databases_and_unload_are_independent(self):
        with tempfile.TemporaryDirectory() as root:
            a = Path(root) / "profile-a"
            b = Path(root) / "profile-b"
            first_manager, first = self.load(a)
            second_manager, second = self.load(b)
            try:
                self.assertEqual(Path(first.audit_ledger.db_path), a / "plugin-data/hermes-sentinel/sentinel_audit.db")
                self.assertEqual(Path(second.audit_ledger.db_path), b / "plugin-data/hermes-sentinel/sentinel_audit.db")
                self.assertIsNot(first.audit_ledger, second.audit_ledger)
                first.on_pre_tool_call(tool_name="read_file", args={})
                first.on_pre_tool_call(tool_name="read_file", args={})
                self.assertIsNone(second.on_pre_tool_call(tool_name="read_file", args={}))
                first_manager.unload()
                self.assertEqual(second.audit_ledger.storage, "persistent")
                second.on_post_tool_call(tool_name="read_file", result="ok")
                self.assertEqual(second.audit_ledger.get_recent_events(1)[0]["action"], "COMPLETED")
            finally:
                first_manager.unload()
                second_manager.unload()

    def test_unload_reload_owns_live_ledger_and_external_reset_still_works(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root)
            manager, first = self.load(home)
            manager.unload()
            manager, reloaded = self.load(home, manager)
            try:
                self.assertEqual(reloaded.audit_ledger.storage, "persistent")
                self.assertIsNot(first.audit_ledger, reloaded.audit_ledger)
                call = {"tool_name": "read_file", "args": {}, "session_id": "same-session"}
                reloaded.on_pre_tool_call(**call)
                reloaded.on_pre_tool_call(**call)
                code = (
                    "from hermes_sentinel.audit import AuditLedger; "
                    f"ledger=AuditLedger({reloaded.audit_ledger.db_path!r}); "
                    "assert ledger.bump_reset_epoch() == 1; ledger.close()"
                )
                child = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True)
                self.assertEqual(child.returncode, 0, child.stderr)
                self.assertIsNone(reloaded.on_pre_tool_call(**call))
                self.assertEqual(reloaded.audit_ledger.get_recent_events(1)[0]["action"], "ALLOWED")
            finally:
                manager.unload()
