"""Run the real demo and exercise its resource boundaries on failure."""
import importlib.util
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sentinel_demo", ROOT / "scripts/run_demo.py")
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


class DemoTests(unittest.TestCase):
    def test_profile_copies_no_config_and_child_environment_has_no_credentials(self):
        with tempfile.TemporaryDirectory() as source:
            root = Path(source)
            (root / "config.yaml").write_text("slack:\n  token: other-platform-secret\n", encoding="utf-8")
            (root / ".env").write_text("OPENAI_API_KEY=private-key\n", encoding="utf-8")
            with patch.dict(os.environ, {"HERMES_HOME": source, "OPENAI_API_KEY": "private-key", "TELEGRAM_BOT_TOKEN": "telegram-secret", "CUSTOM_PASSWORD": "another-secret"}):
                with demo.TemporaryDemoProfile() as profile:
                    owned = profile.profile_dir
                    self.assertEqual(list(owned.iterdir()), [])
                    for key in ["OPENAI_API_KEY", "TELEGRAM_BOT_TOKEN", "CUSTOM_PASSWORD", "HERMES_SENTINEL_DB"]:
                        self.assertNotIn(key, profile.env)
                    self.assertEqual(profile.env["HERMES_HOME"], str(owned))
                    self.assertEqual(profile.db_path, owned / "plugin-data/hermes-sentinel/sentinel_audit.db")
            self.assertFalse(owned.exists())
            self.assertTrue((root / "config.yaml").exists())

    def test_profile_cleanup_on_body_failure_is_idempotent(self):
        profile = demo.TemporaryDemoProfile()
        with self.assertRaisesRegex(RuntimeError, "body failed"):
            with profile:
                owned = profile.profile_dir
                raise RuntimeError("body failed")
        self.assertFalse(owned.exists())
        profile.cleanup()

    def test_profile_cleanup_on_setup_failure(self):
        created = []
        real_mkdtemp = tempfile.mkdtemp

        def track(*args, **kwargs):
            path = real_mkdtemp(*args, **kwargs)
            created.append(Path(path))
            return path

        with patch.object(demo.tempfile, "mkdtemp", side_effect=track), patch.object(demo, "build_demo_environment", side_effect=RuntimeError("setup failed")):
            with self.assertRaisesRegex(RuntimeError, "setup failed"):
                with demo.TemporaryDemoProfile():
                    pass
        self.assertTrue(created)
        self.assertTrue(all(not p.exists() for p in created))

    def test_cleanup_failure_is_reported_and_can_be_retried(self):
        with demo.TemporaryDemoProfile() as profile:
            owned = profile.profile_dir
            with patch.object(demo.shutil, "rmtree", side_effect=PermissionError("locked")):
                with self.assertRaises(PermissionError):
                    profile.cleanup()
            self.assertTrue(owned.exists())
            profile.cleanup()
            self.assertFalse(owned.exists())

    def test_real_python_demo_success_restores_environment_and_signals(self):
        before = dict(os.environ)
        handlers = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
        self.assertEqual(demo.run_demo_sequence(), 0)
        self.assertEqual(dict(os.environ), before)
        self.assertEqual({s: signal.getsignal(s) for s in handlers}, handlers)

    def test_failed_child_is_cleaned_and_parent_state_preserved(self):
        before = dict(os.environ)
        handlers = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
        owned = []

        def fail(command, **kwargs):
            owned.append(Path(kwargs["env"]["HERMES_HOME"]))
            self.assertTrue(owned[-1].exists())
            raise subprocess.CalledProcessError(17, command)

        with patch.object(demo.subprocess, "run", side_effect=fail):
            with self.assertRaises(subprocess.CalledProcessError):
                demo.run_demo_sequence()
        self.assertTrue(owned)
        self.assertFalse(owned[0].exists())
        self.assertEqual(dict(os.environ), before)
        self.assertEqual({s: signal.getsignal(s) for s in handlers}, handlers)

    def test_real_mid_demo_worker_exception_removes_owned_profile(self):
        real_run = subprocess.run
        owned = []
        script = ROOT / "scripts/run_demo.py"
        code = (
            "import sys, runpy; import hermes_sentinel as s; "
            "s.on_transform_tool_result = lambda **kw: (_ for _ in ()).throw(RuntimeError('injected worker failure')); "
            f"sys.argv = [{str(script)!r}, '--worker']; "
            f"runpy.run_path({str(script)!r}, run_name='__main__')"
        )

        def fail_worker(command, **kwargs):
            owned.append(Path(kwargs["env"]["HERMES_HOME"]))
            kwargs.update(capture_output=True, text=True)
            return real_run([sys.executable, "-B", "-c", code], **kwargs)

        with patch.object(demo.subprocess, "run", side_effect=fail_worker):
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                demo.run_demo_sequence()
        self.assertIn("injected worker failure", raised.exception.stderr)
        self.assertTrue(owned)
        self.assertFalse(owned[0].exists())

    def test_handled_signal_cleans_profile_and_restores_handlers(self):
        owned = []
        previous = signal.getsignal(signal.SIGTERM)

        def interrupt(command, **kwargs):
            owned.append(Path(kwargs["env"]["HERMES_HOME"]))
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)

        with patch.object(demo.subprocess, "run", side_effect=interrupt):
            with self.assertRaises(SystemExit) as raised:
                demo.run_demo_sequence()
        self.assertEqual(raised.exception.code, 128 + signal.SIGTERM)
        self.assertFalse(owned[0].exists())
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)

    @unittest.skipUnless(os.name == "nt", "Windows PowerShell runner")
    def test_powershell_real_success_and_failure_propagation(self):
        wrapper = ROOT / "scripts/run_demo.ps1"
        success = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(wrapper), "-PythonExe", sys.executable], capture_output=True, text=True)
        self.assertEqual(success.returncode, 0, success.stdout + success.stderr)
        self.assertIn("[Cleanup] Temporary profile deleted: True", success.stdout)
        # A controlled child exercises the wrapper's nonzero-exit handling.
        with tempfile.TemporaryDirectory() as root:
            bad_plugin = Path(root) / "plugin"
            (bad_plugin / "scripts").mkdir(parents=True)
            (bad_plugin / "scripts/run_demo.py").write_text("raise SystemExit(17)\n", encoding="utf-8")
            result = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(wrapper), "-PluginDir", str(bad_plugin), "-PythonExe", sys.executable], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("[Cleanup]", result.stdout)

    def test_demo_never_invokes_hermes_profile_commands(self):
        # Trap any attempted CLI lookup without executing the real user's Hermes.
        with patch.object(shutil, "which", side_effect=AssertionError("unexpected executable lookup")):
            with demo.TemporaryDemoProfile():
                pass
