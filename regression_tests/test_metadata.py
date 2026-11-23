"""Manifest, package metadata and registration must describe the same plugin."""
import io
from contextlib import redirect_stdout
from pathlib import Path
import tomllib
import unittest

import hermes_yaml as yaml
import hermes_sentinel as sentinel

ROOT = Path(__file__).resolve().parents[1]


class MetadataTests(unittest.TestCase):
    def test_version_and_declarations_match_registration(self):
        manifest = yaml.safe_load((ROOT / "plugin.yaml").read_text(encoding="utf-8"))
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        self.assertEqual(project["version"], manifest["version"])

        class Context:
            def __init__(self):
                self.hooks, self.cli, self.commands, self.unload = {}, {}, {}, []
            def register_hook(self, name, callback):
                self.hooks[name] = callback
            def register_cli_command(self, name, help, setup_fn, handler_fn):
                self.cli[name] = (setup_fn, handler_fn)
            def register_command(self, name, handler, description):
                self.commands[name] = handler
            def on_unload(self, callback):
                self.unload.append(callback)

        context = Context()
        sentinel.register(context)
        self.assertEqual(set(context.hooks), set(manifest["provides_hooks"]))
        self.assertEqual(set(context.cli), {"sentinel"})
        self.assertEqual(set(context.commands), {"sentinel"})
        self.assertEqual(len(context.unload), 1)

        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(sentinel.handle_sentinel_cli(["status"]), 0)
        self.assertIn(f"v{manifest['version']}", output.getvalue())
