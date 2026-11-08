"""Parsed release metadata must describe what this plugin registers."""
import io
from contextlib import redirect_stdout
from pathlib import Path
import re
import tomllib
import unittest

import hermes_yaml as yaml
import hermes_sentinel as sentinel

ROOT = Path(__file__).resolve().parents[1]


class MetadataTests(unittest.TestCase):
    def test_release_and_catalog_example_match_manifest_and_registration(self):
        manifest = yaml.safe_load((ROOT / "plugin.yaml").read_text(encoding="utf-8"))
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        catalog = yaml.safe_load(re.search(r"```yaml\n(.*?)```", readme, re.S).group(1))
        self.assertEqual(manifest["version"], "0.1.1")
        self.assertEqual(project["version"], manifest["version"])
        self.assertEqual(catalog["version"], manifest["version"])
        self.assertEqual(manifest["requires_hermes"], ">=0.22.6")
        self.assertEqual(catalog["requires_hermes"], manifest["requires_hermes"])
        self.assertEqual(catalog["capabilities"]["provides_hooks"], manifest["provides_hooks"])

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
        self.assertIn("v0.1.1", output.getvalue())
