"""Synthetic demonstration fixtures must remain admissible by the real scanner."""
from pathlib import Path
import unittest

from tools.plugin_guard import scan_plugin


class AdmissionTests(unittest.TestCase):
    def test_demo_fixtures_do_not_ship_credential_shaped_literals(self):
        report = scan_plugin(Path(__file__).resolve().parents[1])
        findings = [(f.pattern_id, f.file, f.line) for f in report.findings]
        self.assertNotEqual(report.verdict, "dangerous", findings)
