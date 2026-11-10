"""Regression tests for the disposable, deny-by-default Windows build-root test adapter.

These tests DO NOT prove Windows junction containment or root authorization.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from windows_build_root_test_adapter import BuildRootTestAdapter


class BuildRootAdapterTests(unittest.TestCase):
    def test_fixture_lifetime_and_no_real_open(self):
        with BuildRootTestAdapter() as adapter:
            root = adapter.root
            self.assertTrue(root.is_dir())
            (root / "metadata.json").write_text('{"fixture":true}', encoding="utf-8")
            self.assertEqual(adapter.candidate_name("metadata.json"), "metadata.json")
            with self.assertRaisesRegex(PermissionError, "NOT IMPLEMENTED"):
                adapter.read_metadata("metadata.json")
        self.assertFalse(root.exists())
        with self.assertRaises(RuntimeError):
            _ = adapter.root

    def test_reject_traversal_before_denying_open(self):
        with BuildRootTestAdapter() as adapter:
            for name in ("../escape.json", r"..\\escape.json", r"C:\\outside.json",
                         "meta.json:stream", r"folder\\meta.json"):
                with self.subTest(name=name):
                    with self.assertRaises(ValueError):
                        adapter.read_metadata(name)

    def test_missing_fixture_is_not_implicit_authority(self):
        adapter = BuildRootTestAdapter()
        with self.assertRaises(RuntimeError):
            adapter.read_metadata("metadata.json")

    @unittest.skipUnless(os.name == "nt", "junction fixture needs native Windows")
    def test_windows_junction_attack_fixture_does_not_enable_reads(self):
        # Establish a real junction adversarial fixture; this does NOT test
        # containment of a real handle-relative opener (not implemented).
        with BuildRootTestAdapter() as adapter, tempfile.TemporaryDirectory() as outside:
            outside_dir = Path(outside)
            (outside_dir / "sentinel.json").write_text("OUTSIDE", encoding="utf-8")
            junction = adapter.root / "redirect"
            result = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), str(outside_dir)],
                capture_output=True, text=True, check=False, timeout=15,
            )
            if result.returncode != 0:
                self.skipTest("junction fixture unavailable: " + result.stderr[:200])
            self.assertEqual((junction / "sentinel.json").read_text(encoding="utf-8"), "OUTSIDE")
            with self.assertRaises(ValueError):
                adapter.read_metadata(r"redirect\\sentinel.json")
            with self.assertRaisesRegex(PermissionError, "NOT IMPLEMENTED"):
                adapter.read_metadata("sentinel.json")


if __name__ == "__main__":
    unittest.main()
