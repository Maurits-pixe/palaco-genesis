#!/usr/bin/env python3
"""Exercise both success and rejection paths for Harbor PR-head verification."""
import subprocess
import sys
import pathlib
import unittest
from verify_harbor_pr_head import matches

A = "0ff05fd9ce63e78818a6de0b41e17f96f1c052f7"
B = "e389b2a05900f3b34ae78f450361e6180e280cc7"


class HeadGuardTests(unittest.TestCase):
    def invoke(self, *args):
        script = pathlib.Path(__file__).with_name("verify_harbor_pr_head.py")
        return subprocess.run(
            [sys.executable, str(script), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_cli_accepts_exact_head(self):
        result = self.invoke(A, A)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Exact PR head verified:", result.stdout)

    def test_cli_rejects_wrong_head(self):
        result = self.invoke(A, B)
        self.assertEqual(result.returncode, 1)
        self.assertIn("refusing benchmark", result.stderr)
        self.assertNotIn("Exact PR head verified", result.stdout)

    def test_cli_rejects_missing_arguments(self):
        result = self.invoke(A)
        self.assertEqual(result.returncode, 2)

    def test_cli_rejects_malformed_actual(self):
        result = self.invoke(A, "invalid")
        self.assertEqual(result.returncode, 1)

    def test_accept_exact_sha(self):
        self.assertTrue(matches(A, A))

    def test_reject_different_valid_sha(self):
        self.assertFalse(matches(A, B))

    def test_reject_empty_expected(self):
        self.assertFalse(matches("", A))

    def test_reject_empty_actual(self):
        self.assertFalse(matches(A, ""))

    def test_reject_short_sha(self):
        self.assertFalse(matches(A[:7], A))

    def test_reject_uppercase(self):
        self.assertFalse(matches(A.upper(), A))

    def test_reject_non_hex(self):
        self.assertFalse(matches("z" + A[1:], A))

    def test_reject_whitespace(self):
        self.assertFalse(matches(A + "\n", A))


if __name__ == "__main__":
    unittest.main()
