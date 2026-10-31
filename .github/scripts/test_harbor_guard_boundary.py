#!/usr/bin/env python3
"""Integration tests: shell must not reach simulated benchmark after guard rejection."""
import pathlib
import subprocess
import sys
import tempfile
import unittest

GUARD = pathlib.Path(__file__).with_name("verify_harbor_pr_head.py")
A = "16e5c7742b9eb5aebb117e30f705758fecda2e59"
B = "4af841049070916befcc11dca5fb29cf22c36f06"


class GuardBoundaryTests(unittest.TestCase):
    def run_boundary(self, expected, actual):
        with tempfile.TemporaryDirectory() as folder:
            marker = pathlib.Path(folder) / "benchmark-reached"
            script = 'set -euo pipefail; "$1" "$2" "$3" "$4"; touch "$5"'
            result = subprocess.run(
                ["bash", "-c", script, "guard-boundary", sys.executable,
                 str(GUARD), expected, actual, str(marker)],
                capture_output=True, text=True, check=False,
            )
            return result, marker.exists()

    def test_mismatched_commit_blocks_following_step(self):
        result, reached = self.run_boundary(A, B)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(reached)
        self.assertIn("refusing benchmark", result.stderr)

    def test_empty_expected_blocks_following_step(self):
        result, reached = self.run_boundary("", A)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(reached)

    def test_empty_actual_blocks_following_step(self):
        result, reached = self.run_boundary(A, "")
        self.assertEqual(result.returncode, 1)
        self.assertFalse(reached)

    def test_malformed_expected_blocks_following_step(self):
        result, reached = self.run_boundary("not-a-sha", A)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(reached)

    def test_short_actual_blocks_following_step(self):
        result, reached = self.run_boundary(A, B[:7])
        self.assertEqual(result.returncode, 1)
        self.assertFalse(reached)

    def test_whitespace_actual_blocks_following_step(self):
        result, reached = self.run_boundary(A, A + "\n")
        self.assertEqual(result.returncode, 1)
        self.assertFalse(reached)

    def test_correct_commit_allows_following_step(self):
        result, reached = self.run_boundary(A, A)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(reached)


if __name__ == "__main__":
    unittest.main()
