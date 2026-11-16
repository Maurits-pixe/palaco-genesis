"""WNRA-06Q: compare observed Windows primary-thread and process exit status.

Only test workers; no debugger, audit policy, ACL, production activation,
privilege grant, or claim that a thread exit identifies a loader resource.
"""
import os
import pathlib
import sys
import unittest

from test_windows_anchor_python_entry_markers import (
    MARKERS, PythonEntryMarkerTests,
)


@unittest.skipUnless(sys.platform == "win32", "native Windows required")
class PrimaryThreadExitComparisonTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PythonEntryMarkerTests(
            "test_two_distinct_user_code_markers_under_three_token_policies"
        )
        self.fixture.setUp()

    def test_main_thread_and_process_outcomes_for_two_images(self):
        root = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows"))
        images = {
            "python": pathlib.Path(sys.executable),
            "windows_cmd": root / "System32" / "cmd.exe",
        }
        for image, executable in images.items():
            self.assertTrue(executable.is_file(), image + " missing")
        source = self.fixture.fx._source()
        try:
            for image, executable in images.items():
                results = {}
                for policy in ("low_only", "user", "builtin_users"):
                    outcomes = []
                    for marker in MARKERS:
                        outcome = self.fixture._run_marker(
                            source, policy, executable, marker,
                            image_kind=image, thread_probe=True,
                        )
                        outcomes.append(outcome)
                    results[policy] = outcomes
                self.assertEqual(
                    results["low_only"],
                    ["user_code_marker", "user_code_marker"],
                )
                for policy in ("user", "builtin_users"):
                    self.assertEqual(len(results[policy]), len(MARKERS))
                print(
                    "WNRA06Q_COMPARISON image=" + image
                    + " low_only=" + ",".join(results["low_only"])
                    + " user=" + ",".join(results["user"])
                    + " builtin_users=" + ",".join(results["builtin_users"])
                    + " evidence=thread_and_process_exit_observation"
                    + " loader_denial_traced=false"
                    + " root_cause=UNKNOWN authorization=DENY"
                )
        finally:
            self.fixture.fx.fx._close(source)


if __name__ == "__main__":
    unittest.main()
