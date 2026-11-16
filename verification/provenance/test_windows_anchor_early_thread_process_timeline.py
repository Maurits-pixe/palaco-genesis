"""WNRA-06R: early thread and process signal timeline, native Windows.

All observations are bounded and read-only; polling order never proves which
Windows operation failed. Jobs terminate and clean up every child.
"""
import os
import pathlib
import sys
import unittest

from test_windows_anchor_python_entry_markers import (
    PythonEntryMarkerTests, MARKERS,
)


@unittest.skipUnless(sys.platform == "win32", "native Windows required")
class EarlyThreadProcessTimelineTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PythonEntryMarkerTests(
            "test_two_distinct_user_code_markers_under_three_token_policies"
        )
        self.fixture.setUp()

    def test_bounded_main_thread_and_process_signals(self):
        windows = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows"))
        images = {
            "python": pathlib.Path(sys.executable),
            "windows_cmd": windows / "System32" / "cmd.exe",
        }
        for image, path in images.items():
            self.assertTrue(path.is_file(), "missing image " + image)
        source = self.fixture.fx._source()
        try:
            for image, path in images.items():
                outcomes = {}
                for policy in ("low_only", "user", "builtin_users"):
                    outcomes[policy] = [
                        self.fixture._run_marker(
                            source, policy, path, marker,
                            image_kind=image,
                            thread_probe=True, timeline_probe=True,
                        )
                        for marker in MARKERS
                    ]
                self.assertEqual(
                    outcomes["low_only"],
                    ["user_code_marker", "user_code_marker"],
                )
                self.assertEqual(len(outcomes["user"]), 2)
                self.assertEqual(len(outcomes["builtin_users"]), 2)
                print(
                    "WNRA06R_SUMMARY image=" + image
                    + " low_only=" + ",".join(outcomes["low_only"])
                    + " user=" + ",".join(outcomes["user"])
                    + " builtin_users=" + ",".join(outcomes["builtin_users"])
                    + " samples_per_process_max=12"
                    + " event_order_proven=false"
                    + " root_cause=UNKNOWN authorization=DENY"
                )
        finally:
            self.fixture.fx.fx._close(source)


if __name__ == "__main__":
    unittest.main()
