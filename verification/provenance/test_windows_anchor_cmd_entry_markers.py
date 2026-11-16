"""WNRA-06O: independent Windows cmd.exe built-in exit markers.

Uses native cmd.exe rather than Python to identify whether the failure is
interpreter-specific. A matching process exit marker is evidence that cmd
processed its /c command, not proof of a complete loader trace.
"""
import os
import pathlib
import sys
import unittest

from test_windows_anchor_python_entry_markers import (
    PythonEntryMarkerTests, MARKERS,
)


@unittest.skipUnless(sys.platform == "win32", "native Windows required")
class WindowsCmdEntryMarkersTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PythonEntryMarkerTests(
            "test_two_distinct_user_code_markers_under_three_token_policies"
        )
        self.fixture.setUp()

    def test_native_cmd_markers_without_python_interpreter(self):
        root = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows"))
        executable = root / "System32" / "cmd.exe"
        self.assertTrue(executable.is_file())
        source = self.fixture.fx._source()
        try:
            results = {}
            for policy in ("low_only", "user", "builtin_users"):
                outcomes = []
                for marker in MARKERS:
                    outcome = self.fixture._run_marker(
                        source, policy, executable, marker,
                        image_kind="windows_cmd",
                    )
                    outcomes.append(outcome)
                    print(
                        "WNRA06O_CMD policy=" + policy
                        + " marker=" + str(marker)
                        + " outcome=" + outcome
                        + " image=windows_cmd"
                        + " python_interpreter=false"
                        + " loader_denial_traced=false"
                        + " root_cause=UNKNOWN authorization=DENY"
                    )
                results[policy] = outcomes
            self.assertEqual(
                results["low_only"],
                ["user_code_marker", "user_code_marker"],
            )
            for policy in ("user", "builtin_users"):
                self.assertEqual(len(results[policy]), len(MARKERS))
            print(
                "WNRA06O_SUMMARY low_only=" + ",".join(results["low_only"])
                + " user=" + ",".join(results["user"])
                + " builtin_users=" + ",".join(results["builtin_users"])
                + " independent_interpreter=true"
                + " cause_attributed=false authorization=DENY"
            )
        finally:
            self.fixture.fx.fx._close(source)


if __name__ == "__main__":
    unittest.main()
