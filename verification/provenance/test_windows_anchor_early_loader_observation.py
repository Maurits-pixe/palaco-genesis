"""WNRA-06M: bounded early module and process-exit observations.

Toolhelp samples are snapshots only, not an ETW or loader denial trace.
All child processes remain in kill-on-close Job Objects.
"""
import pathlib
import sys
import unittest

from test_windows_anchor_process_module_snapshot import (
    ProcessModuleSnapshotTests as _ModuleFixture,
)


@unittest.skipUnless(sys.platform == "win32", "native Windows required")
class EarlyLoaderObservationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = _ModuleFixture(
            "test_bounded_process_bound_module_snapshots"
        )
        self.fixture.setUp()

    def test_early_sampling_and_fail_closed_cleanup(self):
        image = pathlib.Path(sys.executable)
        self.assertTrue(image.is_file())
        source = self.fixture.fx._source()
        try:
            control = self.fixture._run_policy(
                source, "low_only", image, early_capture=True,
            )
            user = self.fixture._run_policy(
                source, "user", image, early_capture=True,
            )
            users = self.fixture._run_policy(
                source, "builtin_users", image, early_capture=True,
            )
            self.assertEqual(control, "worker_live")
            valid = {"create_blocked", "runtime_blocked", "worker_live"}
            self.assertIn(user, valid)
            self.assertIn(users, valid)
            print(
                "WNRA06M_SUMMARY low_only=" + control
                + " user=" + user
                + " builtin_users=" + users
                + " bounded_poll=true process_specific=true"
                + " root_cause=UNKNOWN authorization=DENY"
            )
        finally:
            self.fixture.fx.fx._close(source)


if __name__ == "__main__":
    unittest.main()
