"""WNRA-06D: compare executable-image behavior with the same restricted SID.

Diagnostic only. A different process image may change loader dependencies;
this does NOT attribute an access denial to a specific file/DLL or ACE.
No filesystem ACLs or account privileges are changed.
"""
import sys
import unittest

from test_windows_anchor_restricted_sid_access_diagnostics import (
    RestrictedSidAccessDiagnostics,
)

@unittest.skipUnless(sys.platform == "win32", "native Windows token required")
class RestrictedSidExecutableComparisonTests(unittest.TestCase):
    def setUp(self):
        self.fixture = RestrictedSidAccessDiagnostics(
            "test_current_user_sid_restricted_worker"
        )
        self.fixture.setUp()

    def test_windows_cmd_under_current_user_restricting_sid(self):
        result = self.fixture._run_variant("user", "windows_cmd")
        self.assertIn(result, (
            "create_blocked", "runtime_blocked",
            "worker_live_then_job_terminated",
        ))
        print(
            "WNRA06D_IMAGE variant=user image_kind=windows_cmd "
            "result=" + result + " authorization=DENY"
        )

    def test_windows_cmd_under_builtin_users_restricting_sid(self):
        result = self.fixture._run_variant("builtin_users", "windows_cmd")
        self.assertIn(result, (
            "create_blocked", "runtime_blocked",
            "worker_live_then_job_terminated",
        ))
        print(
            "WNRA06D_IMAGE variant=builtin_users image_kind=windows_cmd "
            "result=" + result + " authorization=DENY"
        )


if __name__ == "__main__":
    unittest.main()
