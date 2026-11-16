"""WNRA-06P: expanded restricting-SID-only initialization policy matrix.

Test-only. Keeps DISABLE_MAX_PRIVILEGE and Low integrity unchanged and
compares Authenticated Users and Everyone restricting SIDs against earlier
user and BUILTIN Users fixtures. No production policy is changed.
"""
import os
import pathlib
import sys
import unittest

from test_windows_anchor_python_entry_markers import (
    PythonEntryMarkerTests, MARKERS,
)
from test_windows_anchor_restricted_sid_object_open import (
    RestrictedSidObjectOpenTests, FILE_GENERIC_READ, FILE_GENERIC_EXECUTE,
)
from test_windows_anchor_restricted_token import LOW_INTEGRITY_RID
from test_windows_anchor_restricted_sid_worker import TOKEN_RESTRICTED_SIDS
from ctypes import wintypes
import ctypes


@unittest.skipUnless(sys.platform == "win32", "native Windows restricted tokens required")
class RestrictedSidPolicyMatrixTests(unittest.TestCase):
    def setUp(self):
        self.launch = PythonEntryMarkerTests(
            "test_two_distinct_user_code_markers_under_three_token_policies"
        )
        self.launch.setUp()
        self.object_probe = RestrictedSidObjectOpenTests(
            "test_actual_read_and_execute_opens_match_recorded_dacl_probes"
        )
        self.object_probe.setUp()

    def test_authenticated_and_everyone_restricting_sid_only(self):
        windows = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows"))
        images = {
            "python": pathlib.Path(sys.executable),
            "windows_cmd": windows / "System32" / "cmd.exe",
        }
        for image, path in images.items():
            self.assertTrue(path.is_file(), "missing executable: " + image)
        source = self.launch.fx._source()
        try:
            for policy in ("authenticated_users", "everyone"):
                token = None
                try:
                    token = self.object_probe.fixture._token(source, policy)
                    self.object_probe.fx.token_fixture._lower_integrity(token)
                    observed = self.object_probe.fx.audit._observed(token)
                    self.assertEqual(observed["integrity_rid"], LOW_INTEGRITY_RID)
                    self.assertEqual(observed["restricted"], 1)
                    info = self.object_probe.fx.audit._information(
                        token, TOKEN_RESTRICTED_SIDS,
                    )
                    sid_count = ctypes.cast(
                        info, ctypes.POINTER(wintypes.DWORD),
                    ).contents.value
                    self.assertGreaterEqual(sid_count, 1)
                    self.assertLessEqual(
                        self.object_probe.fx.token_fixture._enabled_count(token),
                        self.object_probe.fx.token_fixture._enabled_count(source),
                    )
                    for image, path in images.items():
                        read, read_error = self.object_probe._object_open(
                            token, path, FILE_GENERIC_READ,
                        )
                        execute, execute_error = self.object_probe._object_open(
                            token, path, FILE_GENERIC_EXECUTE,
                        )
                        if read:
                            self.assertEqual(read_error, 0)
                        else:
                            self.assertNotEqual(read_error, 0)
                        if execute:
                            self.assertEqual(execute_error, 0)
                        else:
                            self.assertNotEqual(execute_error, 0)
                        print(
                            "WNRA06P_ACCESS policy=" + policy
                            + " image=" + image
                            + " read=" + str(read).lower()
                            + " read_error=" + str(read_error)
                            + " execute=" + str(execute).lower()
                            + " execute_error=" + str(execute_error)
                            + " low_integrity=true privileges_reduced=true"
                            + " authorization=DENY"
                        )
                finally:
                    if token:
                        self.object_probe.fx.fx._close(token)

                for image, path in images.items():
                    outcomes = []
                    for marker in MARKERS:
                        outcome = self.launch._run_marker(
                            source, policy, path, marker,
                            image_kind=image,
                        )
                        outcomes.append(outcome)
                        print(
                            "WNRA06P_ENTRY policy=" + policy
                            + " image=" + image
                            + " marker=" + str(marker)
                            + " outcome=" + outcome
                            + " low_integrity=true privileges_reduced=true"
                            + " loader_cause=UNKNOWN authorization=DENY"
                        )
                    self.assertEqual(len(outcomes), len(MARKERS))
            print(
                "WNRA06P_SUMMARY policy_variants=authenticated_users,everyone"
                + " images=python,windows_cmd"
                + " positive_controls=WNRA06N_and_WNRA06O"
                + " sid_only_variation=true"
                + " no_privilege_grants=true"
                + " loader_failure_attributed=false"
                + " root_cause=UNKNOWN authorization=DENY"
            )
        finally:
            self.launch.fx.fx._close(source)


if __name__ == "__main__":
    unittest.main()
