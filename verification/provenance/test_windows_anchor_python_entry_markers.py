"""WNRA-06N: explicit Python user-code entry markers via exit codes.

Two distinct os._exit markers discriminate reaching Python's -c user code
from early process exit. No filesystem writes/pipes/ACL changes are required.
Marker absence does not prove a particular loader or DLL failure.
"""
import ctypes
from ctypes import wintypes
import os
import pathlib
import subprocess
import sys
import unittest

from test_windows_anchor_process_bound_failure import (
    ProcessBoundFailureEvidenceTests,
)
from test_windows_anchor_suspended_job_launch import (
    CREATE_NO_WINDOW, CREATE_SUSPENDED,
    PROCESS_INFORMATION, STARTUPINFOW, RESUME_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
)
from test_windows_anchor_restricted_token import LOW_INTEGRITY_RID
from test_windows_anchor_low_token_job_launch import (
    ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD, ERROR_BAD_TOKEN_TYPE,
)
from test_windows_anchor_restricted_sid_access_diagnostics import (
    ERROR_BAD_IMPERSONATION_LEVEL,
)

MARKERS = (37, 53)
MAX_WAIT_MS = 3000


@unittest.skipUnless(sys.platform == "win32", "Windows process tokens required")
class PythonEntryMarkerTests(unittest.TestCase):
    def setUp(self):
        self.controller = ProcessBoundFailureEvidenceTests(
            "test_process_bound_policy_comparison"
        )
        self.controller.setUp()
        self.fx = self.controller.fx
        self.k = self.controller.k
        self.a = self.controller.a

    def _run_marker(self, source, policy, executable, marker):
        self.assertIn(marker, MARKERS)
        token = None
        job = None
        info = PROCESS_INFORMATION()
        try:
            token = (
                self.fx.token_fixture._restricted(source)
                if policy == "low_only"
                else self.controller.probe._token(source, policy)
            )
            self.fx.token_fixture._lower_integrity(token)
            expected_restricted = policy != "low_only"
            before = self.fx.audit._observed(token)
            self.assertEqual(before["integrity_rid"], LOW_INTEGRITY_RID)
            self.assertEqual(bool(before["restricted"]), expected_restricted)
            job = self.fx.fx._job()
            # A successful user-code path ends with marker 37 or 53.
            # No output stream, file, network, environment mutation or IPC.
            args = [
                str(executable), "-u", "-c",
                "import os; os._exit(" + str(marker) + ")",
            ]
            command = ctypes.create_unicode_buffer(
                subprocess.list2cmdline(args),
            )
            startup = STARTUPINFOW()
            startup.cb = ctypes.sizeof(startup)
            ctypes.set_last_error(0)
            created = bool(self.a.CreateProcessAsUserW(
                token, str(executable), command, None, None, False,
                CREATE_SUSPENDED | CREATE_NO_WINDOW, None, None,
                ctypes.byref(startup), ctypes.byref(info),
            ))
            if not created:
                error = ctypes.get_last_error()
                self.assertIn(error, (
                    ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD,
                    ERROR_BAD_TOKEN_TYPE, ERROR_BAD_IMPERSONATION_LEVEL,
                ))
                self.assertFalse(info.hProcess)
                self.assertFalse(info.hThread)
                self.assertNotEqual(policy, "low_only",
                                    "positive control creation failed")
                print(
                    "WNRA06N_ENTRY policy=" + policy
                    + " marker=" + str(marker)
                    + " outcome=create_blocked code=" + str(error)
                    + " process_bound=false"
                    + " user_code_reached=false"
                    + " loader_cause=UNKNOWN authorization=DENY"
                )
                return "create_blocked"
            self.assertTrue(info.hProcess)
            self.assertTrue(info.hThread)
            self.assertEqual(
                self.k.WaitForSingleObject(info.hProcess, 0), WAIT_TIMEOUT,
            )
            self.fx.fx._check(
                self.k.AssignProcessToJobObject(job, info.hProcess),
            )
            member = wintypes.BOOL()
            self.fx.fx._check(self.k.IsProcessInJob(
                info.hProcess, job, ctypes.byref(member),
            ))
            self.assertTrue(member.value)
            pid = self.k.GetProcessId(info.hProcess)
            self.assertGreater(pid, 0)
            self.assertEqual(pid, info.dwProcessId)
            capacity = wintypes.DWORD(32768)
            path_buffer = ctypes.create_unicode_buffer(capacity.value)
            self.fx.fx._check(self.k.QueryFullProcessImageNameW(
                info.hProcess, 0, path_buffer, ctypes.byref(capacity),
            ))
            self.assertEqual(
                os.path.normcase(os.path.abspath(path_buffer.value)),
                os.path.normcase(os.path.abspath(str(executable))),
            )
            child_token = None
            try:
                child_token = self.fx.audit._token(info.hProcess)
                observed = self.fx.audit._observed(child_token)
                self.assertEqual(observed["integrity_rid"], LOW_INTEGRITY_RID)
                self.assertEqual(
                    bool(observed["restricted"]), expected_restricted,
                )
            finally:
                if child_token:
                    self.fx.fx._close(child_token)
            self.assertNotEqual(
                self.k.ResumeThread(info.hThread), RESUME_FAILED,
            )
            status = self.k.WaitForSingleObject(info.hProcess, MAX_WAIT_MS)
            if status == WAIT_OBJECT_0:
                exit_status = wintypes.DWORD()
                self.fx.fx._check(self.k.GetExitCodeProcess(
                    info.hProcess, ctypes.byref(exit_status),
                ))
                code = exit_status.value
                reached = code == marker
                outcome = "user_code_marker" if reached else "no_marker_exit"
            else:
                self.assertEqual(status, WAIT_TIMEOUT)
                code = -1
                reached = False
                outcome = "timeout_no_marker"
            if policy == "low_only":
                self.assertEqual(outcome, "user_code_marker",
                                 "positive control must reach Python code")
            self.fx.fx._close(job)
            job = None
            self.assertEqual(
                self.k.WaitForSingleObject(info.hProcess, 5000),
                WAIT_OBJECT_0,
            )
            print(
                "WNRA06N_ENTRY policy=" + policy
                + " marker=" + str(marker)
                + " outcome=" + outcome + " code=" + str(code)
                + " process_bound=true pid_verified=true image_verified=true"
                + " child_token_verified=true job_before_resume=true"
                + " user_code_reached=" + str(reached).lower()
                + " loader_cause=UNKNOWN authorization=DENY"
            )
            return outcome
        finally:
            if job:
                self.fx.fx._close(job)
            if info.hProcess:
                if self.k.WaitForSingleObject(info.hProcess, 0) == WAIT_TIMEOUT:
                    self.k.TerminateProcess(info.hProcess, 1)
                    self.k.WaitForSingleObject(info.hProcess, 5000)
                self.fx.fx._close(info.hProcess)
            if info.hThread:
                self.fx.fx._close(info.hThread)
            if token:
                self.fx.fx._close(token)

    def test_two_distinct_user_code_markers_under_three_token_policies(self):
        executable = pathlib.Path(sys.executable)
        self.assertTrue(executable.is_file())
        source = self.fx._source()
        try:
            outcomes = {}
            for policy in ("low_only", "user", "builtin_users"):
                outcomes[policy] = [
                    self._run_marker(source, policy, executable, marker)
                    for marker in MARKERS
                ]
            self.assertEqual(
                outcomes["low_only"],
                ["user_code_marker", "user_code_marker"],
            )
            for policy in ("user", "builtin_users"):
                self.assertEqual(len(outcomes[policy]), len(MARKERS))
            print(
                "WNRA06N_SUMMARY control=two_markers_reached"
                + " user=" + ",".join(outcomes["user"])
                + " builtin_users=" + ",".join(outcomes["builtin_users"])
                + " evidence=python_user_code_exit_markers"
                + " loader_denial_traced=false"
                + " root_cause=UNKNOWN authorization=DENY"
            )
        finally:
            self.fx.fx._close(source)


if __name__ == "__main__":
    unittest.main()
