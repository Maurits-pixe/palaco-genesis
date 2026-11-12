"""WNRA-06H: process-bound low-token vs restricted-SID failure evidence.

Native Windows test-only. Records the created process's image, PID, actual
primary-token attributes, Job membership and post-resume exit status.
It does not trace loader calls or attribute an access denial to a DLL/ACL.
"""
import ctypes
from ctypes import wintypes
import os
import pathlib
import subprocess
import sys
import time
import unittest

from test_windows_anchor_readonly_access_check import ReadOnlyAccessCheckTests
from test_windows_anchor_restricted_token import LOW_INTEGRITY_RID
from test_windows_anchor_suspended_job_launch import (
    CREATE_NO_WINDOW, CREATE_SUSPENDED, PROCESS_INFORMATION,
    RESUME_FAILED, STARTUPINFOW, WAIT_OBJECT_0, WAIT_TIMEOUT,
)
from test_windows_anchor_low_token_job_launch import (
    ERROR_ACCESS_DENIED, ERROR_BAD_TOKEN_TYPE, ERROR_PRIVILEGE_NOT_HELD,
)
from test_windows_anchor_restricted_sid_access_diagnostics import (
    ERROR_BAD_IMPERSONATION_LEVEL,
)

@unittest.skipUnless(sys.platform == "win32", "Windows process token required")
class ProcessBoundFailureEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.probe = ReadOnlyAccessCheckTests(
            "test_restricted_sid_dacl_execute_decisions_on_known_images"
        )
        self.probe.setUp()
        self.fx = self.probe.fx
        self.k = self.probe.k
        self.a = self.probe.a
        self.k.QueryFullProcessImageNameW.argtypes = (
            wintypes.HANDLE, wintypes.DWORD,
            wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
        )
        self.k.QueryFullProcessImageNameW.restype = wintypes.BOOL
        self.k.GetProcessId.argtypes = (wintypes.HANDLE,)
        self.k.GetProcessId.restype = wintypes.DWORD
        self.k.GetExitCodeProcess.argtypes = (
            wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
        )
        self.k.GetExitCodeProcess.restype = wintypes.BOOL

    def _run(self, source, kind, executable):
        token = None
        job = None
        info = PROCESS_INFORMATION()
        resumed = False
        try:
            if kind == "low_only":
                token = self.fx.token_fixture._restricted(source)
            else:
                token = self.probe._token(source, kind)
            self.fx.token_fixture._lower_integrity(token)
            before = self.fx.audit._observed(token)
            self.assertEqual(before["integrity_rid"], LOW_INTEGRITY_RID)
            expected_restricted = 0 if kind == "low_only" else 1
            self.assertEqual(before["restricted"], expected_restricted)
            job = self.fx.fx._job()
            args = [
                str(executable), "-u", "-c",
                "import time; time.sleep(30)",
            ]
            cmd = ctypes.create_unicode_buffer(
                subprocess.list2cmdline(args),
            )
            startup = STARTUPINFOW()
            startup.cb = ctypes.sizeof(startup)
            ctypes.set_last_error(0)
            created = bool(self.a.CreateProcessAsUserW(
                token, str(executable), cmd, None, None, False,
                CREATE_SUSPENDED | CREATE_NO_WINDOW, None, None,
                ctypes.byref(startup), ctypes.byref(info),
            ))
            if not created:
                code = ctypes.get_last_error()
                self.assertIn(
                    code, (ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD,
                           ERROR_BAD_TOKEN_TYPE, ERROR_BAD_IMPERSONATION_LEVEL),
                )
                self.assertFalse(info.hProcess)
                self.assertFalse(info.hThread)
                self.assertNotEqual(kind, "low_only",
                                    "known low-only control did not launch")
                print(
                    "WNRA06H_PROCESS policy=" + kind
                    + " outcome=create_blocked winerror=" + str(code)
                    + " process_bound=false resumed=false authorization=DENY"
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
            image_buffer = ctypes.create_unicode_buffer(capacity.value)
            self.fx.fx._check(self.k.QueryFullProcessImageNameW(
                info.hProcess, 0, image_buffer, ctypes.byref(capacity),
            ))
            image_path = pathlib.Path(image_buffer.value)
            self.assertEqual(
                os.path.normcase(os.path.abspath(str(image_path))),
                os.path.normcase(os.path.abspath(str(executable))),
            )
            actual_token = None
            try:
                actual_token = self.fx.audit._token(info.hProcess)
                observed = self.fx.audit._observed(actual_token)
                self.assertEqual(observed["integrity_rid"], LOW_INTEGRITY_RID)
                self.assertEqual(observed["restricted"], expected_restricted)
                self.assertLessEqual(
                    self.fx.token_fixture._enabled_count(actual_token),
                    self.fx.token_fixture._enabled_count(source),
                )
            finally:
                if actual_token:
                    self.fx.fx._close(actual_token)
            self.assertNotEqual(
                self.k.ResumeThread(info.hThread), RESUME_FAILED,
            )
            resumed = True
            time.sleep(0.5)
            status = self.k.WaitForSingleObject(info.hProcess, 0)
            if status == WAIT_OBJECT_0:
                exit_code = wintypes.DWORD()
                self.fx.fx._check(self.k.GetExitCodeProcess(
                    info.hProcess, ctypes.byref(exit_code),
                ))
                self.assertNotEqual(exit_code.value, 0)
                result = "runtime_blocked"
                code = exit_code.value
            else:
                self.assertEqual(status, WAIT_TIMEOUT)
                result = "worker_live"
                code = 0
            self.fx.fx._close(job)
            job = None
            self.assertEqual(
                self.k.WaitForSingleObject(info.hProcess, 5000),
                WAIT_OBJECT_0,
            )
            print(
                "WNRA06H_PROCESS policy=" + kind
                + " outcome=" + result + " pid_verified=true"
                + " image_verified=true token_integrity=4096"
                + " restricted=" + str(bool(expected_restricted)).lower()
                + " job_before_resume=true resumed="
                + str(resumed).lower()
                + " exit_code=" + str(code)
                + " authorization=DENY"
            )
            return result
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

    def test_process_bound_policy_comparison(self):
        executable = pathlib.Path(sys.executable)
        self.assertTrue(executable.is_file())
        source = self.fx._source()
        try:
            control = self._run(source, "low_only", executable)
            user = self._run(source, "user", executable)
            users = self._run(source, "builtin_users", executable)
            self.assertEqual(control, "worker_live")
            self.assertIn(user, ("create_blocked", "runtime_blocked", "worker_live"))
            self.assertIn(users, ("create_blocked", "runtime_blocked", "worker_live"))
            print(
                "WNRA06H_COMPARISON control=" + control
                + " user=" + user + " builtin_users=" + users
                + " same_image=true same_low_integrity=true"
                + " cause_attributed=false authorization=DENY"
            )
        finally:
            self.fx.fx._close(source)


if __name__ == "__main__":
    unittest.main()
