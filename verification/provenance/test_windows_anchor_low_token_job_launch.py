"""WNRA-06A Windows-native low-integrity token launch feasibility, test-only.

Attempts CreateProcessAsUserW(CREATE_SUSPENDED), assigns a Job Object before
resume, verifies child primary token and terminate-on-job-close. If runner
privileges deny process creation, assert fail-closed and record the blocker.
Never infer production authorization, general sandboxing or launch permission.
"""
import ctypes
from ctypes import wintypes
import subprocess
import sys
import tempfile
import time
import unittest

from test_windows_anchor_restricted_token import (
    RestrictedTokenFixtureTests, TOKEN_DUPLICATE, TOKEN_ADJUST_DEFAULT,
    LOW_INTEGRITY_RID,
)
from test_windows_anchor_token_audit import TOKEN_QUERY
from test_windows_anchor_suspended_job_launch import (
    STARTUPINFOW, PROCESS_INFORMATION, CREATE_SUSPENDED, CREATE_NO_WINDOW,
    WAIT_TIMEOUT, WAIT_OBJECT_0, RESUME_FAILED,
)

TOKEN_ASSIGN_PRIMARY = 0x0001
ERROR_PRIVILEGE_NOT_HELD = 1314
ERROR_ACCESS_DENIED = 5
ERROR_BAD_TOKEN_TYPE = 1349

@unittest.skipUnless(sys.platform == "win32", "requires native Windows tokens")
class RestrictedProcessLaunchTests(unittest.TestCase):
    def setUp(self):
        self.token_fixture = RestrictedTokenFixtureTests(
            "test_reduced_token_has_lower_integrity_and_no_privilege_gain"
        )
        self.token_fixture.setUp()
        self.audit = self.token_fixture.audit
        self.k = self.token_fixture.k
        self.a = self.token_fixture.a
        self.fx = self.audit.fixture
        self.a.CreateProcessAsUserW.argtypes = (
            wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR,
            ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL,
            wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
            ctypes.POINTER(STARTUPINFOW),
            ctypes.POINTER(PROCESS_INFORMATION),
        )
        self.a.CreateProcessAsUserW.restype = wintypes.BOOL

    def test_low_token_suspended_job_launch_or_explicit_denial(self):
        source = self.token_fixture._parent(
            TOKEN_QUERY | TOKEN_DUPLICATE |
            TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY
        )
        low = None
        job = None
        info = PROCESS_INFORMATION()
        created = False
        try:
            low = self.token_fixture._restricted(source)
            self.token_fixture._lower_integrity(low)
            low_observed = self.audit._observed(low)
            self.assertEqual(low_observed["integrity_rid"], LOW_INTEGRITY_RID)
            job = self.fx._job()
            with tempfile.TemporaryDirectory() as temporary:
                # The worker does not need write permission for a marker or
                # stdout. Token membership is observed through OpenProcessToken.
                command = subprocess.list2cmdline([
                    sys.executable, "-u", "-c",
                    "import time; time.sleep(30)",
                ])
                buffer = ctypes.create_unicode_buffer(command)
                startup = STARTUPINFOW()
                startup.cb = ctypes.sizeof(startup)
                ctypes.set_last_error(0)
                created = bool(self.a.CreateProcessAsUserW(
                    low, sys.executable, buffer, None, None, False,
                    CREATE_SUSPENDED | CREATE_NO_WINDOW, None, temporary,
                    ctypes.byref(startup), ctypes.byref(info),
                ))
                if not created:
                    error = ctypes.get_last_error()
                    self.assertIn(
                        error, (ERROR_PRIVILEGE_NOT_HELD, ERROR_ACCESS_DENIED,
                                ERROR_BAD_TOKEN_TYPE),
                        msg="unexpected restricted-process creation error",
                    )
                    self.assertFalse(info.hProcess)
                    self.assertFalse(info.hThread)
                    print(
                        "WNRA06A_CREATE blocked=true winerror=" + str(error)
                        + " child_created=false resume_attempted=false"
                        + " authorization=DENY"
                    )
                    return
                self.assertTrue(info.hProcess)
                self.assertTrue(info.hThread)
                self.assertEqual(
                    self.k.WaitForSingleObject(info.hProcess, 0),
                    WAIT_TIMEOUT,
                )
                # The worker is suspended until job assignment and token query.
                self.fx._check(
                    self.k.AssignProcessToJobObject(job, info.hProcess)
                )
                assigned = wintypes.BOOL()
                self.fx._check(self.k.IsProcessInJob(
                    info.hProcess, job, ctypes.byref(assigned),
                ))
                self.assertTrue(assigned.value)
                child_token = None
                try:
                    child_token = self.audit._token(info.hProcess)
                    observed = self.audit._observed(child_token)
                    self.assertEqual(
                        observed["integrity_rid"], LOW_INTEGRITY_RID
                    )
                    self.assertLessEqual(
                        self.token_fixture._enabled_count(child_token),
                        self.token_fixture._enabled_count(source),
                    )
                finally:
                    if child_token:
                        self.fx._close(child_token)
                self.assertNotEqual(
                    self.k.ResumeThread(info.hThread), RESUME_FAILED,
                )
                time.sleep(0.5)
                self.assertEqual(
                    self.k.WaitForSingleObject(info.hProcess, 0),
                    WAIT_TIMEOUT,
                    "low-integrity worker must still be running after resume",
                )
                self.fx._close(job)
                job = None
                self.assertEqual(
                    self.k.WaitForSingleObject(info.hProcess, 5000),
                    WAIT_OBJECT_0,
                )
                print(
                    "WNRA06A_LAUNCH low_integrity_worker=true"
                    + " job_assigned_before_resume=true"
                    + " worker_alive_after_resume=true"
                    + " job_close_terminated=true authorization=DENY"
                )
        finally:
            if job:
                self.fx._close(job)
            if info.hProcess:
                if self.k.WaitForSingleObject(info.hProcess, 0) == WAIT_TIMEOUT:
                    self.k.TerminateProcess(info.hProcess, 1)
                    self.k.WaitForSingleObject(info.hProcess, 5000)
                self.fx._close(info.hProcess)
            if info.hThread:
                self.fx._close(info.hThread)
            if low:
                self.fx._close(low)
            self.fx._close(source)


if __name__ == "__main__":
    unittest.main()
