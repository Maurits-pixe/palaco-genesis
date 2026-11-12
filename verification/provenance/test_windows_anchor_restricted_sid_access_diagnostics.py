"""WNRA-06C: compare two restricted SID access policies on native Windows.

No ACL modification, no production token broker, no authorization.
A live worker is verified separately from successful process creation.
"""
import ctypes
from ctypes import wintypes
import subprocess
import sys
import time
import unittest

from test_windows_anchor_restricted_sid_worker import (
    RestrictedSidWorkerTests, TOKEN_USER, TOKEN_RESTRICTED_SIDS,
)
from test_windows_anchor_restricted_token import (
    DISABLE_MAX_PRIVILEGE, LOW_INTEGRITY_RID,
)
from test_windows_anchor_token_audit import SID_AND_ATTRIBUTES
from test_windows_anchor_suspended_job_launch import (
    STARTUPINFOW, PROCESS_INFORMATION, CREATE_SUSPENDED, CREATE_NO_WINDOW,
    WAIT_TIMEOUT, WAIT_OBJECT_0, RESUME_FAILED,
)
from test_windows_anchor_low_token_job_launch import (
    ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD, ERROR_BAD_TOKEN_TYPE,
)

ERROR_BAD_IMPERSONATION_LEVEL = 1346
USERS_SID = "S-1-5-32-545"

@unittest.skipUnless(sys.platform == "win32", "native Windows restricted token required")
class RestrictedSidAccessDiagnostics(unittest.TestCase):
    def setUp(self):
        self.fx = RestrictedSidWorkerTests(
            "test_restricted_user_sid_is_present_and_low_integrity"
        )
        self.fx.setUp()
        self.k = self.fx.k
        self.a = self.fx.a

    def _run_variant(self, variant):
        source = self.fx._source()
        restricted = None
        sid_allocated = ctypes.c_void_p()
        job = None
        info = PROCESS_INFORMATION()
        try:
            if variant == "user":
                user = self.fx.audit._information(source, TOKEN_USER)
                sid = ctypes.cast(
                    user, ctypes.POINTER(SID_AND_ATTRIBUTES),
                ).contents.Sid
                self.assertTrue(sid)
            elif variant == "builtin_users":
                self.fx.fx._check(self.a.ConvertStringSidToSidW(
                    USERS_SID, ctypes.byref(sid_allocated),
                ))
                sid = sid_allocated.value
            else:
                self.fail("unknown restricted SID variant")
            restriction = SID_AND_ATTRIBUTES()
            restriction.Sid = sid
            restriction.Attributes = 0
            restricted = wintypes.HANDLE()
            self.fx.fx._check(self.a.CreateRestrictedToken(
                source, DISABLE_MAX_PRIVILEGE,
                0, None, 0, None, 1, ctypes.byref(restriction),
                ctypes.byref(restricted),
            ))
            self.fx.token_fixture._lower_integrity(restricted)
            token = self.fx.audit._observed(restricted)
            self.assertEqual(token["integrity_rid"], LOW_INTEGRITY_RID)
            self.assertEqual(token["restricted"], 1)
            sids_info = self.fx.audit._information(
                restricted, TOKEN_RESTRICTED_SIDS,
            )
            self.assertGreaterEqual(
                ctypes.cast(sids_info, ctypes.POINTER(wintypes.DWORD)).contents.value,
                1,
            )
            self.assertLessEqual(
                self.fx.token_fixture._enabled_count(restricted),
                self.fx.token_fixture._enabled_count(source),
            )
            job = self.fx.fx._job()
            command = subprocess.list2cmdline([
                sys.executable, "-u", "-c", "import time;time.sleep(30)",
            ])
            command_buf = ctypes.create_unicode_buffer(command)
            startup = STARTUPINFOW()
            startup.cb = ctypes.sizeof(startup)
            ctypes.set_last_error(0)
            created = bool(self.a.CreateProcessAsUserW(
                restricted, sys.executable, command_buf, None, None, False,
                CREATE_SUSPENDED | CREATE_NO_WINDOW, None, None,
                ctypes.byref(startup), ctypes.byref(info),
            ))
            if not created:
                error = ctypes.get_last_error()
                self.assertIn(
                    error, (ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD,
                            ERROR_BAD_TOKEN_TYPE, ERROR_BAD_IMPERSONATION_LEVEL),
                )
                self.assertFalse(info.hProcess)
                self.assertFalse(info.hThread)
                result = "create_blocked"
                code = error
            else:
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
                child_token = None
                try:
                    child_token = self.fx.audit._token(info.hProcess)
                    child = self.fx.audit._observed(child_token)
                    self.assertEqual(child["integrity_rid"], LOW_INTEGRITY_RID)
                    self.assertEqual(child["restricted"], 1)
                    child_info = self.fx.audit._information(
                        child_token, TOKEN_RESTRICTED_SIDS,
                    )
                    self.assertGreaterEqual(
                        ctypes.cast(
                            child_info, ctypes.POINTER(wintypes.DWORD),
                        ).contents.value, 1,
                    )
                finally:
                    if child_token:
                        self.fx.fx._close(child_token)
                self.assertNotEqual(
                    self.k.ResumeThread(info.hThread), RESUME_FAILED,
                )
                time.sleep(0.5)
                status = self.k.WaitForSingleObject(info.hProcess, 0)
                if status == WAIT_OBJECT_0:
                    self.k.GetExitCodeProcess.argtypes = (
                        wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
                    )
                    self.k.GetExitCodeProcess.restype = wintypes.BOOL
                    exit_code = wintypes.DWORD()
                    self.fx.fx._check(self.k.GetExitCodeProcess(
                        info.hProcess, ctypes.byref(exit_code),
                    ))
                    self.assertNotEqual(exit_code.value, 0)
                    result = "runtime_blocked"
                    code = exit_code.value
                else:
                    self.assertEqual(status, WAIT_TIMEOUT)
                    self.fx.fx._close(job)
                    job = None
                    self.assertEqual(
                        self.k.WaitForSingleObject(info.hProcess, 5000),
                        WAIT_OBJECT_0,
                    )
                    result = "worker_live_then_job_terminated"
                    code = 0
            print(
                "WNRA06C_DIAGNOSTIC variant=" + variant
                + " result=" + result + " code=" + str(code)
                + " restricted_sid_count=1 integrity_rid="
                + str(LOW_INTEGRITY_RID)
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
            if restricted:
                self.fx.fx._close(restricted)
            if sid_allocated.value:
                self.assertFalse(self.k.LocalFree(sid_allocated))
            self.fx.fx._close(source)

    def test_current_user_sid_restricted_worker(self):
        result = self._run_variant("user")
        self.assertIn(result, (
            "runtime_blocked", "create_blocked", "worker_live_then_job_terminated",
        ))

    def test_builtin_users_sid_restricted_worker(self):
        result = self._run_variant("builtin_users")
        self.assertIn(result, (
            "runtime_blocked", "create_blocked", "worker_live_then_job_terminated",
        ))


if __name__ == "__main__":
    unittest.main()
